"""Ephemeral OAuth callback listener. Never an outbound-scanner SSRF exception.

RFC 8252 loopback redirects and MCP's RFC 9207 issuer validation apply here.
No access logging: request URIs contain authorization codes.
"""

import asyncio
import logging
import secrets
from urllib.parse import parse_qsl

from aiohttp import web

from canmcp.checks.network import ScanError


class CallbackServer:
    def __init__(self, state: str, issuer: str, require_issuer: bool, port: int = 0):
        self.state = state
        self.issuer = issuer
        self.require_issuer = require_issuer
        self.port = port
        self.redirect_uri = ""
        self.runner = None
        self.future = None
        self.requests = 0

    async def __aenter__(self):
        self.future = asyncio.get_running_loop().create_future()
        app = web.Application(client_max_size=8192)
        app.router.add_route("*", "/{path:.*}", self.handle)
        # Parser errors can include raw request fragments containing OAuth credentials.
        # Keep this logger private; do not change the embedding application's logging.
        logger = logging.Logger("canmcp.callback")
        logger.disabled = True
        self.runner = web.AppRunner(
            app,
            access_log=None,
            logger=logger,
            debug=False,
            shutdown_timeout=0.2,
            max_line_size=8192,
            max_field_size=2048,
            max_headers=32,
        )
        try:
            await self.runner.setup()
            site = web.TCPSite(self.runner, "127.0.0.1", self.port)
            await site.start()
            self.port = self.runner.addresses[0][1]
            self.redirect_uri = f"http://127.0.0.1:{self.port}/oauth/callback"
        except OSError as exc:
            await self.runner.cleanup()
            raise ScanError("oauth.callback", "Cannot bind the local OAuth callback port.") from exc
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()
        if not self.future.done():
            self.future.cancel()
        elif not self.future.cancelled():
            self.future.exception()  # Consume errors if another operation already aborted the flow.
        self.state = ""

    @staticmethod
    def reply(status: int, text: str):
        return web.Response(
            status=status,
            text=text,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            },
        )

    async def handle(self, request):
        self.requests += 1
        if self.future.done():
            return self.reply(410, "This authorization attempt is already complete.")
        if self.requests > 128:
            self.future.set_exception(
                ScanError("oauth.callback", "Callback request limit exceeded.")
            )
            return self.reply(429, "Too many callback requests.")
        if (
            request.method != "GET"
            or request.path != "/oauth/callback"
            or request.remote != "127.0.0.1"
            or request.headers.getall("Host", []) != [f"127.0.0.1:{self.port}"]
        ):
            return self.reply(400, "Invalid callback request.")
        try:
            pairs = parse_qsl(
                request.rel_url.raw_query_string,
                keep_blank_values=True,
                strict_parsing=True,
                errors="strict",
                max_num_fields=16,
            )
        except (ValueError, UnicodeError):
            return self.reply(400, "Invalid callback parameters.")
        values = dict(pairs)
        if (
            len(values) != len(pairs)
            or "state" not in values
            or not secrets.compare_digest(values["state"].encode(), self.state.encode())
        ):
            # Unrelated local traffic must not consume the real authorization attempt.
            return self.reply(400, "Invalid OAuth state or duplicate parameters.")
        issuer = values.get("iss")
        error = None
        if (issuer is not None and issuer != self.issuer) or (
            self.require_issuer and issuer is None
        ):
            error = ScanError("oauth.issuer", "OAuth callback issuer is missing or mismatched.")
        elif "error" in values:
            error = ScanError("oauth.denied", "Authorization was denied or failed at the provider.")
        elif not values.get("code") or len(values["code"]) > 4096:
            error = ScanError("oauth.callback", "Authorization callback has no bounded code.")
        if error:
            self.future.set_exception(error)
            return self.reply(400, "Authorization failed. Return to CanMCP for the diagnostic.")
        self.future.set_result(values["code"])
        return self.reply(
            200, "Authorization received. You may close this tab and return to CanMCP."
        )

    async def wait(self, timeout: float):
        try:
            return await asyncio.wait_for(asyncio.shield(self.future), timeout)
        except TimeoutError as exc:
            raise ScanError(
                "oauth.timeout", "Timed out waiting for browser authorization."
            ) from exc
