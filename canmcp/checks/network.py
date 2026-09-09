"""One outbound network boundary for MCP, redirects, and OAuth requests.

The connector dials only the numeric addresses returned by PublicResolver, while
keeping the URL hostname for TLS SNI/certificate verification and HTTP Host.
No separate validation-then-second-DNS-lookup window; no environment proxies.
"""

import asyncio
import ipaddress
import json
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass, field

import aiohttp
import dns.asyncresolver
import dns.exception
from aiohttp.abc import AbstractResolver
from yarl import URL

from canmcp import __version__

MAX_BODY = 1_048_576
MAX_REQUESTS = 32
DNS_TIMEOUT = 5
REDIRECTS = {301, 302, 303, 307, 308}


class ScanError(Exception):
    def __init__(self, check_id: str, message: str):
        self.check_id = check_id
        super().__init__(message)


@dataclass(repr=False)
class BearerToken:
    """An in-memory bearer credential bound to one exact MCP endpoint, not its metadata."""

    endpoint: str
    value: str = field(repr=False)
    expires_at: float | None = None

    def header(self, url: str) -> str:
        target = validate_url(url)
        if target.scheme != "https" or target != URL(self.endpoint):
            raise ScanError("oauth.token_binding", "Token is bound to a different MCP endpoint.")
        if self.expires_at is not None and time.monotonic() >= self.expires_at:
            raise ScanError(
                "oauth.token_expired", "Access token expired before inspection finished."
            )
        if (
            not isinstance(self.value, str)
            or len(self.value) > 8192
            or not re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", self.value)
        ):
            raise ScanError("oauth.token", "Token is not a bounded HTTP Bearer credential.")
        return "Bearer " + self.value


def public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address):
        # Refuse embedded/transition addressing: routing can hide a private target.
        if ip.ipv4_mapped or ip.sixtofour or ip.teredo:
            return False
        if ip in ipaddress.ip_network("64:ff9b::/96") or ip in ipaddress.ip_network(
            "64:ff9b:1::/48"
        ):
            return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def validate_url(value: str) -> URL:
    if not isinstance(value, str) or len(value) > 4096:
        raise ScanError("url", "URL must be a string of at most 4096 characters.")
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ScanError("url", "URL contains whitespace, control characters, or backslashes.")
    try:
        url = URL(value)
        host = url.host
        if url.scheme not in {"http", "https"} or not host or not url.port:
            raise ValueError
        if url.user is not None or url.password is not None or url.fragment:
            raise ValueError
        if "%" in host:
            raise ValueError
        host = host.rstrip(".").lower()
        if host == "localhost" or host.endswith(
            (".localhost", ".local", ".internal", ".home", ".lan")
        ):
            raise ScanError("ssrf", "Local network hostnames are blocked.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                socket.inet_aton(host)
            except OSError:
                pass
            else:
                raise ScanError("ssrf", "Non-canonical numeric IPv4 hostnames are blocked.")
            if "." not in host:
                raise ScanError("ssrf", "Single-label hostnames are blocked.") from None
        else:
            if not public_ip(host):
                raise ScanError("ssrf", "Non-public and transition IP addresses are blocked.")
    except (ValueError, UnicodeError) as exc:
        raise ScanError(
            "url", "Expected an absolute HTTP(S) URL without userinfo or fragment."
        ) from exc
    return url


def display_url(value: str) -> str:
    """Do not leak URL credentials, queries, or terminal escapes into reports."""
    try:
        url = URL(value).with_user(None).with_fragment(None).with_query(None)
        value = str(url)
    except (ValueError, UnicodeError):
        value = "<invalid URL>"
    return value.encode("unicode_escape").decode("ascii")[:4096]


class PublicResolver(AbstractResolver):
    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        validate_url(f"https://{host}:{port or 443}/")
        try:
            resolver = dns.asyncresolver.Resolver()
            answers = await asyncio.wait_for(
                asyncio.gather(
                    *(
                        resolver.resolve(
                            host, kind, search=False, lifetime=DNS_TIMEOUT, raise_on_no_answer=False
                        )
                        for kind in ("A", "AAAA")
                    ),
                    return_exceptions=True,
                ),
                timeout=DNS_TIMEOUT,
            )
            if any(isinstance(answer, Exception) for answer in answers):
                raise ScanError("dns", "Could not obtain complete A and AAAA DNS answers.")
            addresses = list(
                dict.fromkeys(
                    (family, record.address)
                    for family, answer in zip(
                        (socket.AF_INET, socket.AF_INET6), answers, strict=True
                    )
                    for record in answer
                )
            )
        except (dns.exception.DNSException, OSError, TimeoutError) as exc:
            raise ScanError("dns", "DNS resolution failed or exceeded 5 seconds.") from exc
        if not addresses:
            raise ScanError("dns", "DNS returned no addresses.")
        if len(addresses) > 64:
            raise ScanError("limits", "DNS address limit exceeded.")
        if any(not public_ip(ip) for _, ip in addresses):
            raise ScanError(
                "ssrf", "DNS contains a non-public address; the entire target is blocked."
            )
        return [
            dict(
                hostname=host,
                host=ip,
                port=port,
                family=fam,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
            for fam, ip in addresses
        ]

    async def close(self):
        pass


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str
    redirects: list[int]

    def json(self):
        return bounded_json(self.body)


def bounded_json(data: bytes):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("duplicate JSON key")
            obj[key] = value
        return obj

    def invalid_constant(_):
        raise ValueError("non-finite JSON number")

    try:
        obj = json.loads(
            data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant
        )
        stack = [(obj, 0)]
        nodes = 0
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("non-finite JSON number")
            if depth > 48 or nodes > 30_000:
                raise ScanError(
                    "limits", "JSON complexity limit exceeded; inspection is incomplete."
                )
            if isinstance(value, dict):
                stack.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                stack.extend((v, depth + 1) for v in value)
        return obj
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ScanError("json", "Response is not bounded, strict UTF-8 JSON.") from exc


async def read_sse(content, expected_id):
    """Stop at the matching response, even if the server keeps the stream open."""
    buffer = bytearray()
    data = []
    total = 0
    first = True
    async for chunk in content.iter_any():
        total += len(chunk)
        if total > MAX_BODY:
            raise ScanError("limits", "SSE response exceeds 1 MiB.")
        buffer.extend(chunk)
        while True:
            positions = [p for p in (buffer.find(b"\n"), buffer.find(b"\r")) if p >= 0]
            if not positions:
                break
            end = min(positions)
            if buffer[end:] == b"\r":
                break  # CRLF may straddle chunks.
            line = bytes(buffer[:end])
            size = 2 if buffer[end : end + 2] == b"\r\n" else 1
            del buffer[: end + size]
            if first:
                line = line.removeprefix(b"\xef\xbb\xbf")
                first = False
            if not line:
                if data:
                    raw = b"\n".join(data)
                    data = []
                    if not raw:
                        continue  # 2025 priming event
                    obj = bounded_json(raw)
                    if not isinstance(obj, dict) or obj.get("jsonrpc") != "2.0":
                        raise ScanError("streamable_http", "Invalid JSON-RPC SSE event.")
                    if "method" in obj and "id" in obj:
                        raise ScanError(
                            "limits", "Server requested client interaction; not executed."
                        )
                    if "method" not in obj:
                        if (
                            type(obj.get("id")) is not type(expected_id)
                            or obj.get("id") != expected_id
                        ):
                            raise ScanError(
                                "jsonrpc", "SSE response ID does not match the request."
                            )
                        return raw
            elif line.startswith(b"data:"):
                data.append(line[5:].removeprefix(b" "))
    raise ScanError(
        "limits", "SSE ended before a complete response; resumption is not implemented."
    )


class SafeHTTP:
    def __init__(self, timeout: float = 10):
        self.timeout = timeout
        self.count = 0
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(
                resolver=PublicResolver(), use_dns_cache=False, force_close=True, limit=4
            ),
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            trust_env=False,
            auto_decompress=False,
            cookie_jar=aiohttp.DummyCookieJar(),
            max_headers=128,
            headers={"User-Agent": f"canmcp/{__version__}", "Accept-Encoding": "identity"},
        )
        return self

    async def __aexit__(self, *args):
        await self.session.close()

    async def request(
        self,
        method,
        url,
        *,
        headers=None,
        payload=None,
        headers_only=False,
        form=None,
        follow_redirects=True,
        credential: BearerToken | None = None,
    ):
        current = validate_url(url)
        history = []
        outgoing = dict(headers or {})
        if form is not None and payload is not None:
            raise ValueError("Choose form or JSON payload, not both")
        if credential is not None:
            if any(key.lower() == "authorization" for key in outgoing):
                raise ValueError("Authorization header is managed by the bound credential")
            outgoing["Authorization"] = credential.header(str(current))
        for _ in range(6):
            self.count += 1
            if self.count > MAX_REQUESTS:
                raise ScanError("limits", "Request budget exhausted; inspection is incomplete.")
            try:
                async with self.session.request(
                    method,
                    current,
                    headers=outgoing,
                    json=payload,
                    data=form,
                    allow_redirects=False,
                    max_line_size=8190,
                    max_field_size=8190,
                ) as response:
                    if response.status in REDIRECTS:
                        if (
                            not follow_redirects
                            or form is not None
                            or credential is not None
                            or any(key.lower() == "authorization" for key in outgoing)
                        ):
                            raise ScanError(
                                "oauth.redirects",
                                "OAuth writes and authenticated MCP requests "
                                "do not follow redirects.",
                            )
                        location = response.headers.get("Location")
                        if not location:
                            raise ScanError("redirects", "Redirect has no Location header.")
                        target = validate_url(str(current.join(URL(location))))
                        if current.scheme == "https" and target.scheme != "https":
                            raise ScanError("redirects", "HTTPS to HTTP downgrade blocked.")
                        if method == "POST" and response.status in {301, 302, 303}:
                            raise ScanError(
                                "redirects",
                                "POST redirect may change method (301/302/303); "
                                "use the canonical URL or 307/308.",
                            )
                        if target.origin() != current.origin():
                            if any(key.lower() == "mcp-session-id" for key in outgoing):
                                raise ScanError(
                                    "redirects",
                                    "Cross-origin redirect with an MCP session blocked.",
                                )
                            outgoing = {
                                key: value
                                for key, value in outgoing.items()
                                if key.lower() not in {"authorization", "cookie"}
                            }
                        history.append(response.status)
                        current = target
                        continue
                    hdrs = {k.lower(): v for k, v in response.headers.items()}
                    challenges = response.headers.getall("WWW-Authenticate", [])
                    if challenges:
                        hdrs["www-authenticate"] = ", ".join(challenges)
                    if headers_only or response.status in {401, 403}:
                        body = b""
                    elif response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ScanError(
                            "limits", "Compressed responses are not decoded by this scanner."
                        )
                    elif (
                        payload
                        and "id" in payload
                        and hdrs.get("content-type", "").split(";")[0].lower()
                        == "text/event-stream"
                    ):
                        body = await read_sse(response.content, payload["id"])
                    else:
                        body = bytearray()
                        async for chunk in response.content.iter_chunked(16384):
                            body.extend(chunk)
                            if len(body) > MAX_BODY:
                                raise ScanError("limits", "Response exceeds 1 MiB.")
                        body = bytes(body)
                    return Response(response.status, hdrs, body, str(current), history)
            except (aiohttp.ClientSSLError, ssl.SSLError) as exc:
                raise ScanError(
                    "tls",
                    "TLS handshake or certificate verification failed "
                    "(chain, expiry, or hostname).",
                ) from exc
            except aiohttp.ClientConnectorDNSError as exc:
                raise ScanError("dns", "DNS resolution failed.") from exc
            except TimeoutError as exc:
                raise ScanError("reachability", "HTTP request exceeded its time limit.") from exc
            except (aiohttp.ClientError, OSError, ValueError, UnicodeError) as exc:
                raise ScanError(
                    "reachability", "HTTP connection failed or response framing was invalid."
                ) from exc
        raise ScanError("redirects", "More than five redirects; possible redirect loop.")
