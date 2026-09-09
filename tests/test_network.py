import asyncio
import socket
import ssl
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import aiohappyeyeballs
import aiohttp
import dns.asyncresolver
import pytest
import trustme
from aiohttp import web

from canmcp.checks.network import MAX_BODY, PublicResolver, SafeHTTP, ScanError, validate_url
from canmcp.scanner import scan


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/mcp",
        "http://localhost./mcp",
        "http://x.localhost/mcp",
        "http://127.0.0.1/mcp",
        "http://0.0.0.0/",
        "http://10.1.2.3/",
        "http://172.16.0.1/",
        "http://192.168.0.1/",
        "http://169.254.169.254/",
        "http://100.64.0.1/",
        "http://224.0.0.1/",
        "http://[::1]/",
        "http://[::]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[2002:7f00:1::]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[fe80::1%25eth0]/",
        "file:///etc/passwd",
        "ftp://public.example.com/",
        "https://user:secret@public.example.com/",
        "http://printer/",
        "https://x.internal/",
        "https://x.local/",
        "https://x.example.com/#fragment",
        "https://example.com/\n",
        "http://example.com\\@127.0.0.1/",
        "https://example.com:99999/",
    ],
)
def test_ssrf_url_policy(url):
    with pytest.raises(ScanError):
        validate_url(url)


@pytest.mark.parametrize(
    "ips", [["127.0.0.1"], ["8.8.8.8", "10.0.0.1"], ["::1"], ["192.0.2.1"], ["2001:db8::1"]]
)
async def test_dns_blocks_all_mixed_and_nonpublic_answers(monkeypatch, ips):
    async def lookup(host, kind, **kwargs):
        return [SimpleNamespace(address=ip) for ip in ips if (":" in ip) == (kind == "AAAA")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", AsyncMock(side_effect=lookup))
    with pytest.raises(ScanError, match="non-public"):
        await PublicResolver().resolve("public.example.com", 443)


@pytest.mark.parametrize("host", ["2130706433", "0177.0.0.1", "0x7f000001", "127.1"])
async def test_noncanonical_ip_is_blocked_without_dns(host):
    with pytest.raises(ScanError):
        await PublicResolver().resolve(host, 80)


@pytest.fixture
async def serve():
    runners = []

    async def start(handler, ssl_context=None):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", handler)
        runner = web.AppRunner(app, shutdown_timeout=0.1)
        await runner.setup()
        runners.append(runner)
        site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        scheme = "https" if ssl_context else "http"
        return f"{scheme}://scanner.example.com:{port}"

    yield start
    for runner in runners:
        await runner.cleanup()


@pytest.fixture
def local_route(monkeypatch):
    # Test-only resolver injection. The production scanner has no private-network flag.
    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        return [
            dict(
                hostname=host,
                host="127.0.0.1",
                port=port,
                family=socket.AF_INET,
                proto=socket.IPPROTO_TCP,
                flags=socket.AI_NUMERICHOST,
            )
        ]

    monkeypatch.setattr(PublicResolver, "resolve", resolve)


async def test_real_sse_stops_without_waiting_for_close(serve, local_route):
    release = asyncio.Event()

    async def handler(request):
        stream = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await stream.prepare(request)
        for part in [
            b"\xef\xbb\xbf: keepalive\r",
            b"\n\r\n",
            b"id: prime\ndata:\n\n",
            b'data: {"jsonrpc":"2.0",\n',
            b'data: "id":7,"result":{}}\n\n',
        ]:
            await stream.write(part)
        await release.wait()
        return stream

    url = await serve(handler)
    try:
        async with SafeHTTP(timeout=0.5) as http:
            result = await http.request("POST", url + "/mcp", payload={"id": 7})
            assert result.json()["id"] == 7
    finally:
        release.set()


@pytest.mark.parametrize("status", [307, 308])
async def test_method_preserving_redirect(serve, local_route, status):
    seen = []

    async def handler(request):
        seen.append((request.method, await request.json()))
        if request.path == "/start":
            return web.Response(status=status, headers={"Location": "/mcp"})
        return web.json_response({"ok": True})

    url = await serve(handler)
    async with SafeHTTP() as http:
        result = await http.request("POST", url + "/start", payload={"x": 1})
    assert seen == [("POST", {"x": 1})] * 2
    assert result.redirects == [status]


@pytest.mark.parametrize("status", [301, 302, 303])
async def test_unsafe_post_redirect(serve, local_route, status):
    async def handler(request):
        return web.Response(status=status, headers={"Location": "/mcp"})

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError, match="may change method"):
            await http.request("POST", url, payload={})


@pytest.mark.parametrize(
    "target",
    ["http://127.0.0.1/private", "http://169.254.169.254/", "file:///etc/passwd", "http://[::1]/"],
)
async def test_ssrf_redirect(serve, local_route, target):
    async def handler(request):
        return web.Response(status=307, headers={"Location": target})

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError):
            await http.request("GET", url)
        assert http.count == 1


async def test_redirect_loop(serve, local_route):
    async def handler(request):
        return web.Response(status=307, headers={"Location": "/loop"})

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError, match="five redirects"):
            await http.request("GET", url)


async def test_cross_origin_session_redirect(serve, local_route):
    async def handler(request):
        return web.Response(status=307, headers={"Location": "https://other.example.com/mcp"})

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError, match="session blocked"):
            await http.request("POST", url, headers={"Mcp-Session-Id": "secret"}, payload={})


@pytest.mark.parametrize("failure", ["untrusted", "hostname", "expired", "none", "downgrade"])
async def test_real_tls(serve, local_route, monkeypatch, failure):
    ca = trustme.CA()
    kwargs = {}
    if failure == "expired":
        kwargs = {
            "not_before": datetime.now(UTC) - timedelta(days=5),
            "not_after": datetime.now(UTC) - timedelta(days=1),
        }
    cert = ca.issue_cert(
        "wrong.example.com" if failure == "hostname" else "scanner.example.com", **kwargs
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_context)
    if failure != "untrusted":
        client_context = ssl.create_default_context()
        ca.configure_trust(client_context)
        connector = aiohttp.TCPConnector
        monkeypatch.setattr(
            aiohttp, "TCPConnector", lambda **kw: connector(ssl=client_context, **kw)
        )

    async def handler(request):
        if failure == "downgrade":
            return web.Response(status=307, headers={"Location": "http://scanner.example.com/mcp"})
        return web.json_response({"ok": True})

    url = await serve(handler, server_context)
    async with SafeHTTP() as http:
        if failure == "none":
            assert (await http.request("GET", url)).status == 200
        else:
            with pytest.raises(ScanError) as error:
                await http.request("GET", url)
            assert error.value.check_id == ("redirects" if failure == "downgrade" else "tls")


async def test_response_body_limit(serve, local_route):
    async def handler(request):
        return web.Response(body=b"x" * (MAX_BODY + 1))

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError, match="1 MiB"):
            await http.request("GET", url)


async def test_ignores_proxy_environment(serve, local_route, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")

    async def handler(request):
        return web.Response()

    url = await serve(handler)
    async with SafeHTTP() as http:
        assert (await http.request("GET", url)).status == 200


async def test_dns_pinned_and_rebinding_rejected(serve, monkeypatch):
    async def handler(request):
        return web.Response()

    url = await serve(handler)
    addresses = iter(["8.8.8.8", "127.0.0.1"])

    async def answer(host, kind, **kwargs):
        return [SimpleNamespace(address=next(addresses))] if kind == "A" else []

    lookup = AsyncMock(side_effect=answer)
    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", lookup)
    real_connect = aiohappyeyeballs.start_connection
    dialed = []

    async def test_wire(*, addr_infos, **kwargs):
        dialed.extend(info[4][0] for info in addr_infos)
        # Route the validated public address to the local fixture at the socket boundary.
        routed = [
            (fam, typ, proto, name, ("127.0.0.1", address[1]))
            for fam, typ, proto, name, address in addr_infos
        ]
        return await real_connect(addr_infos=routed, **kwargs)

    monkeypatch.setattr(aiohappyeyeballs, "start_connection", test_wire)
    async with SafeHTTP() as http:
        assert (await http.request("GET", url)).status == 200
        assert lookup.call_count == 2  # exactly A + AAAA; no second resolution before socket
        with pytest.raises(ScanError, match="non-public"):
            await http.request("GET", url)
    assert dialed == ["8.8.8.8"]


async def test_dns_timeout_cancels_both_queries(monkeypatch):
    cancelled = []

    async def never_returns(host, kind, **kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(kind)

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", AsyncMock(side_effect=never_returns))
    monkeypatch.setattr("canmcp.checks.network.DNS_TIMEOUT", 0.01)
    with pytest.raises(ScanError, match="DNS resolution failed"):
        await PublicResolver().resolve("scanner.example.com", 443)
    assert set(cancelled) == {"A", "AAAA"}


async def test_dns_partial_failure_is_not_public_evidence(monkeypatch):
    async def answer(host, kind, **kwargs):
        if kind == "AAAA":
            raise TimeoutError
        return [SimpleNamespace(address="8.8.8.8")]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", AsyncMock(side_effect=answer))
    with pytest.raises(ScanError, match="complete A and AAAA"):
        await PublicResolver().resolve("scanner.example.com", 443)


async def test_http_header_count_bounded(serve, local_route):
    async def handler(request):
        return web.Response(headers={f"X-Header-{n}": "x" for n in range(140)})

    url = await serve(handler)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError):
            await http.request("GET", url)


async def test_full_scanner_over_real_http(serve, local_route):
    seen = []

    async def handler(request):
        if request.method == "GET":
            return web.Response(status=405)
        payload = await request.json()
        seen.append(payload["method"])
        if payload["method"] == "server/discover":
            result = {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
            }
        else:
            result = {"resultType": "complete", "tools": []}
        return web.json_response({"jsonrpc": "2.0", "id": payload["id"], "result": result})

    url = await serve(handler)
    report = await scan(url + "/mcp")
    assert report.generic.status == "pass"
    assert report.clients["chatgpt"].status == "fail"  # public endpoint must be HTTPS
    assert seen == ["server/discover", "tools/list"]
