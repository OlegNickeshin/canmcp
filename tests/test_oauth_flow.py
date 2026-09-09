import base64
import hashlib
import json
import ssl
from types import SimpleNamespace
from urllib.parse import unquote_plus

import aiohttp
import pytest
import trustme
from aiohttp import web
from yarl import URL

from canmcp.checks.network import BearerToken, PublicResolver, SafeHTTP, ScanError
from canmcp.oauth import OAuthOptions, pkce_pair
from canmcp.scanner import scan
from tests.conftest import TOOL

TOKEN = "secret-access-token"
CODE = "secret-authorization-code"
SECRET = "client:secret+with special/chars"


@pytest.fixture
async def protected_server(serve, local_route, monkeypatch):
    ca = trustme.CA()
    cert = ca.issue_cert("scanner.example.com")
    server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_ssl)
    client_ssl = ssl.create_default_context()
    ca.configure_trust(client_ssl)
    original_connector = aiohttp.TCPConnector
    monkeypatch.setattr(
        aiohttp, "TCPConnector", lambda **kw: original_connector(ssl=client_ssl, **kw)
    )
    state = SimpleNamespace(
        base="",
        calls=[],
        grants={},
        registered=[],
        modern=False,
        token_reply={
            "access_token": TOKEN,
            "token_type": "Bearer",
            "expires_in": 60,
            "refresh_token": "secret-refresh-token",
            "id_token": "secret-id-token",
        },
        token_status=200,
        fail_at=None,
        redirect_token=False,
        redirect_mcp=False,
        redirect_registration=False,
        metadata_overrides={},
        dcr=True,
        auth_method="none",
        callback_issuer=None,
        bad_registration=False,
        protect_at=None,
        seen_credentials=[],
    )

    async def handler(request):
        path = request.path
        state.calls.append((request.method, path, request.headers.get("Authorization")))
        if path == "/metadata":
            assert "Authorization" not in request.headers
            return web.json_response(
                {
                    "resource": state.base + "/mcp",
                    "authorization_servers": [state.base + "/issuer"],
                    "scopes_supported": ["metadata.read"],
                }
            )
        if path == "/.well-known/oauth-authorization-server/issuer":
            assert "Authorization" not in request.headers
            metadata = {
                "issuer": state.base + "/issuer",
                "authorization_endpoint": state.base + "/authorize",
                "token_endpoint": state.base + "/token",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": [state.auth_method],
                "authorization_response_iss_parameter_supported": True,
            }
            if state.dcr:
                metadata["registration_endpoint"] = state.base + "/register"
            metadata.update(state.metadata_overrides)
            return web.json_response(metadata)
        if path == "/register":
            assert "Authorization" not in request.headers
            data = await request.json()
            state.registered.append(data)
            if state.redirect_registration:
                return web.Response(status=307, headers={"Location": state.base + "/leak"})
            return web.json_response(
                {
                    "client_id": "dynamic-client",
                    **data,
                    "redirect_uris": ["http://127.0.0.1/evil"]
                    if state.bad_registration
                    else data["redirect_uris"],
                },
                status=201,
            )
        if path == "/authorize":
            params = dict(request.query)
            assert params["response_type"] == "code"
            assert params["code_challenge_method"] == "S256"
            assert params["resource"] == state.base + "/mcp"
            assert "code_verifier" not in params
            state.grants.update(params)
            issuer = state.callback_issuer or state.base + "/issuer"
            location = URL(params["redirect_uri"]).with_query(
                {"state": params["state"], "code": CODE, "iss": issuer}
            )
            return web.Response(status=302, headers={"Location": str(location)})
        if path == "/token":
            assert request.content_type == "application/x-www-form-urlencoded"
            data = dict(await request.post())
            state.seen_credentials.append(data)
            if state.redirect_token:
                return web.Response(status=307, headers={"Location": state.base + "/leak"})
            expected = (
                base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"].encode()).digest())
                .rstrip(b"=")
                .decode()
            )
            assert expected == state.grants["code_challenge"]
            assert data["code"] == CODE
            assert data["resource"] == state.grants["resource"]
            assert data["redirect_uri"] == state.grants["redirect_uri"]
            if state.auth_method == "client_secret_basic":
                header = request.headers["Authorization"]
                client, secret = base64.b64decode(header.removeprefix("Basic ")).decode().split(":")
                assert unquote_plus(client) == "existing-client"
                assert unquote_plus(secret) == SECRET
                assert "client_secret" not in data
            elif state.auth_method == "client_secret_post":
                assert data["client_secret"] == SECRET
                assert "Authorization" not in request.headers
            return web.json_response(state.token_reply, status=state.token_status)
        if path == "/mcp":
            payload = await request.json() if request.method == "POST" else None
            method = payload["method"] if payload else "GET"
            authenticated = request.headers.get("Authorization") == "Bearer " + TOKEN
            if (not authenticated and (state.protect_at is None or state.protect_at == method)) or (
                authenticated and method == state.fail_at
            ):
                return web.Response(
                    status=401,
                    headers={
                        "WWW-Authenticate": f'Bearer resource_metadata="{state.base}/metadata", '
                        'scope="tools.read"'
                    },
                )
            if authenticated and state.redirect_mcp:
                return web.Response(status=307, headers={"Location": state.base + "/leak"})
            if method == "GET":
                return web.Response(status=405)
            if method == "server/discover":
                if not state.modern:
                    return web.json_response(
                        {
                            "jsonrpc": "2.0",
                            "id": payload["id"],
                            "error": {"code": -32601, "message": "Not found"},
                        },
                        status=400,
                    )
                result = {
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}},
                    "resultType": "complete",
                }
            elif method == "initialize":
                result = {
                    "protocolVersion": "2025-11-25",
                    "serverInfo": {"name": "test", "version": "1"},
                    "capabilities": {"tools": {}},
                }
            elif method == "notifications/initialized":
                return web.Response(status=202)
            else:
                assert method == "tools/list"  # no arbitrary tool execution
                result = {"tools": [TOOL], **({"resultType": "complete"} if state.modern else {})}
            return web.json_response({"jsonrpc": "2.0", "id": payload["id"], "result": result})
        return web.Response(status=404)

    state.base = await serve(handler, server_ssl)

    async def browser(url):
        async with aiohttp.ClientSession(
            trust_env=False, connector=aiohttp.TCPConnector(resolver=PublicResolver())
        ) as client:
            async with client.get(url) as reply:
                assert reply.status in {200, 400}

    state.browser = browser
    return state


@pytest.mark.parametrize("modern", [False, True])
async def test_oauth_dcr_pkce_and_protected_probe(protected_server, modern):
    server = protected_server
    server.modern = modern
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "pass", report.to_dict()
    assert all(profile.status == "pass" for profile in report.clients.values())
    assert any(c.id == "oauth.authenticated_mcp" for c in report.generic.checks)
    assert server.grants["scope"] == "tools.read"  # challenge has priority over PRM defaults
    assert len(server.registered) == 1
    assert server.registered[0]["application_type"] == "native"
    assert server.registered[0]["grant_types"] == ["authorization_code"]
    serialized = json.dumps(report.to_dict())
    for secret in (
        TOKEN,
        CODE,
        server.grants["state"],
        server.seen_credentials[0]["code_verifier"],
        "secret-refresh-token",
        "secret-id-token",
    ):
        assert secret not in serialized
    assert all(auth is None or path == "/mcp" for _, path, auth in server.calls)


@pytest.mark.parametrize("method", ["none", "client_secret_basic", "client_secret_post"])
async def test_pre_registered_clients_skip_dcr(protected_server, method):
    server = protected_server
    server.auth_method = method
    options = OAuthOptions(
        client_id="existing-client",
        issuer=server.base + "/issuer",
        token_auth_method=method,
        client_secret=SECRET if method != "none" else None,
        scopes=["specific.read"],
    )
    report = await scan(server.base + "/mcp", oauth=options, present=server.browser)
    assert report.generic.status == "pass", report.to_dict()
    assert not server.registered
    assert server.grants["scope"] == "specific.read"
    assert server.grants["client_id"] == "existing-client"


@pytest.mark.parametrize(
    "method", ["server/discover", "initialize", "notifications/initialized", "tools/list", "GET"]
)
async def test_rejected_token_does_not_login_again(protected_server, method):
    server = protected_server
    server.fail_at = method
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "oauth.authorized_probe"
    assert len(server.registered) == 1
    assert sum(path == "/token" for _, path, _ in server.calls) == 1


@pytest.mark.parametrize("where", ["registration", "token", "mcp"])
async def test_oauth_secrets_never_follow_redirects(protected_server, where):
    server = protected_server
    setattr(server, "redirect_" + where, True)
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "oauth.redirects"
    assert not any(path == "/leak" for _, path, _ in server.calls)


async def test_issuer_mixup_never_exchanges_code(protected_server):
    server = protected_server
    server.callback_issuer = "https://attacker.example.com"
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "oauth.issuer"
    assert not any(path == "/token" for _, path, _ in server.calls)


async def test_pinned_issuer_mismatch_never_registers_or_logs_in(protected_server):
    server = protected_server
    options = OAuthOptions(client_id="existing", issuer="https://attacker.example.com")
    report = await scan(server.base + "/mcp", oauth=options, present=server.browser)
    assert report.generic.status == "fail"
    assert not server.registered and not server.grants and not server.seen_credentials


@pytest.mark.parametrize("method", ["tools/list", "notifications/initialized", "GET"])
async def test_late_auth_challenge_restarts_protocol_safely(protected_server, method):
    server = protected_server
    server.protect_at = method
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "pass", report.to_dict()


@pytest.mark.parametrize(
    "field,value",
    [
        ("access_token", "bad\r\nheader"),
        ("token_type", "DPoP"),
        ("expires_in", -1),
        ("expires_in", True),
        ("expires_in", 10**1000),
    ],
)
async def test_bad_token_response_is_safe_failure(protected_server, field, value):
    server = protected_server
    server.token_reply[field] = value
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert not any(auth for _, path, auth in server.calls if path == "/mcp")


async def test_no_dcr_is_configuration_warning(protected_server):
    server = protected_server
    server.dcr = False
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "warn"
    assert any(c.id == "oauth.client_setup" for c in report.generic.checks)
    assert not server.grants


async def test_default_check_is_still_passive(protected_server):
    server = protected_server
    report = await scan(server.base + "/mcp")
    assert report.generic.status == "warn"
    assert not server.registered and not server.grants and not server.seen_credentials


async def test_bad_dcr_callback_prevents_authorization(protected_server):
    server = protected_server
    server.bad_registration = True
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert not server.grants and not server.seen_credentials


@pytest.mark.parametrize(
    "destination",
    [
        "https://other.example.com/mcp",
        "http://mcp.example.com/mcp",
        "https://mcp.example.com/metadata",
        "https://mcp.example.com/mcp?other=1",
    ],
)
async def test_token_exact_target_binding_before_any_network(destination):
    token = BearerToken("https://mcp.example.com/mcp", TOKEN)
    async with SafeHTTP() as http:
        with pytest.raises(ScanError):
            await http.request("POST", destination, credential=token)
        assert http.count == 0
    assert TOKEN not in repr(token)


def test_pkce_pairs_are_independent():
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert len(challenge) == 43
    assert (verifier, challenge) != pkce_pair()


async def test_public_endpoint_does_not_start_oauth(protected_server):
    server = protected_server
    server.protect_at = "unencountered-operation"
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "pass", report.to_dict()
    assert not server.registered and not server.grants and not server.seen_credentials


async def test_oauth_timeout_closes_callback(protected_server):
    server = protected_server
    redirect_uri = None

    async def ignore_login(url):
        nonlocal redirect_uri
        redirect_uri = URL(url).query["redirect_uri"]

    report = await scan(
        server.base + "/mcp", oauth=OAuthOptions(wait_timeout=0.02), present=ignore_login
    )
    assert report.generic.status == "warn"
    assert report.generic.checks[-1].id == "oauth.timeout"
    assert not server.seen_credentials
    async with aiohttp.ClientSession() as client:
        with pytest.raises(aiohttp.ClientConnectorError):
            await client.get(redirect_uri)


@pytest.mark.parametrize(
    "key", ["authorization_endpoint", "token_endpoint", "registration_endpoint"]
)
async def test_private_oauth_destination_rejected_before_login(protected_server, key):
    server = protected_server
    server.metadata_overrides[key] = "https://127.0.0.1/private"
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "ssrf"
    assert not server.registered and not server.grants and not server.seen_credentials


@pytest.mark.parametrize("query", ["state=attacker", "redirect_uri=https://attacker.example.com"])
async def test_reserved_authorization_parameters_rejected_before_dcr(protected_server, query):
    server = protected_server
    server.metadata_overrides["authorization_endpoint"] = server.base + "/authorize?" + query
    report = await scan(server.base + "/mcp", oauth=OAuthOptions(), present=server.browser)
    assert report.generic.status == "fail"
    assert report.generic.checks[-1].id == "oauth.authorization_url"
    assert not server.registered and not server.grants and not server.seen_credentials


@pytest.mark.parametrize("value", ["x" + "=" * 8192, "secret\r\nheader", "", "a b"])
def test_invalid_bearer_rejected(value):
    token = BearerToken("https://mcp.example.com/mcp", value)
    with pytest.raises(ScanError, match="bounded HTTP Bearer"):
        token.header(token.endpoint)
