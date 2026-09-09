import copy
import json

import pytest

from canmcp.checks.network import Response
from canmcp.checks.protocol import LATEST

URL = "https://mcp.example.com/mcp"
TOOL = {
    "name": "weather",
    "description": "Return weather information.",
    "annotations": {"readOnlyHint": True, "destructiveHint": False},
    "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}},
}


def response(body=None, status=200, url=URL, headers=None):
    return Response(
        status,
        headers or {"content-type": "application/json"},
        json.dumps(body).encode() if body is not None else b"",
        url,
        [],
    )


class MCPFixture:
    """Scripted public endpoint at the transport boundary; no external network."""

    def __init__(self, modern=False, tools=None):
        self.modern = modern
        self.tools = copy.deepcopy(tools if tools is not None else [TOOL])
        self.calls = []
        self.capabilities = {"tools": {}}
        self.version = "2025-11-25"
        self.pages = None
        self.override = None
        self.discovery = {}

    async def request(self, method, url, *, headers=None, payload=None, headers_only=False):
        self.calls.append((method, url, headers or {}, payload))
        if self.override:
            custom = self.override(method, url, payload)
            if custom is not None:
                return custom
        if url in self.discovery:
            return response(self.discovery[url], url=url)
        if method == "GET":
            return response(status=405 if url.endswith("/mcp") else 404, url=url)
        rpc = payload["method"]
        assert rpc in {"server/discover", "initialize", "notifications/initialized", "tools/list"}
        id = payload.get("id")
        if rpc == "server/discover":
            if not self.modern:
                return response(
                    {"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "Not found"}},
                    400,
                    url,
                )
            value = {
                "resultType": "complete",
                "supportedVersions": [LATEST],
                "capabilities": self.capabilities,
            }
            assert headers["Mcp-Method"] == rpc
            assert payload["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == LATEST
        elif rpc == "initialize":
            value = {
                "protocolVersion": self.version,
                "capabilities": self.capabilities,
                "serverInfo": {"name": "fixture", "version": "1"},
            }
            return response(
                {"jsonrpc": "2.0", "id": id, "result": value},
                url=url,
                headers={"content-type": "application/json", "mcp-session-id": "test-session"},
            )
        elif rpc == "notifications/initialized":
            assert headers["Mcp-Session-Id"] == "test-session"
            return response(status=202, url=url)
        else:
            if not self.modern:
                assert headers["Mcp-Session-Id"] == "test-session"
            value = self.pages.pop(0) if self.pages else {"tools": self.tools}
            if self.modern:
                value = {**value, "resultType": "complete"}
        return response({"jsonrpc": "2.0", "id": id, "result": value}, url=url)


@pytest.fixture
def mcp():
    return MCPFixture()


@pytest.fixture
def oauth():
    fixture = MCPFixture()

    def protect(method, url, payload):
        if method == "POST":
            return response(
                status=401,
                url=url,
                headers={
                    "www-authenticate": 'Bearer resource_metadata="https://mcp.example.com/metadata"',
                    "content-type": "application/json",
                },
            )

    fixture.override = protect
    fixture.discovery = {
        "https://mcp.example.com/metadata": {
            "resource": URL,
            "authorization_servers": ["https://auth.example.com/tenant"],
        },
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant": {
            "issuer": "https://auth.example.com/tenant",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        },
    }
    return fixture
