"""A small, read-only protocol probe, not a conformance-suite implementation."""

import ipaddress
import re

from yarl import URL

from canmcp import __version__
from canmcp.checks.network import ScanError
from canmcp.checks.oauth import check_oauth
from canmcp.checks.schemas import check_tools
from canmcp.models import Evidence, Status

LATEST = "2026-07-28"
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26")
SOURCE = "https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning"
TRANSPORT = (
    "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http"
)
LEGACY_TRANSPORT = "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports"
ALLOWED_METHODS = {"server/discover", "initialize", "notifications/initialized", "tools/list"}


def rpc_message(method, id, params, version):
    if method not in ALLOWED_METHODS:
        raise ValueError("This scanner cannot execute that MCP method")
    params = dict(params)
    headers = {"Accept": "application/json, text/event-stream"}
    if version:
        headers["MCP-Protocol-Version"] = version
    if version == LATEST:
        headers["Mcp-Method"] = method
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": LATEST,
            "io.modelcontextprotocol/clientInfo": {"name": "canmcp", "version": __version__},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    message = {"jsonrpc": "2.0", "method": method, "params": params}
    if id is not None:
        message["id"] = id
    return message, headers


def envelope(response, id):
    content_type = response.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type not in {"application/json", "text/event-stream"}:
        raise ScanError(
            "streamable_http", "MCP POST must return application/json or text/event-stream."
        )
    data = response.json()
    if (
        not isinstance(data, dict)
        or data.get("jsonrpc") != "2.0"
        or "method" in data
        or ("result" in data) == ("error" in data)
    ):
        raise ScanError("jsonrpc", "Expected a single JSON-RPC 2.0 response with result or error.")
    if type(data.get("id")) is not type(id) or data.get("id") != id:
        # Some protocol errors legally omit id. They are diagnostic failures, not successes.
        if "result" in data or data.get("id") is not None:
            raise ScanError("jsonrpc", "JSON-RPC response ID does not match the request.")
    if "error" in data:
        error = data["error"]
        if (
            not isinstance(error, dict)
            or type(error.get("code")) is not int
            or not isinstance(error.get("message"), str)
        ):
            raise ScanError("jsonrpc", "Malformed JSON-RPC error object.")
    elif not isinstance(data["result"], dict):
        raise ScanError("jsonrpc", "MCP result must be an object.")
    return data


def result(response, id, *, modern=False):
    data = envelope(response, id)
    if "error" in data:
        # Never echo untrusted server error messages into the report.
        raise ScanError("mcp", f"Server returned JSON-RPC error {data['error']['code']}.")
    if response.status != 200:
        raise ScanError(
            "streamable_http", f"MCP request returned HTTP {response.status} instead of 200."
        )
    value = data["result"]
    if modern and value.get("resultType") != "complete":
        if isinstance(value.get("resultType"), str):
            raise ScanError(
                "limits", "Server requires additional interaction or an unsupported result type."
            )
        raise ScanError("mcp", "Modern MCP result is missing resultType: complete.")
    return value


def version_list(value):
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or not all(isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v) for v in value)
    ):
        raise ScanError("protocol_version", "Advertised MCP versions are malformed.")
    return value


def capabilities(value):
    if not isinstance(value, dict):
        raise ScanError("mcp", "Server capabilities must be an object.")
    for key in ("tools", "resources", "prompts", "logging", "completions", "experimental"):
        if key in value and not isinstance(value[key], dict):
            raise ScanError("mcp", "Server capability declarations must be objects.")
    return value


async def check_protocol(http, evidence: Evidence, *, credential=None, issuer=None):
    current = evidence.url
    session = None
    sequence = 0

    async def request(method, params, version):
        nonlocal current, sequence
        sequence += 1
        id = None if method == "notifications/initialized" else sequence
        message, headers = rpc_message(method, id, params, version)
        if session:
            headers["Mcp-Session-Id"] = session
        kwargs = {"credential": credential} if credential is not None else {}
        response = await http.request("POST", current, payload=message, headers=headers, **kwargs)
        current = response.url
        evidence.final_url = current
        if response.redirects:
            evidence.add(
                "redirects",
                Status.WARN,
                f"Followed {len(response.redirects)} method-preserving redirects; "
                "configure the canonical endpoint URL.",
            )
        return response, id

    async def protected(response):
        if credential is not None:
            raise ScanError(
                "oauth.authorized_probe",
                "MCP endpoint rejected the obtained token (401/403); no automatic login retry.",
            )
        await check_oauth(http, response, evidence, issuer=issuer)

    response, id = await request("server/discover", {}, LATEST)
    evidence.add("reachability", Status.PASS, f"Endpoint responded with HTTP {response.status}.")
    evidence.add("dns", Status.PASS, "Connected using a validated public IP address.")
    try:
        ipaddress.ip_address(URL(current).host)
    except ValueError:
        evidence.add("addressing", Status.PASS, "Endpoint uses a DNS hostname.")
    else:
        evidence.add(
            "addressing",
            Status.PASS,
            "Endpoint uses a direct public IP. No undocumented client-specific IP ban is assumed.",
        )
    evidence.add(
        "tls",
        Status.PASS,
        "TLS certificate chain, validity period, and hostname verified."
        if current.startswith("https:")
        else "Plain HTTP endpoint: TLS certificate checks are not applicable.",
    )
    if not any(c.id == "redirects" for c in evidence.checks):
        evidence.add("redirects", Status.PASS, "Initial MCP request did not redirect.")
    if response.status in {401, 403}:
        await protected(response)
        return

    modern = False
    # Discovery distinguishes eras without invoking a tool or probing arbitrary methods.
    try:
        data = envelope(response, id)
    except ScanError:
        if response.status not in {400, 404, 405, 406, 415}:
            raise
        data = None
    if data and "result" in data:
        discovered = result(response, id, modern=True)
        versions = version_list(discovered.get("supportedVersions"))
        evidence.advertised_versions = versions
        if LATEST not in versions:
            raise ScanError(
                "protocol_version",
                "Discovery succeeded but does not advertise the requested MCP version.",
            )
        caps = capabilities(discovered.get("capabilities"))
        evidence.protocol_version = LATEST
        modern = True
        evidence.add(
            "mcp.discover",
            Status.PASS,
            "server/discover succeeded using per-request MCP metadata.",
            SOURCE,
        )
        evidence.add(
            "mcp.initialize",
            Status.PASS,
            "initialize is not applicable to the 2026-07-28 stateless protocol.",
            SOURCE,
        )
    elif data and data.get("error", {}).get("code") == -32022:
        error_data = data["error"].get("data")
        versions = version_list(
            error_data.get("supported") if isinstance(error_data, dict) else None
        )
        evidence.advertised_versions = versions
        if not any(v in LEGACY for v in versions):
            raise ScanError(
                "unsupported_version",
                "Server advertises no MCP revision implemented by this scanner.",
            )
    elif response.status >= 500:
        raise ScanError("reachability", f"Endpoint returned HTTP {response.status}.")

    if not modern:
        response, id = await request(
            "initialize",
            {
                "protocolVersion": LEGACY[0],
                "capabilities": {},
                "clientInfo": {"name": "canmcp", "version": __version__},
            },
            None,
        )
        if response.status in {401, 403}:
            await protected(response)
            return
        initialized = result(response, id)
        version = initialized.get("protocolVersion")
        if not isinstance(version, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", version):
            raise ScanError("protocol_version", "initialize did not return a valid MCP version.")
        evidence.protocol_version = version
        if version not in LEGACY:
            raise ScanError(
                "unsupported_version",
                "Negotiated revision is not implemented for Streamable HTTP by this scanner.",
            )
        caps = capabilities(initialized.get("capabilities"))
        info = initialized.get("serverInfo")
        if (
            not isinstance(info, dict)
            or not isinstance(info.get("name"), str)
            or not isinstance(info.get("version"), str)
        ):
            raise ScanError(
                "mcp.initialize", "initialize is missing valid serverInfo name/version."
            )
        session = response.headers.get("mcp-session-id")
        if session is not None and (
            not session or len(session) > 1024 or any(not 33 <= ord(c) <= 126 for c in session)
        ):
            raise ScanError(
                "mcp.session",
                "MCP session ID must contain visible ASCII and fit the scanner limit.",
            )
        evidence.add(
            "mcp.initialize",
            Status.PASS,
            "initialize returned server identity and capabilities.",
            SOURCE,
        )
        response, _ = await request("notifications/initialized", {}, version)
        if response.status in {401, 403}:
            await protected(response)
            return
        if response.status != 202 or response.body:
            raise ScanError(
                "mcp.initialized",
                "Accepted initialized notification must return HTTP 202 with no body.",
            )
        evidence.add(
            "mcp.initialized",
            Status.PASS,
            "Initialized notification accepted with an empty HTTP 202.",
            LEGACY_TRANSPORT,
        )
    evidence.add(
        "protocol_version",
        Status.PASS,
        f"Observed MCP revision {evidence.protocol_version}.",
        SOURCE,
    )
    if "tools" not in caps:
        evidence.add(
            "tools.list",
            Status.PASS,
            "Server does not advertise tools; tools/list is not applicable.",
        )
    else:
        tools, seen = [], set()
        cursor = None
        for _ in range(10):
            params = {} if cursor is None else {"cursor": cursor}
            response, id = await request("tools/list", params, evidence.protocol_version)
            if response.status in {401, 403}:
                await protected(response)
                return
            listing = result(response, id, modern=modern)
            page = listing.get("tools")
            if not isinstance(page, list):
                raise ScanError("tools.list", "tools/list result must contain a tools array.")
            tools.extend(page)
            if len(tools) > 500:
                raise ScanError("limits", "Tool count exceeds 500; inspection is incomplete.")
            if "nextCursor" not in listing:
                break
            cursor = listing["nextCursor"]
            if not isinstance(cursor, str) or not cursor or len(cursor) > 4096:
                raise ScanError(
                    "tools.list", "Pagination cursor must be a non-empty bounded string."
                )
            if cursor in seen:
                raise ScanError("tools.list", "tools/list repeats a pagination cursor.")
            seen.add(cursor)
        else:
            raise ScanError("limits", "More than 10 tools/list pages; inspection is incomplete.")
        evidence.add("tools.list", Status.PASS, f"Listed {len(tools)} tools without executing any.")
        check_tools(tools, evidence)
    if not modern:
        headers = {"Accept": "text/event-stream", "MCP-Protocol-Version": evidence.protocol_version}
        if session:
            headers["Mcp-Session-Id"] = session
        kwargs = {"credential": credential} if credential is not None else {}
        response = await http.request("GET", current, headers=headers, headers_only=True, **kwargs)
        if response.status in {401, 403}:
            await protected(response)
            return
        if response.redirects:
            evidence.add(
                "redirects.get",
                Status.WARN,
                "Legacy GET transport redirects; verify the canonical endpoint URL.",
            )
        content_type = response.headers.get("content-type", "").split(";")[0].lower()
        if response.status == 405 or (
            response.status == 200 and content_type == "text/event-stream"
        ):
            evidence.add(
                "streamable_http.get",
                Status.PASS,
                "GET offers SSE or explicitly returns 405.",
                LEGACY_TRANSPORT,
            )
        else:
            raise ScanError(
                "streamable_http.get", "Legacy Streamable HTTP GET must offer SSE or return 405."
            )
    evidence.add(
        "streamable_http",
        Status.PASS,
        "Read-only MCP exchanges succeeded over Streamable HTTP.",
        TRANSPORT,
    )
    evidence.protocol_ok = True
