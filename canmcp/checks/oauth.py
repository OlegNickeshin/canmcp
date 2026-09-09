"""Read-only OAuth discovery. DCR/PKCE are advertised support, not active proof."""

import re

from yarl import URL

from canmcp.checks.network import ScanError, validate_url
from canmcp.models import Check, Evidence, Status

SOURCE = "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery"
AUTH_SOURCE = "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization"
TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
PARAM = re.compile(rf'^({TOKEN})\s*=\s*(?:"((?:[^"\\]|\\.)*)"|({TOKEN}))$')


def bearer_challenge(header: str):
    """Parse comma-separated challenges without matching text inside quoted realms."""
    parts, current, quoted, escaped = [], [], False, False
    for char in header:
        if ord(char) < 32 and char != "\t":
            raise ScanError("oauth.www_authenticate", "Control character in WWW-Authenticate.")
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if quoted or escaped:
        raise ScanError("oauth.www_authenticate", "Unterminated quoted value in WWW-Authenticate.")
    parts.append("".join(current).strip())
    scheme, params, found = None, {}, None
    for part in parts:
        match = PARAM.fullmatch(part)
        if match is None:
            start = re.fullmatch(rf"({TOKEN})(?:\s+(.+))?", part)
            if not start:
                raise ScanError("oauth.www_authenticate", "Malformed WWW-Authenticate challenge.")
            if scheme == "bearer":
                if found is not None:
                    raise ScanError(
                        "oauth.www_authenticate", "Ambiguous multiple Bearer challenges."
                    )
                found = params
            scheme, params = start[1].lower(), {}
            part = start[2]
            if not part:
                continue
            match = PARAM.fullmatch(part)
        if scheme == "bearer":
            if match is None or match[1].lower() in params:
                raise ScanError(
                    "oauth.www_authenticate", "Malformed or duplicate Bearer parameter."
                )
            params[match[1].lower()] = (
                re.sub(r"\\(.)", r"\1", match[2]) if match[2] is not None else match[3]
            )
    if scheme == "bearer":
        if found is not None:
            raise ScanError("oauth.www_authenticate", "Ambiguous multiple Bearer challenges.")
        found = params
    if found is None:
        raise ScanError(
            "oauth.www_authenticate", "No Bearer challenge; OAuth discovery may be unavailable."
        )
    return found


def metadata_urls(issuer: str):
    url = URL(issuer)
    origin, path = str(url.origin()), url.raw_path.rstrip("/")
    return list(
        dict.fromkeys(
            [
                origin + "/.well-known/oauth-authorization-server" + path,
                origin + "/.well-known/openid-configuration" + path,
                origin + path + "/.well-known/openid-configuration",
            ]
        )
    )


def https_url(value, *, issuer=False):
    url = validate_url(value)
    if url.scheme != "https" or (issuer and url.query_string):
        raise ScanError(
            "oauth.metadata", "OAuth metadata requires HTTPS URLs; issuer cannot have a query."
        )
    return url


def string_list(document, key, *, required=False, default=None):
    value = document.get(key, default)
    if value is None and not required:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ScanError("oauth.metadata", f"OAuth {key} must be an array of strings.")
    if required and not value:
        raise ScanError("oauth.metadata", f"OAuth {key} cannot be empty.")
    return value


def validate_auth_server(document: dict, issuer: str):
    if document.get("issuer") != issuer:
        raise ScanError(
            "oauth.issuer", "Authorization metadata issuer does not exactly match discovery issuer."
        )
    https_url(document.get("authorization_endpoint"))
    https_url(document.get("token_endpoint"))
    response_types = string_list(document, "response_types_supported", required=True)
    grants = string_list(
        document, "grant_types_supported", default=["authorization_code", "implicit"]
    )
    methods = string_list(document, "code_challenge_methods_supported")
    string_list(document, "token_endpoint_auth_methods_supported")
    string_list(document, "scopes_supported")
    if "code" not in response_types or "authorization_code" not in grants:
        raise ScanError("oauth.authorization_code", "Authorization-code flow is not advertised.")
    if "S256" not in methods:
        raise ScanError(
            "oauth.pkce", "S256 PKCE support is not advertised; clients cannot verify support."
        )
    if "registration_endpoint" in document:
        https_url(document["registration_endpoint"])
    for key in (
        "client_id_metadata_document_supported",
        "authorization_response_iss_parameter_supported",
    ):
        if key in document and not isinstance(document[key], bool):
            raise ScanError("oauth.metadata", f"OAuth {key} must be a boolean.")


async def fetch_document(http, candidates):
    for candidate in candidates:
        https_url(candidate)
        response = await http.request("GET", candidate, headers={"Accept": "application/json"})
        if response.status in {404, 405}:
            continue
        if response.status != 200:
            raise ScanError("oauth.metadata", f"OAuth discovery returned HTTP {response.status}.")
        if response.headers.get("content-type", "").split(";")[0].lower() != "application/json":
            raise ScanError("oauth.metadata", "OAuth discovery must return application/json.")
        document = response.json()
        if not isinstance(document, dict):
            raise ScanError("oauth.metadata", "OAuth metadata must be a JSON object.")
        return document
    raise ScanError("oauth.metadata", "No metadata document found at the standard discovery URLs.")


async def check_oauth(http, response, evidence: Evidence):
    evidence.protected = True
    evidence.add(
        "oauth.authentication",
        Status.WARN,
        "Endpoint requires authentication; protected MCP operations remain unverified."
        if response.status == 401
        else "Endpoint returned 403; authentication, scope, or firewall policy may deny access. "
        "Protected MCP operations remain unverified.",
    )
    challenge = {}
    try:
        challenge = bearer_challenge(response.headers.get("www-authenticate", ""))
        if "error" in challenge and challenge["error"] not in {
            "invalid_request",
            "invalid_token",
            "insufficient_scope",
        }:
            raise ScanError("oauth.www_authenticate", "Unrecognized Bearer error code.")
        evidence.add(
            "oauth.www_authenticate", Status.PASS, "Bearer challenge parses correctly.", SOURCE
        )
    except ScanError as exc:
        evidence.add(exc.check_id, Status.FAIL, str(exc), SOURCE)
    endpoint = URL(response.url).with_query(None)
    origin = str(endpoint.origin())
    if "resource_metadata" in challenge:
        candidates = [challenge["resource_metadata"]]
    else:
        candidates = list(
            dict.fromkeys(
                [
                    origin
                    + "/.well-known/oauth-protected-resource"
                    + endpoint.raw_path.rstrip("/"),
                    origin + "/.well-known/oauth-protected-resource",
                ]
            )
        )
    resource = await fetch_document(http, candidates)
    identifier = resource.get("resource")
    https_url(identifier, issuer=True)
    if identifier not in {str(endpoint), origin, origin + "/"}:
        raise ScanError(
            "oauth.resource", "Resource identifier does not match this endpoint or its origin."
        )
    issuers = string_list(resource, "authorization_servers", required=True)
    string_list(resource, "scopes_supported")
    evidence.add(
        "oauth.protected_resource",
        Status.PASS,
        "Protected Resource Metadata identifies this resource and its issuers.",
        SOURCE,
    )
    errors = []
    for issuer in issuers[:3]:
        try:
            https_url(issuer, issuer=True)
            document = await fetch_document(http, metadata_urls(issuer))
            validate_auth_server(document, issuer)
            evidence.auth_servers.append(document)
            evidence.add(
                "oauth.authorization_server",
                Status.PASS,
                "Authorization metadata has a matching issuer and HTTPS endpoints.",
                SOURCE,
            )
            evidence.add(
                "oauth.pkce",
                Status.PASS,
                "S256 PKCE is advertised; enforcement was not exercised.",
                AUTH_SOURCE,
            )
            dcr = bool(document.get("registration_endpoint"))
            evidence.add(
                "oauth.dcr",
                Status.PASS,
                "DCR endpoint advertised; no registration performed."
                if dcr
                else "DCR is not advertised; optional when CIMD or pre-registration is used.",
                AUTH_SOURCE,
            )
            evidence.add(
                "oauth.cimd",
                Status.PASS,
                "CIMD is advertised."
                if document.get("client_id_metadata_document_supported")
                else "CIMD is not advertised; alternative registration may be used.",
                AUTH_SOURCE,
            )
            if errors:
                evidence.add(
                    "oauth.alternatives",
                    Status.WARN,
                    "An earlier authorization server failed discovery; "
                    "a valid alternative was found.",
                    SOURCE,
                )
            return
        except ScanError as exc:
            if exc.check_id in {"ssrf", "limits"}:
                raise
            errors.append(Check(exc.check_id, Status.FAIL, str(exc), SOURCE))
    if len(issuers) > 3:
        evidence.add(
            "oauth.limits",
            Status.WARN,
            "Only the first three authorization servers were inspected.",
        )
    evidence.checks.extend(errors)
