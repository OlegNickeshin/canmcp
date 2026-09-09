"""Opt-in authorization-code + S256 PKCE; credentials live only for one scan.

Sources:
https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
https://www.rfc-editor.org/rfc/rfc8252
https://www.rfc-editor.org/rfc/rfc7636
https://www.rfc-editor.org/rfc/rfc7591
"""

import base64
import hashlib
import ipaddress
import math
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote_plus

from canmcp.callback import CallbackServer
from canmcp.checks.network import BearerToken, PublicResolver, ScanError
from canmcp.checks.oauth import https_url, string_list
from canmcp.models import Evidence, Status

SOURCE = "https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization"


@dataclass(repr=False)
class OAuthOptions:
    client_id: str | None = None
    issuer: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    token_auth_method: str = "none"
    scopes: list[str] | None = None
    callback_port: int = 0
    wait_timeout: float = 180

    def validate(self):
        if not math.isfinite(self.wait_timeout) or not 0 < self.wait_timeout <= 600:
            raise ScanError(
                "oauth.options", "OAuth wait timeout must be between 0 and 600 seconds."
            )
        if type(self.callback_port) is not int or not 0 <= self.callback_port <= 65535:
            raise ScanError("oauth.options", "Callback port must be between 0 and 65535.")
        if self.client_id is not None:
            bounded_string(self.client_id, "client ID")
            if self.issuer is None:
                raise ScanError(
                    "oauth.options",
                    "A pre-registered client ID requires an explicit --issuer binding.",
                )
        if self.issuer is not None:
            https_url(self.issuer, issuer=True)
        if self.token_auth_method not in {"none", "client_secret_basic", "client_secret_post"}:
            raise ScanError("oauth.options", "Unsupported token endpoint authentication method.")
        if self.client_secret is not None:
            bounded_string(self.client_secret, "client secret")
        if self.token_auth_method == "none":
            if self.client_secret is not None:
                raise ScanError(
                    "oauth.options", "Public client authentication cannot use a client secret."
                )
        elif self.client_id is None or self.client_secret is None:
            raise ScanError(
                "oauth.options",
                "Secret authentication requires a pre-registered client and its secret.",
            )
        if self.scopes is not None:
            validate_scopes(self.scopes)


def bounded_string(value, label):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise ScanError("oauth.response", f"OAuth {label} is missing or malformed.")
    return value


def validate_scopes(scopes):
    # RFC 6749 scope-token; no invented offline_access request for this short-lived scan.
    if (
        not isinstance(scopes, list)
        or len(scopes) > 64
        or any(
            not isinstance(scope, str)
            or not re.fullmatch(r"[\x21\x23-\x5B\x5D-\x7E]{1,256}", scope)
            for scope in scopes
        )
    ):
        raise ScanError("oauth.scope", "OAuth scopes must be bounded RFC 6749 scope tokens.")
    return list(dict.fromkeys(scopes))


def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


async def verify_browser_target(value):
    target = https_url(value)
    try:
        ipaddress.ip_address(target.host)
    except ValueError:
        await PublicResolver().resolve(target.raw_host, target.port)
    return target


async def present_login(url: str):
    # Do not auto-launch a browser: its DNS/redirect handling is outside our SSRF boundary.
    # The URL is serialized/percent-encoded, never server prose or a shell command.
    print(
        "Open this URL in a browser on this machine to authorize CanMCP:\n" + url,
        file=sys.stderr,
        flush=True,
    )


def oauth_document(response, expected_status: int, operation: str):
    if response.status != expected_status:
        raise ScanError("oauth." + operation, f"OAuth {operation} returned HTTP {response.status}.")
    if response.headers.get("content-type", "").split(";")[0].lower() != "application/json":
        raise ScanError("oauth." + operation, f"OAuth {operation} must return application/json.")
    document = response.json()
    if not isinstance(document, dict) or "error" in document:
        raise ScanError(
            "oauth." + operation, f"OAuth {operation} returned an error or invalid object."
        )
    return document


async def register_client(http, metadata, redirect_uri, evidence):
    endpoint = metadata.get("registration_endpoint")
    if not endpoint:
        raise ScanError(
            "oauth.client_setup",
            "No DCR endpoint; supply a pre-registered --client-id and --issuer.",
        )
    https_url(endpoint)
    request = {
        "client_name": "CanMCP local compatibility scanner",
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    response = await http.request(
        "POST",
        endpoint,
        payload=request,
        headers={"Accept": "application/json"},
        follow_redirects=False,
    )
    document = oauth_document(response, 201, "registration")
    client_id = bounded_string(document.get("client_id"), "registered client ID")
    if document.get("token_endpoint_auth_method") != "none" or document.get("redirect_uris") != [
        redirect_uri
    ]:
        raise ScanError(
            "oauth.registration",
            "DCR did not confirm the public client method and exact callback URI.",
        )
    evidence.add(
        "oauth.registration",
        Status.PASS,
        "Registered a public native OAuth client for this scan; provider registration may persist.",
        SOURCE,
    )
    return client_id


async def exchange_code(
    http, metadata, options, client_id, code, verifier, redirect_uri, resource, endpoint
):
    bounded_string(code, "authorization code")
    token_url = str(https_url(metadata["token_endpoint"]))
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": resource,
    }
    headers = {"Accept": "application/json"}
    if options.token_auth_method == "client_secret_basic":
        # RFC 6749 section 2.3.1 encodes each credential before constructing HTTP Basic.
        encoded = quote_plus(client_id) + ":" + quote_plus(options.client_secret)
        headers["Authorization"] = "Basic " + base64.b64encode(encoded.encode()).decode("ascii")
    elif options.token_auth_method == "client_secret_post":
        form["client_secret"] = options.client_secret
    response = await http.request(
        "POST", token_url, form=form, headers=headers, follow_redirects=False
    )
    document = oauth_document(response, 200, "token")
    token_type = document.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise ScanError("oauth.token", "Token response must use Bearer token_type.")
    value = document.get("access_token")
    bounded_string(value, "access token")
    expiration = document.get("expires_in")
    expires_at = None
    if "expires_in" in document:
        if type(expiration) not in {int, float} or not 0 < expiration <= 315_360_000:
            raise ScanError("oauth.token", "Token expires_in must be a positive bounded number.")
        expires_at = time.monotonic() + expiration
    credential = BearerToken(endpoint, value, expires_at)
    credential.header(endpoint)  # Validate before any MCP request.
    # Refresh/ID/registration tokens are deliberately discarded, never returned or logged.
    return credential


async def authorize(
    http,
    evidence: Evidence,
    options: OAuthOptions,
    *,
    present=present_login,
    callback_factory=CallbackServer,
):
    options.validate()
    endpoint = str(https_url(evidence.final_url or evidence.url))
    if not evidence.resource or not evidence.auth_servers:
        raise ScanError(
            "oauth.discovery", "No validated resource and authorization server are available."
        )
    metadata = evidence.auth_servers[0]
    issuer = metadata["issuer"]
    if options.issuer is not None and issuer != options.issuer:
        raise ScanError(
            "oauth.issuer", "Selected authorization server differs from the pinned issuer."
        )
    # Browser navigation is explicit user action. Still reject known non-public destinations first.
    authorization_url = await verify_browser_target(metadata["authorization_endpoint"])
    # Reject ambiguous metadata before registration can create a client at the provider.
    # Other query parameters on authorization endpoints are allowed by OAuth.
    reserved = {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "resource",
        "scope",
        "code",
        "code_verifier",
        "client_secret",
        "access_token",
        "response_mode",
        "request",
        "request_uri",
    }
    if any(key in reserved for key in authorization_url.query):
        raise ScanError(
            "oauth.authorization_url",
            "Authorization endpoint query contains reserved OAuth parameters.",
        )
    methods = string_list(
        metadata, "token_endpoint_auth_methods_supported", default=["client_secret_basic"]
    )
    if options.token_auth_method not in methods:
        raise ScanError(
            "oauth.client_setup",
            "Authorization server does not advertise the selected client authentication method.",
        )
    scopes = validate_scopes(
        options.scopes if options.scopes is not None else evidence.oauth_scopes
    )
    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(32)
    async with callback_factory(
        state,
        issuer,
        metadata.get("authorization_response_iss_parameter_supported") is True,
        options.callback_port,
    ) as callback:
        client_id = options.client_id
        if client_id is None:
            client_id = await register_client(http, metadata, callback.redirect_uri, evidence)
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": callback.redirect_uri,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": evidence.resource,
        }
        if scopes:
            params["scope"] = " ".join(scopes)
        login_url = str(authorization_url.extend_query(params))
        if len(login_url) > 16_384:
            raise ScanError("limits", "Authorization URL exceeds the scanner's length limit.")
        await present(login_url)
        code = await callback.wait(options.wait_timeout)
        credential = await exchange_code(
            http,
            metadata,
            options,
            client_id,
            code,
            verifier,
            callback.redirect_uri,
            evidence.resource,
            endpoint,
        )
    evidence.add(
        "oauth.token_exchange",
        Status.PASS,
        "Authorization code exchanged using S256 PKCE and a resource-bound token request.",
        SOURCE,
    )
    evidence.add(
        "oauth.credential_scope",
        Status.PASS,
        "Token is held in memory for this scan and bound to the exact MCP endpoint.",
        SOURCE,
    )
    return credential
