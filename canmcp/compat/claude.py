from canmcp.compat.generic import base_reasons
from canmcp.models import Check, Evidence, Generic, Profile, Status, worst

# Scope: Claude hosted custom connectors; not local Claude Code/stdio or Messages API.
AUTH = "https://claude.com/docs/connectors/building/authentication"
MCP = "https://claude.com/docs/connectors/building/mcp"


def evaluate(evidence: Evidence, generic: Generic) -> Profile:
    reasons = base_reasons(generic)
    if evidence.missing_claude_hints:
        reasons.append(
            Check(
                "claude.tool_hints",
                Status.WARN,
                "Some tools lack readOnlyHint or destructiveHint requested by Claude's guide; "
                "approval behavior is unverified.",
                MCP,
            )
        )
    if evidence.auth_servers:
        usable = any(
            server.get("registration_endpoint")
            or (
                server.get("client_id_metadata_document_supported") is True
                and "none" in server.get("token_endpoint_auth_methods_supported", [])
            )
            for server in evidence.auth_servers
        )
        if not usable:
            reasons.append(
                Check(
                    "claude.registration",
                    Status.WARN,
                    "Claude CIMD requires token authentication method 'none'; "
                    "no usable CIMD or DCR was advertised. "
                    "A pre-registered client may be required.",
                    AUTH,
                )
            )
    return Profile(worst(reasons), reasons)
