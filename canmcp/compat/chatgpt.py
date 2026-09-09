from canmcp.compat.generic import base_reasons
from canmcp.models import Check, Evidence, Generic, Profile, Status, worst

# Official ChatGPT public-endpoint profile; not the Responses API or Secure MCP Tunnel.
CONNECT = "https://developers.openai.com/plugins/deploy/connect-chatgpt"
AUTH = "https://developers.openai.com/plugins/build/auth"


def evaluate(evidence: Evidence, generic: Generic) -> Profile:
    reasons = base_reasons(generic)
    if not evidence.url.startswith("https://") or not (
        evidence.final_url or evidence.url
    ).startswith("https://"):
        reasons.append(
            Check(
                "chatgpt.https",
                Status.FAIL,
                "ChatGPT's public endpoint connection requires HTTPS.",
                CONNECT,
            )
        )
    if evidence.missing_descriptions or evidence.missing_annotations:
        reasons.append(
            Check(
                "chatgpt.tool_metadata",
                Status.WARN,
                "Some tools lack descriptions or annotations recommended by ChatGPT's "
                "endpoint preparation guide; tool selection/approval may be affected.",
                CONNECT,
            )
        )
    if evidence.auth_servers:
        usable = any(
            server.get("registration_endpoint")
            or (
                server.get("client_id_metadata_document_supported") is True
                and set(server.get("token_endpoint_auth_methods_supported", []))
                & {"none", "private_key_jwt"}
            )
            for server in evidence.auth_servers
        )
        if not usable:
            reasons.append(
                Check(
                    "chatgpt.registration",
                    Status.WARN,
                    "No advertised DCR or ChatGPT-compatible CIMD token authentication; "
                    "a predefined OAuth client may be required.",
                    AUTH,
                )
            )
    return Profile(worst(reasons), reasons)
