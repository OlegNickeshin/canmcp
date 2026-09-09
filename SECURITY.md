# Security policy

CanMCP processes hostile HTTP, JSON, SSE, tool descriptors, and OAuth documents. Never treat
their prose as instructions. This program contains no LLM, shell-command execution, tool-call
implementation, or server-provided executable configuration. OAuth credentials are used only
for explicitly requested interactive authorization; provider passwords are entered in the
provider's browser page, never in CanMCP.

Report vulnerabilities privately through the repository host's private vulnerability reporting
feature when this project is published. Until that is configured, contact the repository owner
privately; do not post credentials or exploitable endpoint details in a public issue.

The outbound security boundary is `canmcp/checks/network.py`. Any new outbound scanner HTTP
access must use that boundary. Tests that route fixture hostnames to loopback must stay inside
`tests/`; do not add
an implicit environment/configuration bypass. HTTP destinations are checked independently of
the trusted DNS resolver used to discover them. This protects against application-level SSRF
and DNS rebinding, not malicious local routing or an already compromised machine.

TLS uses platform trust and performs hostname/IP identity verification. Revocation, DNSSEC,
certificate transparency, cloud egress, and tool behavior are not audited. A PASS is a bounded
diagnostic result, not a security attestation.

## Interactive OAuth

The default scan never registers a client, reads a client secret, or requests tokens. `--oauth`
permits DCR and an authorization-code exchange after browser authorization. DCR creates provider
state which may outlive the scan. A pre-registered client ID requires an explicitly pinned issuer;
the only environment secret read is the variable named with `--client-secret-env`.

S256 PKCE and random state bind the browser response to a single authorization attempt.
Callback `iss`, if present, must exactly match the selected issuer; it is required when the
provider advertises RFC 9207 support. Both authorization and token requests carry the validated
resource identifier. This does not prove that the resource server validates token audience or
that the authorization server rejects invalid PKCE verifiers.

`canmcp/callback.py` binds an ephemeral listener to `127.0.0.1` only. It checks peer address,
Host, path, method, state, duplicate query parameters, issuer, and request/field limits. Unrelated
requests with invalid state do not consume the attempt. The listener disables access and HTTP error logging,
returns static no-store responses without external assets, accepts a code only once, and is
closed on completion, failure, timeout, or cancellation. This inbound listener does not permit
outbound scans of loopback/private targets.

CanMCP prints a serialized authorization link to stderr for manual opening on the same machine.
It checks that URL and its DNS answers before presenting it. The separate browser's subsequent
DNS resolution, redirects, history, and extensions are outside CanMCP's SSRF boundary.

Codes and tokens are not placed in reports or logs. Tokens are kept in process memory and sent
only to the exact final HTTPS MCP URL. They never accompany metadata requests. OAuth POSTs
and authenticated MCP requests reject every redirect, including same-origin redirects. The
scanner does not retry a rejected token with another automatic login. Refresh, ID, and DCR
management tokens are discarded; there is no credential cache, keychain integration, or token
revocation. Python memory is not guaranteed to be securely erased, and a compromised local
process, OS, browser, or OAuth provider is outside this threat model.
