Your MCP server can be spec-compliant and still fail in ChatGPT or Claude. CanMCP tells you why.

# CanMCP

A small, open-source CLI for diagnosing public remote MCP endpoints from your own machine.
No hosted service, account, database, dashboard, or API key. Python 3.11+; MIT licensed.

[PyPI](https://pypi.org/project/canmcp/) ·
[Releases](https://github.com/OlegNickeshin/canmcp/releases) ·
[Report a bug](https://github.com/OlegNickeshin/canmcp/issues) ·
[MIT license](https://github.com/OlegNickeshin/canmcp/blob/main/LICENSE)

Part of **tools for an agent-native web**: small, independent open-source tools for connecting
agents to useful services. See the
[project series](https://github.com/OlegNickeshin/canmcp/blob/main/docs/series.md).

## For AI agents

Use CanMCP when a user asks why a remote MCP endpoint will not connect, or wants
protocol, TLS and OAuth diagnostics before configuring an MCP client. The
[CanMCP skill](skills/canmcp/SKILL.md) explains when to run the CLI, how to read
its JSON findings, and when an authenticated check needs separate permission.

Example tasks:

- "Diagnose why this MCP endpoint fails to connect in my client."
- "Check this remote MCP server without executing any of its tools."
- "Inspect the OAuth metadata and explain what remains unverified."

Agents need a terminal, Python 3.11+ and direct network access to run CanMCP.
The skill can be loaded by a skill-capable agent; it is not a remote connector
URL. A chat client without command execution must ask the user to run the CLI.
CanMCP remains a CLI, not a server published in the Official MCP Registry.

## Usage

Install from PyPI:

```sh
pip install canmcp
canmcp check https://example.com/mcp
canmcp check https://example.com/mcp --json
```

To install from source:

```sh
git clone https://github.com/OlegNickeshin/canmcp.git
cd canmcp
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install .
canmcp check https://example.com/mcp
```

Replace the example URL with a real public MCP endpoint. DNS and direct outbound HTTP(S)
must work on the machine running CanMCP. Proxy environment variables are deliberately ignored.

```sh
canmcp check https://example.com/mcp --timeout 15
canmcp check https://example.com/mcp --json > report.json
python -m canmcp --version
```

### Inspecting a protected endpoint

Version 0.2 adds optional interactive OAuth. The default command only inspects metadata;
it never signs in or registers a client. To authorize a protected MCP inspection:

```sh
canmcp check https://example.com/mcp --oauth
canmcp check https://example.com/mcp --oauth --json > report.json
```

CanMCP prints an authorization link to **stderr**. Open it in a browser on the same machine
and review the provider's consent screen. The browser returns to a temporary listener at
`http://127.0.0.1:PORT/oauth/callback`. No deployed server is needed. The listener binds only
loopback, accepts one authorization result, and closes on completion, timeout, or interruption.
The default browser wait is 180 seconds; `--oauth-timeout 300` changes it, up to 600 seconds.

Without `--client-id`, CanMCP attempts Dynamic Client Registration (DCR) for a public native
client if advertised. **This creates a client registration at the provider that may persist.**
CanMCP neither saves the registration nor deletes it afterward. Current MCP guidance prefers
pre-registration or Client ID Metadata Documents (CIMD); DCR is a deprecated compatibility
fallback. If DCR is unavailable, the report explains that client configuration is needed.
CanMCP does not host a CIMD document.

To use an existing registration, configure its redirect URI as
`http://127.0.0.1:8765/oauth/callback`, then pass the provider's exact issuer and client ID:

```sh
canmcp check https://example.com/mcp --oauth \
  --issuer https://auth.example.com \
  --client-id YOUR_CLIENT_ID --callback-port 8765
```

The issuer must exactly match one advertised in the resource metadata. Public clients use
`none` token authentication. For a pre-registered client that requires a secret, place it in
an environment variable yourself and add `--client-secret-env CANMCP_CLIENT_SECRET`.
CanMCP reads only that explicitly named variable. The default with a secret is
`client_secret_basic`; use `--token-auth-method client_secret_post` if your registration
requires it. Secrets cannot be supplied as command-line values. `private_key_jwt` is not
implemented.

Scopes come from the Bearer challenge, falling back to resource metadata. To choose explicit
scopes, use `--scope tools.read`, repeating the flag for additional scopes. CanMCP adds no
offline-access scope of its own and never refreshes tokens. A public endpoint needs no login,
even with `--oauth`.

After a successful code exchange using S256 PKCE, CanMCP repeats MCP discovery/initialization
and `tools/list` with the token. Tokens stay in process memory for the scan and are bound to
the **exact final MCP URL**; OAuth writes and authenticated MCP requests never follow redirects.
The report contains no code, verifier, state, client secret, or token. The separate login link
necessarily contains state, the PKCE challenge, and the public client ID. Login tests CanMCP's
client registration, not ChatGPT's or Claude's actual OAuth integration.

An illustrative result for a valid server with incomplete ChatGPT tool metadata:

```text
Generic MCP: PASS
- All implemented MCP protocol checks passed

ChatGPT: WARN
- Some tools lack descriptions or annotations recommended by ChatGPT's endpoint preparation guide

Claude: PASS
- All implemented MCP protocol checks passed
```

## Reading a report

- **PASS:** the implemented checks completed successfully, or a particular check is inapplicable
  with a stated reason. This is not full MCP certification or proof of cloud-client acceptance.
- **WARN:** a compatibility concern, an optional feature is unavailable, an unknown revision/dialect,
  or inspection could not finish within a safety limit.
- **FAIL:** an observed protocol/metadata error, connectivity failure, blocked target, or a documented
  client requirement is unmet. Failures describe this local observation.

Each profile includes reasons. A profile inherits generic findings, then adds its own documented
rules. `chatgpt` means public remote endpoints in ChatGPT; `claude` means hosted custom connectors.
They do not claim to represent every local, API, tunnel, directory-review, or account configuration.
The profiles are qualitative diagnostics, not invented numerical probabilities.

Exit codes: `0` all profiles pass; `1` at least one fails; `2` warning/incomplete inspection or CLI
usage error; `130` interrupted. Valid `check --json` invocations write one JSON object to stdout,
including on scan failures. CLI usage errors go to stderr.

JSON shape (abbreviated):

```json
{
  "url": "https://example.com/mcp",
  "generic": {
    "status": "pass",
    "checks": [{"id": "tools.list", "status": "pass", "message": "Listed 2 tools without executing any.", "source": null}]
  },
  "clients": {
    "chatgpt": {"status": "warn", "reasons": [{"id": "chatgpt.tool_metadata", "status": "warn", "message": "Some tools lack descriptions or annotations.", "source": "https://developers.openai.com/plugins/deploy/connect-chatgpt"}]},
    "claude": {"status": "pass", "reasons": [{"id": "mcp", "status": "pass", "message": "All implemented MCP protocol checks passed.", "source": null}]}
  },
  "protocol_version": "2025-11-25",
  "advertised_versions": [],
  "final_url": "https://example.com/mcp",
  "schema_version": "1",
  "scanner_version": "0.2.0",
  "limitations": ["Local observation; no cloud-client connection was performed."]
}
```

`protocol_version` is observed, not guessed. `advertised_versions` contains claims from discovery
or a version error, not independently verified support for every listed version. URLs in reports
omit userinfo, query strings and fragments; the request still uses the supplied query. Server
messages, instructions, descriptions, tool names, and tokens are not copied into reports.

## Checks in v0.2

| Area | Implemented inspection |
| --- | --- |
| URL and reachability | HTTP(S) syntax, public-target policy, response status and bounded timeout |
| DNS | A and AAAA queries using system-configured DNS; all returned addresses must be public |
| TLS | Normal platform CA trust, chain, validity period, and URL hostname/IP verification; no insecure switch |
| Redirects | Maximum five hops; validate every target; preserve POST only for 307/308; reject HTTPS downgrade and cross-origin session forwarding |
| Streamable HTTP | POST JSON or SSE, strict UTF-8 JSON-RPC envelope and matching ID; stop SSE on the response; legacy GET SSE/405 |
| MCP revisions | 2026-07-28 `server/discover` and request metadata; fallback `initialize` for 2025-11-25, 2025-06-18, 2025-03-26 |
| Initialization | Legacy identity/capabilities, negotiated revision, session ID, initialized notification and HTTP 202 |
| Tools | Capability-aware `tools/list`, pagination, descriptor types, input/output JSON Schema dialect validation and modern `x-mcp-header` constraints |
| Protected endpoints | On 401/403: Bearer `WWW-Authenticate`, Protected Resource Metadata, RFC 8414/OIDC discovery, resource/issuer binding, HTTPS endpoint URLs, authorization-code flow, advertised S256 PKCE, DCR and CIMD |
| Optional OAuth login | Public DCR or pre-registered client; S256 PKCE, random state, callback issuer validation, resource parameter at authorization and token endpoints, Bearer response validation, authenticated MCP inspection |
| Client profiles | ChatGPT public HTTPS and tool metadata; ChatGPT/Claude registration-method differences; Claude tool hints |

Schema validation is static. Remote references and unknown dialects produce incomplete-coverage
warnings; reference graphs are not evaluated against tool arguments. Tool annotations are untrusted
claims: CanMCP checks their types, not whether a tool actually is safe or read-only.

Without `--oauth`, protected endpoints are reported as **WARN or FAIL** because protected
operations remain unverified. With a successful login and completed checks, generic MCP can
**PASS**. Metadata inspection alone checks advertised PKCE/DCR support; optional login exercises
a valid PKCE exchange but does not attempt invalid-verifier attacks to prove server enforcement.
The first usable authorization server is inspected (at most three candidates); other providers
may differ. Absence of DCR is not a generic failure: CIMD and pre-registration are valid alternatives.

## Relationship to official MCP tooling

The [current specification](https://modelcontextprotocol.io/specification/2026-07-28) and
[official conformance framework](https://github.com/modelcontextprotocol/conformance) were reviewed
before implementation. Revision 2026-07-28 has stateless requests; earlier supported revisions
use initialization. CanMCP follows this distinction instead of treating missing initialization
as a failure on a modern server.

The official suite covers implementation conformance far beyond this diagnostic. Some scenarios
call tools and expect particular fixture behavior. CanMCP does not wrap or automatically run it
against arbitrary endpoints. Use the suite separately against a server you control when you need
full conformance testing. CanMCP adds safe public-endpoint inspection, deployment diagnostics,
and source-backed client profiles; it is deliberately not another conformance framework.

See [sources and rule rationale](https://github.com/OlegNickeshin/canmcp/blob/main/docs/sources.md)
for the exact official links and profile scope.

## Safety and limits

MCP requests are limited to `server/discover`, `initialize`, `notifications/initialized`,
`tools/list`, and legacy transport GET. Default OAuth inspection uses only metadata GET.
Explicit `--oauth` additionally permits DCR POST and authorization-code token exchange POST.
The server can log requests, allocate a legacy MCP session, or retain a DCR registration.
No arbitrary MCP tools, server-supplied commands, URLs from tool schemas, sampling, elicitation,
or resource reads are executed. Environment credentials are read only when a variable is
explicitly named with `--client-secret-env`.

All outbound scanner HTTP destinations, including OAuth writes, metadata, and redirects,
cross the same SSRF boundary. DNS
answers are checked immediately before connection and handed to the connector as numeric IPs.
TLS SNI and HTTP Host still use the intended hostname. There is no second hostname lookup between
validation and connection, DNS cache, connection reuse, cookie jar, or environment proxy.
Private, loopback, localhost, link-local, multicast, shared, reserved, documentation, and selected
IPv6 transition targets are refused. There is no public CLI override for private targets.
DNS uses the machine's configured resolver, with search suffix expansion disabled; `/etc/hosts`
overrides are not used. DNS traffic itself goes to that trusted local resolver.

The OAuth callback is an inbound loopback listener, not an exception for outbound requests:
scanning localhost stays forbidden. The callback handler returns fixed text, disables caching,
and includes no external assets; access and HTTP error logging are disabled. Browser navigation is outside the
scanner's network boundary. CanMCP checks the authorization endpoint's public DNS addresses
before displaying its link but cannot constrain a separate browser's DNS resolution, redirects,
extensions, or history. It does not launch the browser automatically.

Defaults: 10 seconds per request (configurable up to 30), 5 seconds per DNS resolution,
60 seconds per MCP inspection phase, 32 HTTP requests across the whole scan, five redirects
per unauthenticated request, 1 MiB per body/SSE exchange,
128 HTTP headers with bounded fields, 48 JSON nesting levels, 30,000 JSON nodes per response,
64 KiB/4,000 nodes per schema, 500 tools, and 10 list pages. Duplicate JSON keys and non-finite
numbers are rejected. Compressed bodies are not decoded. Limits are scanner policy, not invented
MCP/client requirements. They can produce WARN for an otherwise valid large or slow server.
OAuth adds the configured browser wait plus a 60-second budget for setup and token exchange;
the authenticated MCP phase has its own 60-second budget. Callback input is bounded to 128
requests, 16 query parameters, and an 8 KiB request line.

A local scanner cannot prove reachability from OpenAI or Anthropic IP ranges, inspect account
policies, detect every WAF rule, audit tool behavior, or compensate for a compromised local
network, resolver configuration, CA store, or routing table.
See [SECURITY.md](https://github.com/OlegNickeshin/canmcp/blob/main/SECURITY.md).

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
python -m build
```

Tests use scripted responses and local HTTP/TLS fixtures, including real certificate validation.
OAuth tests exercise a TLS authorization provider, DCR, browser redirects to the real loopback
callback, PKCE verification, token exchange, and protected MCP requests. Failure cases cover
issuer mix-ups, invalid state, denied authorization, timeouts, malformed token responses, credential
redirects, and callback cleanup. No real provider login or arbitrary tool call is required.
They need permission to bind loopback sockets, but no internet access. Only test fixtures replace
the resolver to route public-looking test names to loopback. Production policy stays enabled.

## Deliberately outside v0.2

No cloud-side probes, token persistence/refresh/revocation, automatic scope escalation, hosted
CIMD document, DCR registration cleanup, private-key client authentication, device-code login,
tool execution, full conformance suite, deprecated 2024 HTTP+SSE transport, stdio, SSE resumption,
MRTR interaction, resources or prompts inspection, schema reference fetching, certificate
revocation audit, dashboard, hosted server, users, database, payments, or telemetry.
