Your MCP server can be spec-compliant and still fail in ChatGPT or Claude. CanMCP tells you why.

# CanMCP

A small, open-source CLI for diagnosing public remote MCP endpoints from your own machine.
No hosted service, account, database, dashboard, or API key. Python 3.11+; MIT licensed.

## Usage

After a release is published to PyPI:

```sh
pip install canmcp
canmcp check https://example.com/mcp
canmcp check https://example.com/mcp --json
```

This initial source project has not been published to PyPI. From a clone, install it now:

```sh
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
  "scanner_version": "0.1.0",
  "limitations": ["Local observation; no cloud-client connection was performed."]
}
```

`protocol_version` is observed, not guessed. `advertised_versions` contains claims from discovery
or a version error, not independently verified support for every listed version. URLs in reports
omit userinfo, query strings and fragments; the request still uses the supplied query. Server
messages, instructions, descriptions, tool names, and tokens are not copied into reports.

## Checks in v0.1

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
| Client profiles | ChatGPT public HTTPS and tool metadata; ChatGPT/Claude registration-method differences; Claude tool hints |

Schema validation is static. Remote references and unknown dialects produce incomplete-coverage
warnings; reference graphs are not evaluated against tool arguments. Tool annotations are untrusted
claims: CanMCP checks their types, not whether a tool actually is safe or read-only.

Protected endpoints are reported as **WARN or FAIL**, never as a fully verified protocol PASS:
without signing in, `initialize`/`tools/list` may be inaccessible. PKCE and DCR checks concern
metadata advertisement. CanMCP does not attempt registration or prove PKCE enforcement.
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

See [sources and rule rationale](docs/sources.md) for the exact official links and profile scope.

## Safety and limits

Only `server/discover`, `initialize`, `notifications/initialized`, `tools/list`, legacy transport
GET, and OAuth metadata GET are sent. The server can still log requests or allocate a legacy MCP
session. No arbitrary MCP tools, server-supplied commands, URLs from tool schemas, sampling,
elicitation, or resource reads are executed. No credentials are read from the environment.

All HTTP destinations, including metadata and redirects, cross the same SSRF boundary. DNS
answers are checked immediately before connection and handed to the connector as numeric IPs.
TLS SNI and HTTP Host still use the intended hostname. There is no second hostname lookup between
validation and connection, DNS cache, connection reuse, cookie jar, or environment proxy.
Private, loopback, localhost, link-local, multicast, shared, reserved, documentation, and selected
IPv6 transition targets are refused. There is no public CLI override for private targets.
DNS uses the machine's configured resolver, with search suffix expansion disabled; `/etc/hosts`
overrides are not used. DNS traffic itself goes to that trusted local resolver.

Defaults: 10 seconds per request (configurable up to 30), 5 seconds per DNS resolution,
60 seconds per scan, 32 HTTP requests, five redirects per request, 1 MiB per body/SSE exchange,
128 HTTP headers with bounded fields, 48 JSON nesting levels, 30,000 JSON nodes per response,
64 KiB/4,000 nodes per schema, 500 tools, and 10 list pages. Duplicate JSON keys and non-finite
numbers are rejected. Compressed bodies are not decoded. Limits are scanner policy, not invented
MCP/client requirements. They can produce WARN for an otherwise valid large or slow server.

A local scanner cannot prove reachability from OpenAI or Anthropic IP ranges, inspect account
policies, detect every WAF rule, audit tool behavior, or compensate for a compromised local
network, resolver configuration, CA store, or routing table. See [SECURITY.md](SECURITY.md).

## Development

```sh
python -m pip install -e '.[dev]'
python -m pytest
ruff check .
ruff format --check .
python -m build
```

Tests use scripted responses and local HTTP/TLS fixtures, including real certificate validation.
They need permission to bind loopback sockets, but no internet access. Only test fixtures replace
the resolver to route public-looking test names to loopback. Production policy stays enabled.

## Deliberately outside v0.1

No cloud-side probes, OAuth login/token exchange/DCR writes, tool execution, full conformance
suite, deprecated 2024 HTTP+SSE transport, stdio, SSE resumption, MRTR interaction, resources or
prompts inspection, schema reference fetching, certificate revocation audit, dashboard, hosted
server, users, database, payments, or telemetry.

One next step for v0.2: an opt-in interactive OAuth authorization-code + PKCE flow, with
origin-bound token handling, to verify protected `initialize` and `tools/list` after user consent.
