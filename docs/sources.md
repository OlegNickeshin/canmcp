# Sources and compatibility rules

Reviewed 2026-09-09. Client documentation changes independently of protocol revisions.
Each client-specific finding carries a `source` URL in JSON and the corresponding constant
in `canmcp/compat/`. Rules describe the named connection surface, not every product bearing
the ChatGPT or Claude name.

| Rule ID | Trigger and interpretation | Primary source |
| --- | --- | --- |
| `chatgpt.https` | FAIL for a public HTTP endpoint. The guide specifies a public HTTPS endpoint for this connection mode. Secure MCP Tunnel is a separate mode outside this profile. | [Connect and test: Prepare the endpoint](https://developers.openai.com/plugins/deploy/connect-chatgpt#prepare-the-endpoint) |
| `chatgpt.tool_metadata` | WARN when descriptions or annotations are missing. The preparation guide calls for these fields; tool-selection/approval impact is an inference, not proof of connection rejection. | [Connect and test](https://developers.openai.com/plugins/deploy/connect-chatgpt) |
| `chatgpt.registration` | WARN if discovery offers neither DCR nor CIMD with a token-authentication method supported by ChatGPT (`none` or `private_key_jwt`). A predefined OAuth client can still work. | [Authentication: OAuth metadata and client registration](https://developers.openai.com/plugins/build/auth) |
| `claude.registration` | WARN if neither DCR nor CIMD with `none` is advertised. Claude documents its public-client CIMD requirement; manually supplied pre-registered credentials can still work. | [Authentication: DCR and CIMD details; Custom connectors](https://claude.com/docs/connectors/building/authentication) |
| `claude.tool_hints` | WARN when `readOnlyHint` or `destructiveHint` is missing. Claude's building guide requests them; the scanner does not assert all custom connections are rejected without them. | [MCP: Tool hints](https://claude.com/docs/connectors/building/mcp#tool-hints) |

Generic failures/warnings are propagated as diagnostic evidence, not presented as new
client-specific requirements. PASS means no failure in the implemented checks. It is not an
exhaustive client compatibility claim. Cloud connectivity remains untested, including
[Claude's documented network origin](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp).

No official source reviewed establishes a blanket ban on a public direct-IP HTTPS endpoint.
CanMCP reports direct-IP addressing but adds no invented ChatGPT/Claude warning if TLS verifies.
It also does not require `search`/`fetch` tools for ordinary remote connections, require DCR
universally, guess client protocol version allowlists, or assume all static credentials are
unsupported. An IP certificate must pass the same normal TLS identity verification as any URL.

## MCP protocol references

- [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28)
- [Versioning and era compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [Modern Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [Legacy Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [Legacy lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
- [Tools and schemas](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Authorization discovery](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery)
- [Authorization and S256 PKCE](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 9728 protected resources](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8414 authorization server metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 6750 Bearer challenges](https://www.rfc-editor.org/rfc/rfc6750)

CanMCP deliberately overlaps only the minimum message validation needed to establish useful
diagnostic evidence. The [official conformance repository](https://github.com/modelcontextprotocol/conformance)
remains the implementation test suite. Its revision-scoped requirements and active tool scenarios
are not duplicated or run implicitly. [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector)
is a separate interactive debugging tool and may execute tools when used to do so.

## Interactive OAuth in v0.2

These are generic OAuth/MCP checks, not invented ChatGPT or Claude requirements:

| Behavior | Primary source |
| --- | --- |
| Authorization code, S256 PKCE, resource parameter on both authorization and token requests, Bearer authorization header | [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) |
| Prefer explicitly supplied pre-registration; native DCR as a deprecated fallback; do not require DCR universally | [MCP client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration) |
| Public HTTPS authorization/token endpoints and protection of credentials | [MCP authorization security](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) |
| External browser and loopback IP redirect with a temporary listener | [RFC 8252, sections 7.3 and 8](https://www.rfc-editor.org/rfc/rfc8252) |
| Random verifier and SHA-256 challenge | [RFC 7636, section 4](https://www.rfc-editor.org/rfc/rfc7636) |
| Validate callback issuer, require it when advertised | [RFC 9207, sections 2 and 3](https://www.rfc-editor.org/rfc/rfc9207), [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) |
| Form-encoded code exchange and percent-encoded HTTP Basic client credentials | [RFC 6749, sections 2.3.1 and 4.1](https://www.rfc-editor.org/rfc/rfc6749) |
| Public-client DCR request/response and exact callback confirmation | [RFC 7591, sections 2 and 3](https://www.rfc-editor.org/rfc/rfc7591) |

Exact-URL token binding, refusing credential redirects, issuer pinning for pre-registered clients,
manual link opening, no token persistence, and scanner limits are CanMCP safety policies. They
may prevent inspection of configurations that other clients support. A successful login tests
the CanMCP registration only; the ChatGPT/Claude profiles remain evidence-based heuristics.
