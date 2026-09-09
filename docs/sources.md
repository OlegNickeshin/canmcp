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
