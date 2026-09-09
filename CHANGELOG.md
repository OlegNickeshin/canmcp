# Changelog

## 0.2.0

- Prepare the first public release with package metadata, project links, and the
  "tools for an agent-native web" series.
- Add opt-in `canmcp check URL --oauth`: browser authorization, S256 PKCE, one-use loopback
  callback, token exchange, and protected MCP discovery/initialization and tool listing.
- Support public native DCR or a pre-registered client pinned to an issuer, with `none`,
  `client_secret_basic`, or `client_secret_post` token authentication.
- Bind tokens to the exact MCP URL and reject redirects for OAuth writes and authenticated
  requests. Keep credentials out of reports; close callbacks on failure and cancellation.
- Preserve passive default behavior and JSON stdout; present the login link on stderr.
- Add end-to-end local TLS OAuth tests, callback validation, and credential-boundary tests.

## 0.1.0

- Initial local MCP protocol, transport, TLS/DNS, schema, OAuth metadata, and sourced
  ChatGPT/Claude compatibility checks with a shared SSRF boundary.
