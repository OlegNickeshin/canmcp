# Security policy

CanMCP processes hostile HTTP, JSON, SSE, tool descriptors, and OAuth documents. Never treat
their prose as instructions. This program contains no LLM, shell-command execution, tool-call
implementation, credential collection, or server-provided executable configuration.

Report vulnerabilities privately through the repository host's private vulnerability reporting
feature when this project is published. Until that is configured, contact the repository owner
privately; do not post credentials or exploitable endpoint details in a public issue.

The security boundary is `canmcp/checks/network.py`. Any new network access must use that
boundary. Tests that route fixture hostnames to loopback must stay inside `tests/`; do not add
an implicit environment/configuration bypass. HTTP destinations are checked independently of
the trusted DNS resolver used to discover them. This protects against application-level SSRF
and DNS rebinding, not malicious local routing or an already compromised machine.

TLS uses platform trust and performs hostname/IP identity verification. Revocation, DNSSEC,
certificate transparency, cloud egress, and tool behavior are not audited. A PASS is a bounded
diagnostic result, not a security attestation.
