# aap-mcp

Credential-free MCP adapter over a session-bound `aap_types::AgentService`.
The local profile pins MCP 2025-11-25. SDK protocol types stay in this crate;
the adapter has no engine, store, policy, HTTP connector, or cookie dependency.

`Tools` exposes the seven vault/request tools; `serve` accepts caller-owned
asynchronous input/output and uses the caller's Tokio runtime. No process-global
subscriber, signal handler, trust store, or network connector is installed.
The caller must enforce filesystem/network confinement around an untrusted host.

The official `rmcp` 3.4.0 dependency has all optional/default features disabled.
Its protocol types are used inside an owned bounded loop, not its default
server task scheduler or payload logging. MCP types do not enter the core
service interface. The SDK's newer result fields are excluded from this pinned
wire version. See [the implemented contract](../../docs/mcp.md) and
[delivery evidence](../../docs/proof-of-concept.md).
