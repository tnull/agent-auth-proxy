# Sources and integration findings

Research date: 2026-09-22. Sources distinguish published specifications,
local evidence, and project proposals.

## Standards assessment

| Source | Contribution / decision |
| --- | --- |
| [OAuth security BCP, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html) | Security reference for token acquisition/refresh |
| [Cookies, RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html) | Base cookie semantics; additional browser behavior needs explicit profiles |
| [HTTP early data, RFC 8470](https://www.rfc-editor.org/rfc/rfc8470.html) | Replay concerns support disabling early data on authenticated paths |
| [MCP authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Separate local authorization and upstream OAuth audience/token handling |
| [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools), [transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), and [cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation), 2025-11-25 | Pinned basis for the proposed [local MCP adapter](mcp.md) and [remote MCP profile](remote-mcp.md); project-specific policy, tools, and limits are specified separately |
| [MCP security practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices) | Confused-deputy and token-passthrough concerns |

Pin protocol revisions for interoperability claims and review upgrades explicitly.
The local context/placeholder contracts and MCP vault schemas are project
proposals; the cited standards do not define them. Resources continue to use
their existing authentication mechanisms.

## Local Loupe baseline

Inspected `../loupe` at commit
`7261a264aaa819ebc4c505b7c6e8f400119f60a4`. Its unrelated untracked user files
were not changed. Findings come from tracked source/history; its tests were
not executed for this planning task.

| Evidence | Relevant behavior |
| --- | --- |
| [`model_proxy.rs`](../../loupe/crates/loupe-worker/src/llm/model_proxy.rs) | Credential-free loopback adapter relays to the job's host broker socket |
| [`model_broker.rs`](../../loupe/crates/loupe-worker/src/llm/model_broker.rs) | Host-owned upstream/credential/model policy, limits, injection, streaming |
| [Broker integration tests](../../loupe/crates/loupe-worker/tests/model_broker.rs) | Sandbox and CLI-to-broker contract scenarios; source evidence only |
| [Loupe README](../../loupe/README.md) | Provider-key isolation and current sandbox egress behavior |
| [`988526c`](https://github.com/project-loupe/loupe/commit/988526c) | Introduces the credential-free broker core |
| [`9590ee6`](https://github.com/project-loupe/loupe/commit/9590ee6) | Isolation gates, bounded connections, upstream redirect rejection |
| [`b2221cc`](https://github.com/project-loupe/loupe/commit/b2221cc) | Rejects `mcp_servers`, which can make the provider contact caller-chosen URLs |

Transfer host-selected authority, per-job ingress binding, absence of secrets
in the sandbox adapter, removal of caller authentication, final credential
insertion, bounded streams, and refusal of credential-bearing redirects.

The `mcp_servers` correction shows that delegated external communication can
appear outside an obvious tool list. This daemon needs semantic policy for all
such features. A denylist of known fields also needs a strategy for newly
introduced provider capabilities; full-coverage profiles should allow only
understood network-capable features.

Scope differences from the inspected Loupe implementation:

- The broker covers a small provider surface, not general TLS interception,
  secret-store-backed password management, or cookie virtualization.
- Its response-header sanitizer removes framing/hop-by-hop fields; it is not
  the private Set-Cookie capture and secret-response filtering required here.
- Its documented default permits public IPv4 egress. Complete interception in
  this plan requires all sandbox egress to use the mediator instead.
- It does not implement this plan's observation export contract.

These are source-based scope differences, not claims of newly demonstrated
vulnerabilities in Loupe's intended deployment.

## Local Goose reuse opportunities

Inspected `../goose` at commit
`bfbbf4463164f5585dcf7c407556fd1acd84d57f`. No files were changed and no Goose
builds or tests were run. These findings identify integration seams, not a
claim that the proposed proxy already works with Goose.

| Evidence | Design consequence |
| --- | --- |
| [Workspace manifest](../../goose/Cargo.toml) | The inspected workspace declares Rust 1.94.1; evaluate compatibility before setting this project's MSRV |
| [Release configuration](../../goose/release-plz.toml) | GDK packages have a deliberate release/API boundary; avoid importing private application code as if it were a stable SDK |
| [Provider contract](../../goose/crates/goose-provider-types/src/base.rs) | Model/messages/tools abstractions already exist; this proxy should not duplicate a conversation or agent SDK |
| [Provider API client](../../goose/crates/goose-providers/src/api_client.rs) | Configurable host/authentication and request customization support endpoint integration, but do not establish a general replaceable transport interface |
| [OpenAI provider](../../goose/crates/goose-providers/src/openai.rs) | Provider builder configuration offers a path to a session-bound local model endpoint without real sandbox credentials |
| [MCP extension configuration](../../goose/crates/goose/src/agents/extension.rs) | Stdio and Streamable HTTP, including a Unix socket option, offer routes to the daemon's MCP surface |
| [MCP runner](../../goose/crates/goose-mcp/src/mcp_server_runner.rs) | Existing use of the Rust MCP SDK supports isolating that SDK in this project's MCP adapter |
| [Application configuration](../../goose/crates/goose/src/config/base.rs) | Native/file secret handling is application-owned; use a public store contract, not a dependency on Goose's internal configuration module |
| [Goose manifest](../../goose/crates/goose/Cargo.toml) | Existing SQLite linkage makes SQLCipher/native dependency compatibility a real embedding check |

Prefer external-daemon integration first: credential-free provider endpoints
and MCP over an admitted per-session socket/bridge. Later, a trusted host can
embed the same broker libraries with its own store and observation sink. Neither
project becomes a workspace/path dependency; verify any concrete integration
against a pinned, supported host API in a separate scoped change.

## Implementation references

The [deployment contract](deployment.md) uses the Linux man-pages descriptions
of [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
and [Unix-domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html), plus
kernel documentation for [Yama process restrictions](https://docs.kernel.org/admin-guide/LSM/Yama.html)
and [no new privileges](https://docs.kernel.org/userspace-api/no_new_privs.html).
These describe OS mechanisms, not a certification of the proposed deployment.
The isolation profile, responsibility split, and acceptance gates are project
requirements that still need tests against the selected launcher and host.

The [workspace design](rust-workspace.md) cites official Cargo, Tokio, Hyper,
Rustls, and MCP SDK documentation for its proposed stack. Exact dependency
versions remain an implementation-time resolution and build check.

The [store design](secret-stores.md) cites SQLCipher and rusqlite for encrypted
SQLite, Apple's Keychain services/item/access-control documentation for native
custody and reuse limitations, and `security-framework` documentation for direct
Rust access. Backend selection is a project decision: Keychain holds the
credential items on macOS, while encrypted SQLite is the non-macOS default.
