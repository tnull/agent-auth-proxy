# Agent authentication proxy

A password manager and policy-controlled network gateway for agents, written
in Rust. The proxy holds credentials outside the agent, performs authorized
requests on its behalf, and exports redacted communication streams.

The Linux proof of concept is ready for **synthetic experiments**, not production
credentials. It runs as a standalone daemon; its components are also reusable
by a trusted Rust host. macOS Keychain support is planned but not implemented.

## Try the demo

From the checkout on Linux:

```sh
./scripts/demo.sh          # Verify the flow, then stay running for experiments
./scripts/demo.sh smoke    # Alternatively: verify once and exit
```

Requires Rust 1.95.0 (the pinned toolchain), Bash, a C compiler, `pkg-config`,
and OpenSSL development libraries. If your installed 1.95.0 toolchain is named
`stable`, prefix the command with `RUSTUP_TOOLCHAIN=stable`.

The launcher provisions a persistent encrypted demo vault, starts the actual
daemon and local HTTPS fixture, and exercises provider-key injection and a
complete fake-password/cookie login through a real stdio MCP bridge. No API
keys, paid providers, or model subscription are needed. The provider fixture
returns fixed text; it is not an LLM.

While running, it streams redacted observation JSON on stdout and writes MCP
client settings and an agent prompt under `$HOME/.aap-demo/`. In a second
terminal, `./scripts/demo.sh check` repeats the walkthrough. Ctrl-C stops the
demo without deleting its state. Build artifacts stay under `/tmp`.

The demo **does not sandbox your agent**, and stores its convenience unlock key
beside its synthetic vault. Do not put real credentials there. See the
[demo guide](docs/demo.md) for setup, client connection, restart, and limits.

## Architecture

```text
 Agent + tools (sandbox enforced separately)
     |
     | aap-client / stdio MCP bridge / CONNECT / enrolled TCP
     | session-bound Unix socket
     v
 +--------------------- Trusted proxy host ---------------------+
 | aap-daemon: ingress and host lifecycle                       |
 |     |                                                        |
 |     v                                                        |
 | aap-engine: sessions, policy, approvals, operation state     |
 |     |                                                        |
 |     +--> SecretStore interface --> SQLCipher                 |
 |     +--> aap-auth: header/form injection, private cookies    |
 |     +--> redacted observations ------------------------------+--> Collector / IDS
 |     +--> admitted transport ---------------------------------+--> Upstream
 +--------------------------------------------------------------+
       ^ Separate operator sockets: grants, revoke, reload
```

Upstreams are enrolled providers, websites, remote MCP servers, or TCP services.
Credential-bearing traffic uses independently verified HTTPS. Optional CONNECT
inspection terminates the client's TLS with a scoped CA, then establishes
separate verified upstream TLS. Raw TCP is an explicitly enrolled,
credential-free relay, not a fallback around HTTP inspection.

The engine authorizes the session, destination, action, and limits before
credential use. For website login, the agent receives context-bound fake
username/password values; the proxy replaces only the profiled fields at the
outbound boundary. It captures cookies and CSRF state privately, sanitizes
responses, and rechecks authority as work progresses. Provider requests receive
their authentication headers inside the proxy instead.

See the [password-injection walkthrough](docs/mcp.md#password-injection-example)
for the actual marker format and an example request before and after injection.

Operator, agent, and observer authority are separate. An agent cannot choose
another session, read the underlying store, or change its grants. Observation
consumers receive transformed views, not raw secret-bearing traffic. The async
approval interface is separate from store unlock; approval-required work is
denied when no trusted approval provider is configured.

## What works today

| Capability | Implemented scope |
| --- | --- |
| Credential custody | Pluggable `SecretStore` interface; SQLCipher backend with versions, lock/unlock, encrypted backup and key-rotation primitives |
| Provider brokerage | Narrow text-only OpenAI-style chat and Anthropic-style messages profiles, final key injection, bounded response streaming |
| Password manager | MCP item discovery, fake credentials, profiled form/JSON login, private cookies/CSRF, status and logout |
| TLS inspection | Optional session-bound HTTP/1.1 CONNECT; scoped downstream CA and independent upstream verification |
| Remote MCP | Pinned HTTP JSON/SSE profile, enrolled tools, private upstream contexts, cancellation and bounded cleanup |
| TCP | Enrolled bounded duplex relay, explicit half-close, status/cancel, credential-free Rust client |
| Observation | Redacted content/lifecycle records, scoped collectors, acknowledgments, gaps/resume, required or best-effort recording |
| Reuse | Independent Rust client, embedded broker, and custom store/approval/observation examples |

The small launcher demonstrates provider JSON and form login. The other paths
have dedicated library/process fixtures, including six opt-in Linux confinement
tests; they are not all enabled by the demo. See the
[current status and evidence](docs/proof-of-concept.md#current-status).

## Rust workspace

The root workspace has 16 crates. The daemon composes these libraries rather
than maintaining a separate authentication implementation.

| Crate(s) | Responsibility |
| --- | --- |
| [`aap-types`](crates/aap-types/README.md) | Credential-free DTOs, stream contracts, and `AgentService` |
| [`aap-policy`](crates/aap-policy/README.md) | Catalog, resource/route/address rules, restrictive approval policy |
| [`aap-config`](crates/aap-config/README.md) | Owner-private files, strict JSON loading, atomic updates |
| [`aap-secrets`](crates/aap-secrets/README.md), [`aap-store-sqlite`](crates/aap-store-sqlite/README.md) | Backend-neutral custody interface and concrete encrypted store |
| [`aap-auth`](crates/aap-auth/README.md), [`aap-providers`](crates/aap-providers/README.md) | Credential transforms, cookies, redaction, and narrow provider request inspection |
| [`aap-engine`](crates/aap-engine/README.md) | Broker/session authority, request lifecycle, approvals, and shared operation pipeline |
| [`aap-transport`](crates/aap-transport/README.md) | DNS candidates, admitted dialing, TLS/HTTPS, and TCP I/O |
| [`aap-observe`](crates/aap-observe/README.md) | Bounded recording and scoped observation subscriptions |
| [`aap-http`](crates/aap-http/README.md) | Session HTTP API, CONNECT inspection, and TCP framing |
| [`aap-mcp`](crates/aap-mcp/README.md), [`aap-client`](crates/aap-client/README.md) | Credential-free local MCP tools and daemon client |
| [`aap-mcp-upstream`](crates/aap-mcp-upstream/README.md) | Trusted remote MCP validation and private session state |
| [`aap-daemon`](crates/aap-daemon/README.md) | Linux executable, configuration, control plane, and host lifecycle |
| [`aap-test-support`](crates/aap-test-support/README.md) | Development-only synthetic TLS fixtures |

Dependencies are scoped by responsibility. The agent-facing client and MCP
libraries do not depend on the engine or secret store. There is no Keychain
crate yet, no UniFFI dependency, and no `secrecy`/ORM/plugin framework.

## Integration with Goose / GDK

Start with the external daemon: a trusted launcher grants a session, and Goose
connects its MCP extension to `agent-auth-proxy mcp-bridge SESSION_SOCKET`.
That gives tools access to the password-manager and authenticated-request API.
It does **not** automatically route Goose's own model requests through the proxy.
A separate provider/transport adapter would use `aap-client`, translate the
supported provider messages/streams, and preserve cancellation and no-retry
semantics. Full agent tool-call schemas need additional profile support.

Alternatively, a trusted GDK host can compose `aap-engine` with selected store,
transport, and approval components in its own runtime. The embedding process
joins the credential trust boundary: do not put it inside the untrusted agent.
Only a session-scoped `AgentService` belongs on the agent-facing side.

Neither Goose nor GDK has been modified. The [reuse guide](docs/reuse.md)
describes the tested building blocks and proposed integration seams.

## Limits and follow-up work

- This is not a sandbox launcher. Mandatory interception requires separately
  enforced filesystem/network/process isolation; a proxy setting is not enough.
- Compatibility is demonstrated with controlled local services, not arbitrary
  websites or live model providers. HTTP/2/3, WebSockets, generic browser/SSO
  login, and OAuth discovery/refresh are not implemented.
- Keychain, production credential enrollment/recovery workflows, and signed
  human-approval UI/push integrations remain follow-ups.
- Whole-host shutdown/drain accounting, cross-generation limits, and the full
  adversarial/reuse matrix remain incomplete. Revocation cannot undo remote
  effects; operation deduplication is not upstream business idempotency.
- Observation is bounded local memory, not durable capture. Redacted prompts
  can still contain private data; arbitrary secret laundering by a malicious
  authorized upstream is not preventable by a universal filter.

## Development and documentation

Use the pinned toolchain and a fresh build directory outside the checkout:

```sh
build_target=$(mktemp -d /tmp/cargo-target-agent-auth-proxy-main.XXXXXX)
export CARGO_TARGET_DIR="$build_target"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Private-file fixtures normally use root-owned sticky `/tmp`. If that ancestry
is unsafe, set `AAP_TEST_ROOT` to a trusted existing parent for their temporary
directories; build artifacts still stay under `/tmp`. Do not loosen permissions
to make tests pass. Root tests exclude the opt-in confinement suite and the
separate consumer workspaces; their guides contain the additional commands.

- [Hands-on demo](docs/demo.md) and [daemon/operator configuration](docs/daemon.md)
- [Local HTTP API](docs/local-http.md), [MCP](docs/mcp.md), [CONNECT](docs/connect.md), and [TCP](docs/tcp.md)
- [Observation](docs/observation.md), [confinement evidence](docs/confinement.md), and [reuse](docs/reuse.md)
- [Current status and historical evidence](docs/proof-of-concept.md) and [design/remaining requirements](plan/README.md)

Packages remain unpublished with `publish = false`; a distribution license has
not been selected. No system-wide service, CA, or neighboring-project changes
are installed by the demo.
