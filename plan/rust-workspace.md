# Rust workspace and reusable crate boundaries

Status: implementation design. A starter workspace exists; this document
specifies the target package graph, not a list of completed crates. Actual
progress is recorded in [the delivery tracker](../docs/proof-of-concept.md).
Authentication behavior remains defined by
[the authentication specification](authentication.md).

## Product and reuse model

Ship one freestanding `agent-auth-proxy` daemon first. Build its behavior in
reusable libraries from the beginning, so a trusted host such as Goose can later
embed the broker or use selected components without launching the daemon.
The daemon must use the same library entry points as an embedding application.

Support three integration levels:

| Consumer | Intended dependency | Trust boundary |
| --- | --- | --- |
| Sandboxed agent/tool or another application using the daemon | `aap-client`, HTTP proxy, or MCP interface | No backing-store access, real credentials, or control-plane authority |
| Trusted host embedding the complete service | `aap-engine` plus selected HTTP/MCP/provider/store adapters | Host process joins the credential trust boundary |
| Trusted application reusing a component | Policy, authentication, observation, or secret-store crates | Component contracts apply; the host assembles and enforces the full boundary |

Embedding the engine inside an untrusted agent process does not preserve
credential isolation. Keep the trusted host separate from sandboxed tools and
untrusted code. Rust visibility and opaque types prevent accidental API misuse;
they are not a security boundary against a malicious embedding host.

## Repository layout

Use the existing Git repository and a virtual Cargo workspace, with each major
part as an independent package. `aap-` is the proposed local package prefix;
registry-name availability is not assumed.

```text
agent-auth-proxy/
  Cargo.toml                  # Virtual workspace; explicit members
  Cargo.lock                  # Committed resolved dependency graph
  rust-toolchain.toml          # Pinned build/format/lint toolchain
  README.md                   # Build, daemon use, and embedding entry points
  plan/                       # Design and implementation sequence
  docs/                       # Operator guide and public integration examples
  crates/
    aap-types/                # Shared non-secret contracts
    aap-policy/               # Grants, destination rules, decisions
    aap-config/               # Trusted private-file access and safe updates
    aap-secrets/              # Secret-store interface and guarded values
    aap-store-sqlite/          # Non-macOS default encrypted SQLite backend
    aap-store-keychain/        # macOS default native credential backend
    aap-auth/                 # Password manager, substitution, cookie sessions
    aap-observe/              # Redacted events and bounded delivery
    aap-transport/            # Network/TLS primitives and upstream execution
    aap-engine/               # Session lifecycle and complete request pipeline
    aap-http/                 # HTTP proxy and local data-plane adapter
    aap-mcp/                  # Vault tools and MCP mediation
    aap-providers/            # Provider-specific request profiles
    aap-client/               # Credential-free daemon client
    aap-daemon/               # Binary composition and host control plane
    aap-test-support/         # Development-only fixtures
  .github/workflows/          # CI for implemented crates and supported features
```

Each crate has its own `Cargo.toml`, README, `src/`, and relevant integration
tests. The daemon uses Keychain directly on macOS and encrypted SQLite on other
platforms. The native backend is a separate package introduced with its
integration milestone and uses direct Rust `security-framework` bindings. Existing
authorized Keychain items can be enrolled without copying their passwords.
Other store adapters can implement the same interface without changing the
engine. See [secret stores](secret-stores.md).

These boundaries separate reusable APIs and distinct dependency/custody needs.
Keep cookie handling, form parsers, and placeholder management as modules within
`aap-auth`; keep individual model-provider profiles as modules within
`aap-providers` initially. Do not create a crate for every module or website.

## Package responsibilities

The proposed exported names below identify API responsibilities, not finalized
Rust signatures. Review concrete signatures during each implementation step.

| Crate | Owns / proposed API | Explicit boundary |
| --- | --- | --- |
| `aap-types` | IDs, resource/profile descriptions, operation/status/error DTOs, request/response stream contracts, `AgentService` interface | No secret values, filesystem discovery, CLI, MCP SDK, or network connections |
| `aap-policy` | `PolicySet`, grant evaluation, origin/route/address rules, safe decision reasons | Evaluates supplied facts; does not resolve DNS, fetch secrets, or send requests |
| `aap-config` | Private directory/file handles, bounded JSON reads, owner/mode/ACL/link checks, atomic file replacement | Trusted filesystem access only; no policy decisions, credential resolution, or process-global path discovery |
| `aap-secrets` | `SecretStore` trait, private store references, version/availability contract, guarded secret values | No agent-facing secret retrieval API; backend dependencies remain outside this crate |
| `aap-store-sqlite` | SQLCipher-backed store, transactional item versions, schema/key lifecycle | Non-macOS daemon default; native database dependency is confined here |
| `aap-store-keychain` | Native credential storage, authorized existing-item enrollment, access/lock semantics | macOS daemon default; no dependency from portable libraries |
| `aap-auth` | `PasswordManager`, context-bound placeholders, login profiles, cookie jars, credential transforms, response secret capture | Depends on store abstractions; does not select arbitrary destinations or open connections |
| `aap-observe` | `ObservationEvent`, sink/subscription interfaces, redacted chunks, sequence/gap tracking, bounded export | Receives safe views; never serializes raw authenticated requests or store responses |
| `aap-transport` | DNS resolution results, admitted endpoint dialing, HTTP streaming, TLS client/server primitives, bounded TCP relay | No credential lookup or implicit redirect/retry; caller supplies admitted routing and request data |
| `aap-engine` | `Broker`, privileged session creation/revocation, session-scoped `AgentService`, `ApprovalProvider`, quotas, operation deduplication, request pipeline | One behavior path for daemon and embedded use; contains no CLI, approval UI, or provider SDK |
| `aap-http` | Forward-proxy/CONNECT ingress, inspected HTTP handling, local operation/status endpoints, stream framing | Converts admitted connections into session-scoped engine operations; no independent auth policy |
| `aap-mcp` | `vault.*` tools, constrained internet-access tool, remote MCP forwarding, stdio bridge | Translates MCP to the same `AgentService`; keeps SDK types out of the engine API |
| `aap-providers` | Approved provider routes, request schemas, model/tool constraints, response/usage interpretation | Supplies profiles to the engine; no credential ownership, provider HTTP client, or conversation abstraction |
| `aap-client` | `DaemonSessionClient`, operation/status/cancel and vault DTOs, credential-free stdio bridge support | Agent-safe dependency closure; no engine, secret store, private cookie, or CA key dependencies |
| `aap-daemon` | `agent-auth-proxy` executable, configuration, socket/listener setup, operator administration, service lifecycle | Thin composition root; no duplicate substitution, policy, cookie, or observation logic |
| `aap-test-support` | Fake store, controlled resolver/clock, test origins, observation collector, synthetic credentials | Development dependencies only; never a production store fallback |

Website profiles describe exact fields, routes, and response handling. Keep
simple profiles as validated data. Use reviewed Rust adapters for behavior that
cannot be expressed safely as data; do not introduce runtime scripts, native
plugins, or a general browser automation engine in the first release.

## Dependency direction

This table lists direct dependencies between production workspace crates;
external Rust dependencies and development-only edges are omitted.

| Crate | Direct workspace dependencies |
| --- | --- |
| `aap-types` | None |
| `aap-policy` | `aap-types` |
| `aap-config` | `aap-types` |
| `aap-secrets` | `aap-types` |
| `aap-auth` | `aap-types`, `aap-secrets` |
| `aap-observe` | `aap-types` |
| `aap-transport` | `aap-types` |
| `aap-engine` | `aap-types`, `aap-policy`, `aap-secrets`, `aap-auth`, `aap-observe`, `aap-transport` |
| `aap-http` | `aap-types`, `aap-transport` |
| `aap-mcp` | `aap-types` |
| `aap-providers` | `aap-types` |
| `aap-client` | `aap-types` |
| `aap-store-sqlite` | `aap-types`, `aap-secrets`, `aap-config` |
| `aap-store-keychain` | `aap-types`, `aap-secrets` |
| `aap-daemon` | `aap-types`, `aap-engine`, `aap-policy`, `aap-config`, `aap-secrets`, `aap-observe`, `aap-transport`, `aap-http`, `aap-mcp`, `aap-providers`, `aap-client`; platform-selected `aap-store-sqlite` or `aap-store-keychain` |

`AgentService` is the narrow agent-facing interface. The engine implements it
on a session handle; the remote client implements it over the daemon connection.
HTTP and MCP adapters accept that interface rather than importing engine internals.
The daemon's credential-free `mcp-bridge` subcommand composes the client and MCP
adapter, while the trusted `serve` subcommand composes the complete broker.
Bridge mode never opens the secret store or loads privileged daemon configuration.

Upstream MCP traffic still passes through engine admission, authentication, and
observation. The MCP SDK must not independently open upstream HTTP connections,
follow redirects, or refresh tokens outside that path. Choose its client/transport
integration accordingly; its local server transport is not an egress exception.

Extension interfaces belong to the lowest crate that defines their contract:
store interface in `aap-secrets`, observation sinks in `aap-observe`, and profile
inspection interfaces in `aap-types`. Dependents supply implementations upward.
No lower crate imports the daemon, Goose, or an HTTP/MCP server framework.

The private-file boundary is shared by daemon configuration and the SQLite
adapter in `aap-config`, rather than duplicating permission/link checks or adding
filesystem dependencies to the backend-neutral store interface. Its scoped
`rustix` dependency provides safe descriptor-relative OS operations. The Linux
implementation is first; native ACL behavior remains a gate on other platforms.

The approval interface belongs in `aap-engine`, which owns immutable operations
and their lifecycle. Pure policy requirements remain in `aap-policy`; native
unlock/access checks remain in `aap-secrets` and its adapters. Inject a trusted
`ApprovalProvider` when composing the broker; never expose approval submission
authority through `AgentService`. No separate crate is needed until a concrete
UI or signed-decision adapter has its own dependency boundary. See
[the asynchronous approval contract](approval.md).

`aap-test-support` depends only on the low-level crates whose interfaces it
implements, plus its fixture networking dependencies. It must not depend on
crates that depend on it for tests; higher-level fixtures belong in the consuming
crate's tests. Verify this graph with Cargo metadata when crates are introduced.

## APIs that preserve the boundary

Separate a privileged `Broker` handle from a session-scoped `AgentService`.
Only the trusted host creates sessions, grants, and resource profiles. The
agent interface cannot create sessions, choose another tenant, enumerate native
store identifiers, retrieve secrets, or change observation requirements.
A displayed `SessionId` cannot be converted into an authenticated handle.

All entry points use the same pipeline:

```text
bound ingress or trusted host session
  -> parse and normalize the request
  -> check profile, grant, limits, and destination
  -> prepare approved authentication and safe observation
  -> recheck current authority and store/context validity
  -> inject and dispatch on the admitted connection
  -> capture private response state and deliver sanitized streams
```

DNS resolution and dialing are distinct transport operations. The engine
evaluates the actual candidate addresses before dialing; the connector uses an
admitted address with the original approved authority/TLS name. Re-resolution,
redirects, and connection reuse cannot introduce a different destination.
The transport never follows redirects automatically or retries a possibly
dispatched request on its own.

Agent request types, private prepared authentication, and sanitized observation
events are distinct. Secret-bearing types must not implement ordinary `Debug`,
`Display`, or serialization; conversion to an agent error is explicit and safe.
Only the authentication/dispatch path handles real credentials. Safe mutation
metadata describes substitutions without hashing or revealing secret values.
Libraries expose typed errors; contextual process diagnostics belong in the daemon.

The engine owns session and operation lifecycles; `aap-auth` owns the private
state of each authentication context. Shared grants/limits apply across HTTP,
MCP, and embedded callers. Serialize login and cookie mutations per context,
but do not hold a global lock across network I/O. Tag in-flight work with context
generation so a late response cannot recreate cookies after logout/revocation.

Use bounded request bodies for form processing and bounded streaming bodies for
normal request/response traffic. Cancellation and shutdown propagate through
all spawned work. Expose explicit end/incomplete outcomes rather than requiring
consumers to infer success from an EOF. Libraries use the caller's Tokio runtime
and return lifecycle handles; they do not install process-global logging,
signal handlers, environment variables, trust roots, or a nested runtime.

## Rust and dependency policy

Keep direct dependencies minimal and review their transitive/native cost.
Use standard-library types for small wrappers, errors, ownership, and futures.
Do not add convenience crates speculatively. Each dependency must support an
implemented requirement that would be materially harder or less reliable with
the existing stack. Reuse dependencies already needed by protocol adapters.

Use Rust 2024 with an explicit Cargo resolver `3`. Centralize common package
metadata, dependency requirements, and lints at the root. Commit `Cargo.lock`
for reproducible daemon development and releases. Workspace dependencies use
local paths; add version requirements when preparing libraries for publishing.
[Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html),
[dependency resolver](https://doc.rust-lang.org/cargo/reference/resolver.html#resolver-versions)

The workspace declares Rust 1.88 compatibility and pins Rust 1.95.0 for
build/format/lint tooling. The initial five crates have passed local checks and
tests on both toolchains; see the delivery tracker for exact coverage. Reverify
the MSRV when adding crates or dependencies. This target also precedes the
inspected Goose minimum (`rust-version = "1.94.1"`); do not silently require a
newer compiler from downstream users.

Proposed implementation stack:

| Concern | Initial choice | Reason / limit |
| --- | --- | --- |
| Asynchronous I/O | Tokio; selected features per crate | Shared runtime with embedders, cancellable network work |
| HTTP messages and streaming | `http`, `bytes`, `http-body`, Hyper and its runtime utilities | Preserve streaming and explicit proxy/connection behavior |
| TLS | Rustls with one explicitly selected crypto provider and Tokio integration | Separate downstream termination and upstream certificate validation |
| MCP | Official `rmcp` SDK, isolated in `aap-mcp` | Reuse protocol handling without making SDK types core public types |
| Non-secret serialization/config | Serde and JSON at adapter/daemon boundaries | Reuse the wire-format parser for initial configuration; no separate config parser |
| Secret handling | Small private-field owned-byte wrapper using `std` | Intentional access, no automatic formatting/serialization, minimal copies; no dedicated wrapper dependency |
| Non-macOS secret store | `rusqlite` with SQLCipher support | Existing database encryption, isolated to `aap-store-sqlite` |
| macOS secret store | `security-framework` bindings or a host-supplied Rust store | Direct credential storage and permitted reuse of existing items; no SQLite mirror |
| Diagnostics | Typed library errors; `tracing` events with explicitly safe fields | Host chooses subscribers and process-level reporting |

These choices are supported by the projects' documentation:
[Tokio](https://docs.rs/tokio/latest/tokio/),
[Hyper](https://docs.rs/hyper/latest/hyper/),
[Rustls](https://docs.rs/rustls/latest/rustls/),
[official Rust MCP SDK](https://github.com/modelcontextprotocol/rust-sdk),
[rusqlite](https://github.com/rusqlite/rusqlite),
[SQLCipher](https://www.zetetic.net/sqlcipher/).
Select exact compatible versions when adding dependencies; this document does
not prescribe a lockfile that has not been resolved and built.

Keep TLS/MCP/store dependencies out of `aap-types` and `aap-policy`. Shared stream
contracts may use lightweight HTTP/bytes/future traits without a concrete socket
or runtime type. Use narrowly scoped features for protocol support, not flags
that disable authorization, certificate verification, redaction, or confinement.
Feature combinations must preserve the same security requirements. Cargo feature
unification must not make a test-only secret store available in a production
daemon. [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html)

No general configuration framework, CLI framework, async-trait macro, ORM,
plugin loader, or secret-wrapper package is assumed. Start small and justify
additions through the code that needs them. Do not replace established TLS,
SQLCipher encryption, or protocol parsers with home-grown security code.

Native database linkage needs an explicit embedding check: consumers may
already link SQLite through another dependency. Keep the SQLCipher adapter
optional for library users and validate compatible native linkage/features
before enabling it in an existing application's dependency graph. A host can
instead supply its own store or use the external daemon.

## Reuse by Goose and other hosts

The current Goose checkout has reusable provider packages, configurable provider
API clients, and MCP transports, including HTTP over a Unix socket. These are
integration opportunities, not completed integrations; see the pinned local
evidence in [references](references.md).

Start with the external daemon. Configure model requests to reach its
session-bound provider endpoint with no real API key in the agent environment.
Configure vault tools as MCP over the session socket or the credential-free
stdio bridge. Local HTTP provider adapters must remain inside the session's
network boundary; loopback alone on a shared host is not session authentication.
Do not assume the provider API client already accepts a replacement transport
just because it supports request customization.

Later, a trusted Goose host can construct `aap-engine::Broker` with its own
`SecretStore` and observation sink, then expose session-scoped operations to
its sandboxed tools. Its provider requests can use the same local HTTP adapter;
a direct provider transport adapter can be added after confirming the host's
public API. Authentication should not require copying Goose's conversation,
model selection, or agent-loop abstractions into this workspace.

Keep Goose-specific glue in Goose or a separate integration crate. The core
workspace must build and test with neither `../goose` nor `../loupe` present.
Their source trees are research inputs, never production path dependencies.
Use pinned Git revisions for early external consumption; later publish only
the deliberate reusable API set. Never depend on a moving development branch
for a security-sensitive integration.

Reusing the libraries does not itself enforce every tool's egress. The embedding
host must supply the same sandbox, process, and socket restrictions required by
the standalone deployment. Demonstrate that property separately from showing
that a provider call or MCP tool works.
