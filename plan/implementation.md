# Implementation sequence and delivery plan

This plan implements the password-manager and credential-injection design as
the [Rust workspace](rust-workspace.md). The first product is a freestanding
daemon; reusable library APIs are exercised throughout development. Starter
manifests and initial contracts now exist. This document specifies required
work; [the delivery tracker](../docs/proof-of-concept.md) records evidence, and
[the proposed first proof](proof-of-concept.md) narrows initial coverage and
demonstration limits.

## Initial release boundary

Target a Linux host with externally enforced agent sandboxes first. Provide
session-bound local ingress, provider credential injection, MCP item lookup and
fake credentials, supported form logins, private cookie sessions, and redacted
observation. Start with a small declared set of provider routes and login sites.
Keep the library interfaces portable; isolate Unix sockets and process handling
from policy, credential state, and public operation contracts.

The first Linux release uses encrypted SQLite behind the `SecretStore` interface.
Implement database encryption with SQLCipher rather than custom cryptography.
The macOS release uses Keychain directly for all managed persistent credentials,
including authorized existing items where possible; it must not ship with SQLite
as a substitute for incomplete Keychain support. Rust host implementations
use that same interface. Never ship the fixture
store as an operational fallback.
The backend and unlock-key requirements are detailed in
[secret stores](secret-stores.md).

MCP access to the vault and HTTP forwarding are separate frontends to the same
engine. Private cookies and provider keys remain in the trusted daemon for
both. General protocol relay, further site profiles, and human interaction are
later expansions within the same architecture.

## Work packages

Each package should produce a reviewable change with a clear verification result.
Dependencies express ordering of functional delivery, not a requirement to make
one enormous commit per milestone.

| ID | Work | Crates / artifacts | Completion evidence |
| --- | --- | --- | --- |
| W0 | Establish workspace and contributor workflow | Root Cargo/toolchain/lints, crate manifests/READMEs, minimal public contracts, CI | Clean workspace build; dependency graph is acyclic; production/client dependency closures contain no test stores or unintended heavy adapters |
| W1 | Model identity, catalog, profiles, policy, approval boundary, and request lifecycle | `aap-types`, `aap-policy`, initial `aap-engine` session state and `ApprovalProvider` | Cross-session/account/origin denial; restrictive approval composition and fake-provider lifecycle; duplicate-operation behavior; deterministic expiry/revocation tests |
| W2 | Define store contract and encrypted SQLite backend | `aap-secrets`, `aap-store-sqlite`, store fixture | Correct key required; writes/WAL/backups encrypted; version/lock/rotation and recovery behavior verified |
| W3 | Deliver the first complete provider brokerage path | `aap-transport`, `aap-auth` header injection, `aap-engine`, `aap-providers`, basic `aap-observe` | Local agent request reaches controlled HTTPS provider with daemon-held key; stream returns safely; route substitution, redirect, and delegated-fetch attacks are denied |
| W4 | Expose the standalone daemon and credential-free client | `aap-http`, `aap-client`, `aap-daemon` | Real per-session sockets, separate operator socket, startup/shutdown, quotas, cancellation, and confinement fixture work end to end |
| W5 | Expose the MCP password manager | `aap-auth` item/placeholder handling, `aap-mcp`, daemon/client composition | Agent can search permitted items and obtain context-bound fake credentials; unauthorized store access and cross-session use fail |
| W6 | Complete the first supported website login | TLS interception in `aap-transport`/`aap-http`, form and cookie logic in `aap-auth`, engine integration | MCP discovery through fake form submission to authenticated page retrieval; private cookies, CSRF, safe redirects, logout, rotation, and uncertainty handling all verified |
| W7 | Complete observation delivery and broaden transport support | `aap-observe`, `aap-http`, `aap-mcp-upstream`, `aap-transport`, engine integration | Resume/gaps and required-mode failure behavior; declared remote MCP and TCP profiles pass their acceptance suites; HTTP/2/WebSocket remain separate coverage gates |
| W8 | Prove reuse and prepare an operational release | External consumer fixtures, embedding examples, daemon packaging/docs | Another Rust project uses the libraries without daemon startup or neighboring repositories; shared behavioral suite passes for daemon and embedded use |
| W9 | Deliver macOS credential storage and existing-item reuse | `aap-store-keychain` using `security-framework` | Keychain is the macOS default; new and enrolled existing items work without SQLite copies; access denial, external changes, and lock behavior are verified |

W1 and the store contract in W2 can be developed independently after W0. W3
needs both; W4 makes that path usable as a daemon. W5 and W6 form the first
password-manager release. W7 extends declared coverage and export behavior,
not the initial guarantee that every supported request has safe observation.
Do not advertise a protocol or required-observation mode before its checks pass.
W9 is required for a macOS release, not an optional product enhancement. Its
store/access feasibility work can start after W2; its full daemon checks require
W4 and its authenticated website checks require W6. It need not wait for W8.

## W0: workspace and Git management

Keep one repository and one root lockfile. Add the library/package boundaries
listed in the workspace design as they receive their initial contracts; omit
the native store adapter from workspace members until its milestone. A scaffold
must not claim unimplemented listeners or security guarantees are functional.

Use a root virtual manifest with explicit members and shared metadata, lints,
dependency requirements, and release profiles. Record the MSRV, pinned toolchain,
license decision, and intended public API packages. Use `publish = false` until
the release/license/API decisions are settled; local reuse through pinned Git
revisions does not require publishing packages.

Commit Cargo manifests, `Cargo.lock`, source, documentation, synthetic fixtures,
and CI configuration. Ignore build output, local runtime directories, credential
files, private CA material, and observation captures. Never commit a sample with
a working credential. Test certificate keys are synthetic test fixtures, clearly
marked and unsuitable for use outside the suite.

New branches use the current `YYYY-MM-` prefix. New logical work gets a standalone
descriptive commit; corrections use the positional `f ` convention after their
base commit and existing fixups. Do not rebase merely to position a commit unless
history editing was requested. Draft messages to satisfy the global hook and
include `Co-Authored-By: HAL 9000`.

## W1–W2: reusable contracts and custody

Define operation IDs separately from session authority. The trusted host creates
sessions; HTTP/MCP/client request fields cannot forge one. Resource profiles
hold safe item aliases and store references privately, with explicit origin,
route, account, format, credential-field, CSRF, and cookie constraints.

Separate pure policy decisions from effectful operations. The engine supplies
identity, current policy generation, request facts, and transport-resolved
addresses. Check authority again at dispatch and on private state writeback;
validation of an earlier version does not keep a revoked grant alive.

Implement the [versioned catalog](catalog.md) and restrictive item-policy
composition before credential use. Add the engine's asynchronous
[`ApprovalProvider`](approval.md) seam and bounded pending lifecycle, with a
deterministic test provider. No configured approval path means denial when one
is required. The production UI/signing adapter is deferred, not the enforcement
of approval-required policy. Test cookie-authenticated actions as well as
password reads; store access control alone cannot cover both.

The `SecretStore` contract needs these operations and outcomes:

- Read permitted item metadata separately from resolving secret field values.
- Resolve a coherent credential snapshot with an opaque version and finite
  validity/lease information, where the backend supports a lease.
- Revalidate access/version before release, and report locked, unavailable,
  missing/revoked, or changed state without disclosing native store diagnostics.
- Expose invalidation notifications where supported; otherwise revalidate on
  use and bound any cache lifetime. Do not invent instantaneous revocation for
  backends that cannot provide it.

Where a backend has no revision identifier, its adapter must define a safe
change-detection strategy before use: resolve a coherent snapshot again and
compare inside the trusted boundary. Do not publish content-derived fingerprints
or treat a missing version API as permission to retain secrets indefinitely.
Prove the selected adapter's guarantees against that actual backend.

Keep grants, item aliases, and allowed destinations in validated non-secret
configuration. Passwords, provider keys, refresh tokens, CA keys, and store
unlock credentials come through trusted store/provisioning channels. Agent
environment variables and tool configuration never provide these real values.

The SQLite adapter is the first concrete implementation of these contracts.
Include coherent transactional item updates, opaque versions, encrypted schema
migration/backup, and explicit lock/unlock/key provisioning. Keep the database
key outside the database and normal configuration. Test the native SQLCipher
build so missing encryption support cannot silently become plaintext SQLite.
Do not add an ORM or general storage abstraction beyond the small store interface.

## W3–W4: complete mediation and a thin daemon

Implement verified upstream TLS, explicit destination resolution/admission,
bounded HTTP bodies, streaming responses, and safe header processing before
general proxy support. Introduce one provider profile, then a second to prove
that credentials, route constraints, and API semantics are not hard-coded into
the engine. Provider profiles inspect network-capable tool fields and enforce
selected models/limits where configured.

The daemon's initial commands are `serve`, non-secret configuration validation,
and a credential-free `mcp-bridge`. Operator session creation/revocation and
status use a separate local control socket. Keep their transport schemas and
agent data-plane schemas separately versioned. Do not add a remotely reachable
administration API in the first release.

The control plane creates a distinct Unix-domain ingress socket or equivalent
host-established attachment for each session. Only that socket is made visible
to its sandbox. Bind identity to the listener/attachment, never a caller-selected
session header. Host permissions, namespace/mount restrictions, and descriptor
handling must prevent access to other sessions or the operator socket; Unix
peer credentials alone cannot distinguish all sandboxes running under one UID.

Expose model endpoints, local operation APIs, and MCP routes on the session's
admitted ingress. A loopback HTTP adapter may translate clients unable to use
Unix sockets, but it must run inside the session network boundary and carry no
real credential. Keep proxy destination requests distinct from local API routes
so a crafted Host/path cannot access administration or choose another session.

Configuration contains backend selection/references, provider and site profiles,
listener settings, TLS trust configuration, observation settings, and quotas.
Protect this metadata with user-owned `0700` directories and `0600` files,
descriptor-based ownership/type/mode checks, safe paths, and private atomic
updates. Reject unsafe files at startup and reload; see
[catalog privacy](secret-stores.md#private-catalog-and-policy-metadata).
Validate the entire configuration before accepting traffic. A reload installs a
new validated generation atomically; removed grants/items revoke related work
and contexts. Failed reloads leave the previous valid configuration active and
report a safe operator error.

The catalog and daemon configuration carry a shared `configuration_revision`.
Reject mismatched pairs on startup/reload; replace them as private files and
publish only one validated in-memory generation. Document interrupted-update
recovery explicitly. A failed reload is not successful revocation: report that
the prior generation remains active so the operator can revoke or stop it.

The daemon owns signals, process logging setup, configured store connections,
and listener lifetimes. Libraries own their behavior and expose cancellation
and shutdown handles. Shutdown stops admission, cancels pending operations,
drains only within a configured deadline, emits incomplete stream outcomes,
and invalidates session state. It never reports uncertain upstream work as
rolled back or successful.

## W5–W6: password-manager vertical slice

Implement `vault.search_items`, `vault.get_login`, `vault.auth_status`, and
`vault.logout` exactly as described in [the tool contract](password-manager.md).
The MCP adapter translates data and errors; the engine/authentication libraries
own item matching, placeholder issuance, and cookie state. Add a constrained
`request.execute` internet-access tool and `request.status`/`request.cancel`
tools on that same session interface. Follow the [MCP adapter contract](mcp.md)
for version negotiation, result envelopes, bounded stdio, and approval-safe
concurrency. Prove the credential-free bridge with real process tests before
claiming local MCP support; remote MCP remains a separate W7 gate.

Demonstrate one complete workflow with a controlled site:

1. Search an approved origin and select a permitted account.
2. Obtain fake username/password values and an authentication context.
3. Fetch the login page while the proxy captures pre-login cookies/CSRF state.
4. Submit fake values; the daemon substitutes only the enrolled parsed fields.
5. Capture authentication cookies and return a safe login result.
6. Fetch a protected page, reauthenticate with permitted placeholder reuse,
   then log out and demonstrate immediate local invalidation.

TLS interception uses an explicitly provisioned CA and scoped client trust.
The CA key remains in the trusted process/store. Admit the destination before
issuing/using a leaf certificate, bound certificate caching, and validate the
independent upstream TLS connection. Never install a trust root globally as a
side effect of starting a library or daemon. Select a maintained certificate
construction library at this milestone instead of implementing X.509 logic.

Start with UTF-8 form fields and JSON field selectors. Website profiles explicitly
declare login success, token-bearing responses, cookie handling, and redirects.
Reject flows needing unsupported script execution or opaque password transforms.
Do not broaden to arbitrary sites until the existing profiles' failure behavior
and secret-response filtering have been exercised.

## W7–W8: observation, coverage, and reuse

Basic safe events exist from W3. Complete chunk sequencing, bounded queues,
consumer acknowledgment/resume, gap reporting, and required-observation admission
as specified in [observability](observability.md). Sinks receive redacted data;
a sink cannot request the private authenticated request or store values.
Content inspection has bounded buffering/decompression and cancellation.

Add transports individually. The [first remote MCP contract](remote-mcp.md)
defines W7's pinned Streamable HTTP profile, private upstream sessions, reviewed
tools, cancellation, and bounded JSON/SSE handling. Implement its profile and
pure protocol tests first, then engine integration and an actual daemon/TLS
fixture. Keep trusted remote state in `aap-mcp-upstream`, not the credential-free
local adapter. Store API-key injection alone does not establish MCP mediation.

For TCP, expose only admitted destinations and honest plaintext/opaque
classification. HTTP/2 needs independent stream identity and origin checks;
WebSocket needs explicit frame/operation policy. These later coverage profiles
are not required to claim the narrower [first proof](proof-of-concept.md), and
a successful upgrade is never unlimited authorization.

Provide examples for a trusted host embedding the engine with an existing
store adapter, a host supplying its own `SecretStore`/observation sink, and a
credential-free client using the daemon. Run the same operation/credential
conformance scenarios against in-process and daemon transports. Package an
example external consumer outside the workspace so missing exports, dependency
leaks, and accidental workspace-only assumptions are detectable.

Do not modify Goose merely to prove the libraries compile. Use its documented
integration opportunities as design inputs; add a real Goose integration in a
separate scoped change once the reusable APIs and daemon surface work.

## W9: macOS native credential custody

Implement new item storage and narrow trusted enrollment of existing accessible
Internet/generic-password items through the common store interface. Existing
items stay in place; read/use is the default and unbinding never deletes them.
The agent sees only the enrolled catalog and placeholders. No private SQLite
password mirror, automatic migration, or backend fallback is permitted.

Test the chosen signed daemon/native host against macOS item access controls,
user permission, lock state, and external item edits/deletion. Establish which
Keychain implementations it can access; do not promise universal access to
Passwords/Safari/iCloud items. Native enrollment prompts are distinct from future
per-operation approval/push features. Deny interaction-requiring reads when no
trusted interaction path is available. See [the store contract](secret-stores.md).

Use direct Rust `security-framework` bindings for the daemon. Keep Apple
dependencies inside the platform adapter, out of the portable core and
agent-client dependency closures. A macOS release also needs a separately
verified sandbox/egress boundary; passing store tests alone is insufficient.

## Verification and CI

Favor behavior at trust boundaries over tests that repeat internal structures.
Use synthetic secrets and loopback fixture services; ordinary tests need no live
accounts, paid model calls, or unlocked personal vault. Test actual store adapters
against an isolated backend fixture in a separate integration job.
For the default backend, that means an actual temporary SQLCipher database,
including wrong-key, restart, WAL, migration, and rekey scenarios. Native
Keychain tests run separately on macOS using isolated test items/keychains.

| Boundary | Required checks |
| --- | --- |
| Session/policy | Cross-session/item/account/origin denial, quotas shared across adapters, revocation races, ID conflicts |
| Store | Lock/outage/change, coherent versions, wrong-key rejection, encrypted WAL/backup/recovery, safe errors, no plaintext/test-store fallback |
| Authentication | Exact field substitution, duplicate-field rejection, permitted reuse, expiry/revocation, CSRF and private cookie isolation |
| Transport | DNS rebinding, authority mismatch, redirects, framing ambiguity, invalid upstream TLS, partial send/response, cancellation |
| Provider profiles | Credential replacement, route/model limits, delegated network features, safe streaming and usage accounting |
| Observation | Secrets split across chunks, safe error/redirect content, backpressure, gaps/resume, required-mode failures |
| Daemon | Separate control/agent sockets, restart invalidation, graceful shutdown, private configuration ownership/mode/path checks, atomic reload |
| Embedding | Public API consumer compiles, no daemon/global side effects, shared behavior with daemon mode |
| Confinement | Direct IPv4/IPv6/DNS/alternate-socket egress and access to host/control/other-session resources denied |

Fuzz security-relevant parsers and transformations: origins/authorities, HTTP
framing adapters, form/JSON selectors, cookies, and streaming redaction. Use
property tests where they express meaningful invariants, such as unrelated
form fields retaining their meaning after substitution. A discovered regression
gets a test shown to fail on pre-fix code and pass on the correction.

Run formatting, compilation, tests, Clippy, and documentation checks for the
implemented packages, with workspace checks before committing. CI must check
supported feature combinations and the declared MSRV; do not rely solely on
`--all-features` to establish that minimal library builds work. Add a dependency
advisory/license check before release and review TLS/store dependencies.
Inspect dependency trees for minimal library/client builds and the default daemon.
SQLCipher and Apple frameworks must appear only where selected; do not
add convenience packages without a concrete requirement.

For local Rust builds and tests, use a fresh directory under `/tmp` named for
the repository and branch; do not put build output in the worktree. Example
workflow, run from the workspace root:

```sh
build_branch=$(git branch --show-current | tr '/ ' '--')
build_target=$(mktemp -d "/tmp/cargo-target-agent-auth-proxy-${build_branch}.XXXXXX")
export CARGO_TARGET_DIR="$build_target"
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --workspace --no-deps --locked
```

After editing Rust, run `cargo fmt --all` before the check. Cache reuse across
commands in this one task is fine; unrelated worktrees/tasks get their own
target directories. Actual feature-matrix and backend-fixture commands are
added with those packages. Documentation-only work should validate examples,
links, and consistency; it does not establish runtime security. Before any
commit in this Rust workspace, run the required formatting, compilation, and
test checks and report existing failures rather than claiming an unverified
clean build.

## Remaining implementation choices

- Select the SQLCipher build/linking approach and trusted database-key
  provisioning mechanism; validate native dependency compatibility for embedders.
- Validate direct `security-framework` bindings for the macOS daemon. Record accessible existing-item
  classes, signing/access requirements, and enrollment UX before macOS release.
- Validate the proposed provider/site fixtures and finite limits in
  [the first proof](proof-of-concept.md); choose a real production site's
  profile before claiming supported access.
- Choose a distribution license and verify the declared MSRV/toolchain before
  distributing libraries or a daemon.
- Specify the initial local operation/control HTTP schemas during W4; keep their
  access paths separate and preserve the common operation semantics.
- Agree retention and required-observation policy before collecting real content.

These decisions refine concrete work packages; none requires an upstream service
to implement a new authentication scheme.
