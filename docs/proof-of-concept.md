# Proof-of-concept delivery and evidence

This tracks implementation of [the plan](../plan/implementation.md), not a
replacement specification. Unchecked items are not implemented or verified.
The end-to-end proof must use real transports and the encrypted store, not
only mocked component tests. Tests use synthetic credentials and local origins.

## Completion checklist

- [ ] W0: Git-managed workspace, documented crates, toolchain, CI and dependency checks.
- [ ] W1: Strict contracts, session binding, policy, expiry/revocation and operation deduplication.
- [ ] W2: Pluggable store and actual SQLCipher encryption, versions, lock, wrong-key rejection, backup/rekey and restart checks.
- [ ] W3: Two provider profiles, verified TLS, final key injection, bounded response streaming and safe observation.
- [ ] W4: Standalone daemon, distinct session/control sockets, client, quotas, cancellation, configuration validation/reload and shutdown.
- [ ] W5: MCP discovery, fake credentials, status/logout and constrained HTTP tools.
- [ ] W6: Intercepted TLS, form/JSON substitution, private cookies, CSRF, response sanitization and a complete authenticated website flow.
- [ ] W7: Observation export with gaps/resume/required mode; MCP mediation and constrained TCP relay.
- [ ] W8: Trusted embedding and external client examples, operator instructions, real confinement checks and complete local verification.
- [ ] W9: Direct macOS Keychain adapter and existing-item enrollment; identify macOS-only validation.

HTTP/2, WebSocket, cross-origin federation, additional site adapters, OAuth
interactive enrollment and human approval are declared individually rather than
silently passed through. Unsupported traffic must fail explicitly. The first
supported form login, provider path, MCP and TCP coverage are required; replacing
them with a generic request example does not complete this proof.

## Implementation choices

- Start with the installed Rust 1.95 toolchain; declare Rust 1.88 compatibility
  and verify it before completion.
- Keep dependencies scoped; no `secrecy`, ORM, or general plugin system.
- Use `security-framework` directly for Keychain. Narrow low-level bindings may
  supplement it; a Swift bridge is not necessary.
- Do not modify Goose or Loupe. Their integration seams remain research inputs.
- Native macOS runtime checks may remain explicitly unverified on this Linux host.
- Leave product/license/production enrollment questions for the final handoff.
- Catalog metadata lives in private versioned JSON, separate from credentials:
  user-owned `0700` directories and `0600` files, safe descriptor-based opening,
  private atomic writes, and rejection of unsafe modes, links, and ownership.
- Preserve asynchronous operation approval separately from store unlock.
  Global/session, item, and action requirements combine restrictively. Signing
  and UI are later adapters; approval-required requests fail closed without one.

## Evidence log

W0 foundation: the three initial contract crates build and their empty test
suites run under Rust 1.95.0. Crates are added as their implementation begins.
CI describes format/check/test/lint/doc and MSRV gates; remote CI has not run.
No behavioral or security claim is verified by the scaffold.

This host's Rustup installation is read-only. Local commands use
`RUSTUP_TOOLCHAIN=stable`, whose installed compiler is exactly the pinned
1.95.0 version. This is a local invocation override, not a changed toolchain
requirement or an unverified claim that another compiler passed.

Core test-first checks: ID canonicalization, duplicate JSON members at every
depth, and special-purpose destination rejection failed against their initial
implementations before being implemented. Random-ID and authority-field rejection
tests likewise failed first. All five checks now pass on Rust 1.95.0, alongside
workspace check and Clippy. The async service and credential-free DTOs are
defined; the engine that enforces their complete contract is still pending.

Planning continuation, 2026-09-22: added proposed
[catalog](../plan/catalog.md), [approval](../plan/approval.md), and
[first-proof scope](../plan/proof-of-concept.md) contracts. The catalog now
specifies a paired `configuration_revision`; draft Rust types still need to
implement that contract. These documents do not complete an implementation
milestone.

Read-only verification of the existing work in progress: workspace compilation
passes under Rust 1.95.0. The five completed core tests pass; five additional
policy tests fail against unfinished catalog/target/approval stubs. Formatting
checks also report those draft Rust files. No Rust source was changed during
this planning continuation, and no commit was made with these checks failing.
The catalog JSON example parses, relative document links resolve, and the
planning diff has no whitespace errors.

Policy implementation: the unfinished catalog/target/approval stubs are now
implemented. The typed catalog carries the configuration revision, validates
store/profile/item bindings, and rejects mismatched revisions. Exact route,
header, complete-DNS-result, form-profile, and restrictive approval checks were
verified red against their initial implementations and then green. All 15
current unit tests pass, as do workspace format/check/Clippy. Session binding,
the configuration-file loader, approval execution, and store access remain
separate pending implementation work; W1 is not complete yet.

Store contract: object-safe asynchronous read/use and separate administrative
interfaces now exist, with bounded non-printable secret bytes, coherent field
snapshots, opaque item revisions, and store-access generations. Three new
behavior tests were verified failing before implementation and now pass;
a compile-fail doctest checks that secret debug formatting is unavailable.
Workspace format/check/test/Clippy pass (18 unit tests and one doctest).
No real backend behavior is established by these contract tests.

Private filesystem boundary: `aap-config` implements Linux descriptor-based
private reads/creation/replacement, ownership/mode/type/link checks, bounded
JSON, safe ancestor traversal, and conservative POSIX ACL rejection. Six tests
exercise private replacement, unsafe permissions/paths/links, size limits,
descriptor anchoring, duplicate JSON, and a real extended ACL with mode 0600.
The initial filesystem tests failed on their stubs; the ACL test also fails
when the production ACL check is removed and passes with it restored.

This host has a non-sticky group-writable `/tmp`, which is correctly rejected
as a configuration ancestor. Filesystem tests use
`AAP_TEST_ROOT=/home/tnull/workspace` for fresh automatically removed fixtures;
Cargo build output remains under the task's `/tmp/cargo-target-*` directory.
The user namespace maps only UID 1000, so the real ACL fixture names that
mapped UID rather than attempting to create an invalid unmapped-user ACL.
Other-platform ACL handling remains explicitly unsupported, not assumed safe.

Actual encrypted backend: `aap-store-sqlite` now uses bundled SQLCipher with
system OpenSSL and a caller-supplied runtime handle. Ten backend tests cover
keyed creation/read/write, coherent versioned transactions and forced rollback,
encrypted database/WAL/backup files, wrong/missing/invalid keys, plaintext
refusal, lock/unlock/deletion/restart, separate-key backup, and database-key
rotation with an encrypted recovery copy. File replacement or unsafe access
closes the live handle. Unsupported schemas are rejected without altering the
database. Native work has bounded admission and no plaintext/test-store fallback.

The initial backend, backup, rotation, schema-refusal, and changed-file tests
were observed failing before their implementations/corrections and now pass.
The forced-write-failure test was also demonstrated to fail with the write
transaction removed and pass after restoring it. Native wrong-key tests emit
fixed SQLCipher decryption diagnostics; no native diagnostic enters store errors.

Current verification: all 34 unit tests and the secret-formatting compile-fail
doctest pass on Rust 1.95.0 and Rust 1.88.0. Workspace compilation passes on
both; formatting, Clippy, and public documentation builds pass on 1.95.0.
Rust 1.88.0 was installed into an isolated task directory under `/tmp`, leaving
the host's read-only Rustup installation unchanged. Normal dependency inspection
confirms SQLCipher is confined to its backend and no ORM, dedicated secret
wrapper, or default Wasm/cache adapter was added.

W2 remains incomplete pending process-interruption/recovery fault coverage,
the schema-upgrade maintenance path, shared backend conformance, and remaining
native-work race/limit checks. The engine, real transport, daemon, password
substitution/cookie handling, MCP, observability, and confinement demonstrations
are still to be implemented; these component tests do not establish the full
proof of concept.

Verified upstream transport: `aap-transport` now separates DNS candidate
enumeration from admitted-address dialing and performs real HTTP/1.1 over
certificate/name-verified TLS. It has bounded streaming, deadlines, cancellation,
connection-driver cleanup, explicit uncertain-delivery errors, and no automatic
redirects, retries, or TLS early data. `aap-test-support` supplies only synthetic
local TLS origins as a development dependency; it is not a production fallback.
Nine transport tests cover these boundaries. Initial endpoint/execution tests
failed against stubs; additional malformed-port rejection failed before its
correction. Workspace format/check/test/Clippy pass on Rust 1.95.0; all 43 unit
tests and the compile-fail doctest also pass on Rust 1.88.0.

These are private low-level upstream responses, not yet an agent-safe broker.
Final credential injection, response sanitization, interception/CONNECT, and
the daemon remain separate uncompleted work. No W3 completion is claimed by
transport tests alone.

## First provider library integration

`aap-engine` now implements a privileged broker and session-bound API-key
operations using the real SQLCipher backend and verified TLS transport.
`aap-providers` supplies a strict text-only request inspector;
`aap-auth` supplies private key preparation and incremental response sanitization;
`aap-observe` supplies bounded local recording with acknowledgment/resume gaps.
No new external dependencies were added for these four crates.

Nine engine tests demonstrate both provider request profiles, private final
headers, split-key echo suppression, cookie stripping, safe observed content,
session-separated request status, duplicate/conflicting operation IDs, missing
approval, asynchronous approval/revocation, rotation during approval, pending
payload limits, oversized-chunk-safe outbound redaction, required recording
failure, ambiguous disconnects, abandoned responses, and cancellation at EOF.
Store resolution is counted: it stays at zero during pending approval and when
required recording is already unavailable. These are synthetic local fixtures,
not live-provider or complete daemon conformance tests.

Initial broker/auth/provider/recording tests failed against their stubs before
implementation. Additional tests caught, before correction, malformed provider
version overrides, large-body redaction rejection, missing pending-byte limits,
new-cookie body echoes, eviction of required records by best-effort traffic,
secret resolution while required recording was offline, and a cancellation/EOF
completion race. No assertion was weakened to obtain a pass.

All 61 unit tests and the secret-formatting compile-fail doctest pass on Rust
1.95.0 and 1.88.0. Workspace formatting, compilation, and Clippy pass on 1.95.0.
The complete W1/W3/W7 gates remain unchecked: native daemon/client ingress,
configuration lifecycle, exhaustive quota/race checks, complete observation
views/export, and the website/MCP/TCP/confinement paths are still pending.
Known-value suppression remains defense in depth against ordinary echoes; it
does not defeat covert encoding by an intentionally malicious upstream.

## Private local session transport

`aap-config` now exclusively binds owner-only Linux sockets, pins their inodes,
revalidates permissions/type/owner/ACL, and cleans up only its own unchanged
entry. Two tests cover real socket connection, exclusion of existing entries,
permission loss, and preservation of a replacement during cleanup. The initial
tests failed against the socket stubs. The native Rustix backend does not support
no-follow chmodat; permission changes instead use the pinned kernel descriptor
path, not a mutable caller pathname or a process-global umask.

`aap-http` and `aap-client` implement the [versioned local binding](local-http.md).
Three real-socket tests cover independent bound sessions, typed error/status
round trips, malformed/duplicate JSON, forged authority fields, rejection of
operator/absolute targets, and shutdown while an execution is pending. The
initial client/server test failed before implementation. Client normal dependency
inspection shows no engine, secret-store, authentication, SQLCipher, TLS, or
test-support packages. This is adapter evidence, not yet a standalone daemon
or sandbox demonstration. The workspace has 66 unit tests plus the compile-fail
doctest; build, tests, formatting, and Clippy pass on Rust 1.95.0. The same
66 unit tests and doctest also pass on Rust 1.88.0.

## Standalone provider daemon

`aap-daemon` now composes the existing libraries into the actual Linux binary.
Five process tests use a fresh SQLCipher vault, private sockets, real local TLS,
an independent client, and a separately attached observation reader. They cover
private key injection and sanitized output, authority separation, revocation,
invalid/valid configuration reload, unsafe-file/key/startup refusal, exclusive
runtime ownership, graceful shutdown, abrupt death/restart, and session expiry.
Restart keeps encrypted credentials but invalidates old session attachments and
operation lookup. The initial process tests failed against the daemon stub.

Observation export additionally bounds encoded page bytes before cloning
records. A new test failed against that API's stub, then passed with JSON
escaping, cursor continuation, count limits, and oversized-record refusal.
The operator contract, current configuration fields, reload/restart behavior,
and explicit limitations are documented in [daemon.md](daemon.md).

Workspace compilation, formatting, Clippy, and documentation builds pass on
Rust 1.95.0. All 67 unit tests, five process tests, and the compile-fail doctest
pass on both Rust 1.95.0 and the Rust 1.88.0 MSRV. The only newly introduced
external package is Tokio's `signal-hook-registry` dependency for daemon-owned
termination signals; no credential custody was added to the agent client.

W4 remains unchecked: this proves the explicit local operation API, not
provider-compatible proxy mounts, CONNECT, full admission/overload conformance,
or actual sandbox egress denial. W5/W6 website credentials, MCP, private cookie
sessions, remaining W7 transports/observation, reuse examples, and macOS native
custody are still pending. Required observation currently accepts into bounded
local memory only; it is not a durable collector-delivery guarantee.

## Website authentication primitives

`aap-auth::login` now supports independently random fake username/password
values, strict bounded form/JSON validation before secret substitution, exact
field/pointer replacement, and JSON-page CSRF virtualization. Eight additional
tests across login and cookies initially failed against stubs and now pass.
They exercise valid reusable placeholders, special-character serialization,
duplicate/misplaced/foreign placeholders, malformed percent/UTF-8/JSON input,
CSRF rotation, and exact response-token replacement. Visible-username disclosure
remains unsupported until its approval path is integrated.

`aap-auth::cookies` provides a private exact-origin jar for the conservative
host-only Secure fixture profile. Tests cover independent jars/ports/hosts,
path/default selection, sensitive headers, replacement, Max-Age/Expires,
deletion, malformed/unsupported attributes, prefix rules, batch/count/history
limits, removal of all setting headers, and clearing authority on failed capture.
Replaced/deleted values remain in bounded echo-suppression history rather than
being silently forgotten. The supported subset and upstream references are
documented in the [authentication crate](../crates/aap-auth/README.md).

The normal client dependency graph still excludes policy, authentication,
credential stores, and TLS. These transforms add no new external packages:
form serialization and HTTP-date parsing reuse packages already in the lockfile.
All 75 unit tests, five process tests, and the compile-fail doctest pass on Rust
1.95.0 and 1.88.0; format/check/Clippy/documentation checks pass on 1.95.0.

W5/W6 remain incomplete. These helpers do not authorize requests or provide
session/context lifecycle, attempt quotas, approval, credential-version checks,
application login success, redirect handling, MCP, or CONNECT interception.
The next vertical step must integrate those controls in the engine and prove
the complete fake-login-to-protected-resource exchange over real TLS; passing
transform tests alone does not establish end-to-end credential isolation.

## Engine and daemon website integration

The engine now binds authorized catalog search, metadata-only fake-credential
issuance, private contexts, status/logout, and the controlled website flow to
the existing session API. Trusted session creation accepts an optional item
allowlist, enforced for provider injection as well as website credentials.
Issuance shares execution's ID namespace and tracking budgets. Search cursors,
context counts/lifetimes, cookie exchanges, login attempts, and private redaction
templates have explicit finite bounds documented in the engine README.

Twelve new engine tests prove authorized discovery/pagination, identical versus
conflicting issuance, account/session separation, expiry, context limits,
rotation/lock/logout invalidation, form and JSON login over real TLS, explicit
application success, subsequent private-cookie access, CSRF rotation, attempt
limits across fresh contexts, no password resolution while approval is pending,
late approval after rotation/logout, concurrent context denial, approval/store
checks for cookie actions, and uncertain login without redispatch. Password
resolution is counted. Unknown/unauthorized items cannot release credentials.

The initial vault and website tests failed against unsupported behavior before
implementation. A targeted race test additionally failed when local logout
during revalidation revoked another context for the same item; the correction
limits that broader invalidation to actual store-access/version failure. A new
redactor-template test failed against its stub and passes without transferring
buffered stream content between requests.

A sixth real-process test runs catalog lookup through fake form submission and
protected-resource retrieval via the daemon and independent Rust clients. It
proves per-session placeholder/jar isolation, logout, and a separately attached
observation reader that sees neither actual credentials nor placeholders. The
agent still receives virtual CSRF data needed to complete the form.

All 88 unit tests, six process tests, and the compile-fail doctest pass on Rust
1.95.0 and 1.88.0. Workspace format/check/Clippy/documentation checks pass on
1.95.0. No external dependency was added; Tokio's existing test clock feature
is enabled for deterministic context-expiry coverage.

This establishes the website flow through the **explicit local operation API**,
not the full W5/W6 gates. MCP tools/stdio, CONNECT interception, the separately
enrolled post-login redirect transition, remaining adversarial/race/overload
cases, and complete observation views still need evidence. Website responses
are currently bounded JSON, and redirects/unsupported profiles fail closed.
Remote MCP/TCP, actual sandbox confinement, reusable examples, remaining store
maintenance/recovery, and native macOS custody also remain on the original plan.

## Credential-free MCP tools and stdio bridge

`aap-mcp` now supplies the seven local vault/request tools over `AgentService`
and an owned, bounded stdio loop. The daemon's `mcp-bridge SESSION_SOCKET`
command composes it with the existing client without configuration/store/key
access. MCP `2025-11-25` is pinned independently of the SDK package. Admission
occurs before handler spawning; framing, parsing, retained result reservations,
response collection, output stalls, cancellation, and shutdown have finite
bounds. Status/cancel work remains available while work calls are pending.

Ten adapter tests cover strict schemas and delegation, safe errors, exact binary
bodies, duplicate-operation envelopes versus resource JSON, result limits,
initialization, real stdio frames, duplicate-member/oversized input rejection,
pending work and correlation-ID cancellation, overload/control capacity,
concurrent duplicate RPC IDs, EOF cleanup, and deterministic timeout checks.
Initial tool and wire tests failed against stubs before implementation.

A seventh process test failed before the CLI bridge existed, then passed with
the bridge. It runs two independent bridge processes against actual daemon
sessions and a synthetic SQLCipher vault. Both form and JSON website variants
cover catalog lookup, fake credentials, CSRF, private cookies, protected data,
duplicate requests/status, cross-session denial, logout, and a separately
attached observation consumer. No real credential appears in the tool results
or observation content, and duplicate/denied operations do not add upstream
requests. Successful bridge stderr is empty.

The official `rmcp` 3.4.0 SDK is the only new direct external package. All of
its optional/default features are disabled; the adapter uses its protocol types
without its payload-logging/unbounded handler loop. Cargo adds 34 lockfile
packages, including platform-specific transitive dependencies; the normal MCP
closure contains no engine, store, TLS connector, OAuth client, SDK macro/schema
feature, or private-cookie component. The agent client closure is unchanged.

Notification cancellation drops the matching owned service invocation, not a
guessed application operation. Explicit `request.cancel`/`request.status` are
the authoritative daemon controls. A lost transport does not prove upstream
cancellation or rollback. See [the implemented MCP contract](mcp.md) for exact
limits and the separation from remote MCP and sandbox guarantees.

All 98 unit tests, seven process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. Workspace checks pass on both; formatting, Clippy, and
public documentation builds pass on 1.95.0. The complete proof is still open:
CONNECT/TLS inspection,
the declared redirect transition, remote MCP/TCP, complete observation views,
real confinement and external reuse evidence, remaining store recovery work,
and native macOS custody are not established by this local MCP milestone.

## Session-bound CONNECT and TLS inspection

The session listener now optionally accepts CONNECT and terminates downstream
TLS using an operator-enrolled, store-held CA key. Certificate construction,
HTTP adaptation, and engine destination/account selection remain separate
reusable components. Every inspected request goes through the existing engine;
there is no raw tunnel fallback. Native CA material is excluded from the agent
catalog. Configuration checks public CA constraints without reading its key;
store lease/key consistency is checked on admitted use.

Nine additional unit tests cover strict authority/forwarding DTOs, destination
and DNS admission, unique profile selection and existing operation semantics,
required recording before signing admission, real scoped-trust/SNI/ALPN/IP TLS
handshakes, invalid CA material, and inner/outer HTTP authority/header checks.
Authority, engine, certificate, parser, and required-observation behavior tests
failed before their implementations and then passed. The issuer helper validates
CA constraints and signatures explicitly because rcgen's CA import does not.

Three additional actual-daemon process tests exercise provider-key injection
and sanitized streaming through CONNECT; complete fake-credential form login,
private CSRF/cookies, protected access, implicit-context ambiguity and explicit
selection; and CA-version rotation after an established TLS handshake, private
key mismatch, and independent upstream trust failure. The two initial tunnel
tests failed when the daemon still rejected CONNECT. Rotated or denied traffic
does not add an upstream application request. No global CA/service or personal
credential is used. Limits and unverified surfaces are in [the CONNECT contract](connect.md).

All 107 unit tests, ten process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. Workspace compilation passes on both; formatting,
Clippy, and public documentation builds pass on 1.95.0. No new lockfile package
was required: rcgen and its X.509/time dependencies now also serve the production
TLS-identity path, with default features disabled. Credential-free client/MCP
dependencies remain separate from private custody.

W6 is not yet complete: the separately declared post-login redirect transition
and remaining compatibility/race cases are still open. W7/W8 also still require
remote MCP/TCP, complete observation views and connection lifecycle, external
reuse examples, and real confinement checks. Store-maintenance/recovery and
native macOS custody remain on the original proof-of-concept plan.

## Explicit post-login GET transition

Website profiles can now enroll one exact same-origin query-free GET target
through `post_login_redirect`, paired with `success.status: 303`. Explicit JSON
success evidence and expected private cookies are still required; a redirect
or cookie by itself is not login success. Cookie capture precedes redirect
validation. Only the matching Location is reconstructed, after known-secret
suppression checks. No internal follow-up, credential-body replay, or general
redirect handling is enabled.

Three new unit tests first failed against the pre-feature code, then passed:
profile admission rejects unsafe destinations/statuses, the opt-in sanitizer
preserves only safe 303 metadata, and the engine requires independent approval
for the next GET while refusing 307/308, cross-origin, secret-bearing and
unsuccessful responses. The ordinary response sanitizer still rejects all
redirects. The real-daemon TLS website test now also runs a 303 variant and
asserts exactly one separately submitted, body-free protected GET.

This closes the first proof's declared redirect-transition example, not general
browser/SSO compatibility. Unsupported HTML or empty-body success evidence,
302, query-bearing redirects, cross-origin chains, and automatic following
remain unsupported. Complete observation/coverage/reuse/confinement, remaining
store-maintenance evidence, and macOS custody still need completion.

All 110 unit tests, ten process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. Workspace checks pass on both; formatting, Clippy, and
public documentation pass on 1.95.0. This feature adds no dependencies.

## Correlated logical HTTP observation

HTTP operations now carry random flow identities, four independently ordered
directional views, protocol/inspection/redaction classifications, structured
safe headers, policy decisions, logical flow endings, and sanitized byte totals.
Website views distinguish structural placeholder redaction from private
substitution, cookie capture, and CSRF virtualization. Request selectors are
redacted after parsing, so alternative form/JSON placeholder encodings do not
evade that transformation. Provider streams emit paired agent/upstream records.

The recorder accepts bounded batches atomically. Required-mode capacity failure
cannot retain half a paired chunk or a successful ending for just one view.
Concurrent flow clones serialize sequence assignment with acceptance; failed
recording still consumes identities so losses remain detectable. Abandoned
responses report incomplete views rather than a spurious policy denial.

Flow ordering, atomic acceptance, provider/website views, encoded-placeholder
redaction, and failure-reporting tests were observed failing before their
respective changes, then passing. Header-withholding coverage additionally
checks that unknown names cannot become a metadata leak. The pre-existing
byte-budget test still requires exactly one escaped record per page; its page
budget now accounts for the larger serialized envelope.

See [the actual observation binding](observation.md). Logical flow allocation
is not a TCP/TLS establishment event. Scoped consumers, physical connection
coverage, remote MCP/TCP, cross-protocol placeholders, and the remaining W7/W8
acceptance work remain open. This slice adds no dependencies.

All 120 unit tests, ten process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both; formatting,
warning-free Clippy, and warning-free public documentation pass on 1.95.0.

## Quoted placeholder observation

Recognizable placeholders are now suppressed from observations even when quoted
in a provider prompt/response or another website context. Supported forms are
raw tokens, mixed percent/JSON ASCII escapes, and individual base64 encodings.
This is an observation-only transform: neither the upstream request nor the
agent's permitted response is rewritten by it. No credential store lookup or
cross-context authority is introduced.

The streaming recognizer has at most 305 undecided source bytes. The engine
retains the corresponding agent bytes until their observation is accepted,
so required recording cannot lag behind delivery. EOF flushes the remainder;
cancellation or recording failure cannot report successful completion.

Recognizer and provider/website tests first failed before their corresponding
changes, then passed. Every split boundary is exercised for each supported
representation. Additional coverage checks that a partial response has already
been recorded in both views when delivered and that recording loss stops the
remaining response. Arbitrary encodings/covert channels remain outside this
bounded recognizer. The outstanding transport, consumer isolation, confinement,
reuse, and store-maintenance work is unchanged. No dependencies were added.

All 125 unit tests, ten process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target checks pass on both; formatting, warning-free
Clippy, and warning-free public documentation pass on 1.95.0.
