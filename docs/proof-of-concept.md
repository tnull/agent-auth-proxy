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

## Scoped observation collectors

The recorder now supports sixteen independently enrolled session/view/content
subscriptions. Delivery cursors and acknowledgments are bound to one immutable
scope and only previously issued pages. Filtered-out records do not consume
delivery IDs. Canonical records remain shared under global limits and an 8 MiB
per-session retained-content ceiling; owner and collector acknowledgments
release only their own claims. Required updates are atomic across eligible
queues, while best-effort consumer-local overflow leaves other queues intact.

The real daemon exposes operator-only observation create/revoke endpoints and
separate owner-only sockets per collector. Expiry, session revocation, valid
reload, and shutdown revoke attachments; invalid reload leaves them intact.
Enrollment selects existing live sessions without history or future wildcards.
The privileged owner channel remains separate and must also be drained in
required mode. Source event numbering remains visible to authorized collectors;
this is content/session access control, not a traffic-anonymity guarantee.

Seven library tests cover scope/filtering, independent claims, cursor misuse,
consumer-local loss, finite subscribers/pages, shared accounting and the
per-session ceiling. The new behaviors were observed failing before their
respective changes. A real-process test initially failed at the missing operator
enrollment path and now verifies two sessions, metadata/content grants, cursor
isolation, revocation, expiry, and reload. A second process scenario confirms
required collector overflow sends no upstream request and that explicit
revocation permits newly authorized work afterward.

An additional churn test checks the internal retention-claim and byte-accounting
invariants across repeated recording, loss, acknowledgment, close, and re-enrollment.

This advances W7 without completing its remote MCP/TCP or physical connection
coverage. Confinement, external reuse examples, remaining store-maintenance
evidence, and macOS custody remain outstanding. No dependency was added.

All 133 unit tests, twelve process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both; formatting,
warning-free Clippy, and warning-free public documentation pass on 1.95.0.

## Remote MCP message boundary

`aap-mcp-upstream` now provides a trusted, connector-free protocol component for
the [pinned remote profile](../plan/remote-mcp.md). It compiles finite reviewed
tool/argument contracts, bounds and validates JSON-RPC requests, reconstructs
handshakes without agent capabilities, and requires caller-assigned upstream
request IDs. Request objects are bound to the exact compiled profile instance.

Complete response messages are checked against the expected request ID and
profile. Only enrolled tool definitions and approved text/structured results
survive; arbitrary upstream instructions, error details, metadata, binary
content, resource links, and later SDK extensions cannot pass through. Known
secrets are suppressed structurally after JSON decoding, including escaped
strings, object keys, and numeric values. Redaction collisions, damaged protocol
fields, output amplification, and numeric error-code echoes fail safely. Server
ping is returned as private control work for engine admission, never dispatched
by this component.

The incremental SSE framer handles UTF-8 chunk splits, an initial BOM, line
ending variants, multiline data, priming events, and ignored unknown fields.
Line/event/count/total budgets and poisoned failure state prevent unbounded
retention or resume after errors. Its output remains private raw event data;
the response validator and eventual engine completion checks are still required
before any agent or observation delivery. IDs/retry hints are discarded.

Ten initial tests failed against the fail-closed interface stubs before
implementation. Follow-up tests demonstrated malformed post-redaction replies,
numeric error-code leakage, and incorrect SSE field handling before their
corrections. Additional coverage checks profile-instance isolation, output
amplification, and aggregate SSE input limits. Thirteen component tests now
pass. No new external dependency was added; the crate reuses existing JSON,
authentication, and pinned SDK dependencies. Client/local-MCP custody dependency
boundaries remain unchanged.

This does not complete W7. Private upstream session lifecycle/header handling,
HTTP status/notification integration, operation/approval/cancellation ownership,
aggregate engine quotas, observation, and the actual daemon remote-MCP fixture
remain pending. TCP, full connection coverage, confinement, reusable examples,
store-maintenance evidence, and native macOS custody also remain outstanding.

All 146 unit tests, twelve process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both; formatting,
warning-free Clippy, and warning-free public documentation pass on 1.95.0.

## Private remote MCP context lifecycle

The remote component now owns isolated upstream context identities, private
session headers, finite handshake/lifetime state, non-reused upstream request
IDs, and bounded work/control exchange maps. Complete validated initialization
stages a private header; an opaque matching completion commits it, and a later
accepted initialized notification commits readiness. No tool request can skip
those transitions. Public safe responses contain no native session header.

HTTP response admission checks status, singleton headers, session syntax,
encoding, and cookie/session replacement attempts. JSON and SSE collectors
require one complete matching final response, suppress captured session/key
echoes, and accept only empty notification acknowledgments. Protocol failures
poison the entire context and its outstanding decoders. Uncertain abandoned
ordinary work loses its mapping; an abandoned handshake invalidates its owner.

Cancellation maps only current-context live IDs to the engine's supplied
operation identifiers. Completed, unknown, and initialization MCP cancellation
IDs are ignored. A cancelled response cannot commit. Server pings are one-shot
private child preparations bound to a live parent/decoder, including provisional
initialization session state; the component never sends them. Cleanup first
removes local authority, and expired/failed/closed contexts yield no private
cleanup headers. Dropping the owner invalidates retained decoders.

Seven lifecycle tests were observed failing against initial fail-closed stubs.
Targeted cleanup/fault and owner-drop cases also failed before their corrections.
Ten context tests now pass, including additional duplicate-header, failed
initialization, notification-body, completion-token and ID-exhaustion checks.
Only the existing `http` dependency was added to this crate; no new external
package or credential-free client dependency was introduced.

Engine binding to sessions/resources/accounts, store-version checks, approvals,
shared quotas, cancellation task ownership, required observation, child-response
handling, trailers, and actual admitted HTTPS dispatch remain integration work.
These pure state/decoder tests do not complete remote MCP mediation or W7, and
the other previously listed proof-of-concept gates remain outstanding.

All 156 unit tests, twelve process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both; formatting,
warning-free Clippy, and warning-free public documentation pass on 1.95.0.

## Remote MCP enrollment policy

Private resource configuration now recognizes `Authentication::Mcp`: one exact
query-free POST endpoint, optional same-path DELETE, a catalog-bound credential
item/header, and finite reviewed tool contracts. Enrollment rejects streaming,
oversized limits, unsupported caller headers, transport-header credential
collisions, missing item bindings, and incompatible tool schemas. Private
session/resumption headers cannot be enrolled as caller fields on any route.

The catalog rejects non-MCP routes at the same origin/path and use of an
MCP-enrolled store/key reference through a non-MCP profile. Separate MCP account
bindings remain permitted. This compares private references, not passwords or
their hashes; an operator's deliberate duplicate values in different records
or store aliases cannot be inferred by this check.

The non-secret tool/argument types and validation moved to `aap-types::mcp`,
re-exported by the trusted adapter. Configuration and protocol compilation use
the same schema/size rules without a policy-to-custody dependency cycle or an
MCP SDK in the client dependency closure. No external package was added; the
remote adapter's now-unused direct `serde` dependency was removed.

All five enrollment tests were observed failing before production changes.
They now pass alongside the existing message/context tests. Workspace checks
and 161 unit tests, twelve process tests, and one compile-fail doctest pass on
Rust 1.95.0 and 1.88.0; stable formatting, warning-free Clippy, and warning-free
documentation pass. The engine still rejects MCP dispatch as unsupported:
these configuration checks do not yet establish real remote MCP mediation.

## First remote MCP engine exchanges

The engine now connects the enrolled protocol component to its local-session
identity, item grant, real SQLCipher store, admitted HTTPS connector, asynchronous
approval, response-completion guard, and sanitized HTTP observation. A context
pins the credential lease and owns an independent safe generation ID. Approval
includes that generation, and provider/website/MCP paths share one bounded
approval helper without holding newly resolved secrets during the wait.

Seven engine integration tests use real controlled HTTPS origins. They cover
JSON and chunked SSE initialization/list/call exchanges, empty initialized
acknowledgments, two isolated local sessions, exact tool/header validation before
resolution, key/session echo suppression in agent and observation views, dropped
handshakes, approval/cancel/revoke/rotation, and uncertain-call deduplication.
Credentials are revalidated before delivery and at final completion; tests rotate
them both before the first frame and after delivery has started. Fresh explicit
initialization works without reviving old native context authority.

The first three tests failed at the missing-dispatch boundary before production
code was added. Targeted failed-secret-resolution and rejected-trailer cases
then exposed retained-context bugs in the draft integration; both were observed
failing at their intended assertions before correction and now pass. The other
approval and late-custody cases provide additional conformance evidence.

Remote requests share work slots and have separate bounded control slots and
protocol reservations. Current reservation accounting and the narrower control
response bound are documented in [the engine contract](../crates/aap-engine/README.md#remote-mcp-integration);
this is not yet a proof of all planned allocation/concurrency invariants.

The full W7 gate remains incomplete. Server-initiated ping and DELETE cleanup
still fail explicitly, complete cancellation-child behavior and protocol-level
observation metadata remain to implement, and the actual daemon/CONNECT fixture,
multiple-account isolation, and adversarial capacity tests remain outstanding.
The previously listed TCP, confinement, reuse, maintenance, and native-store
deliverables also remain required; this slice does not narrow the proof's scope.

All 168 unit tests, twelve daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both;
formatting, warning-free Clippy, and warning-free public documentation pass
on 1.95.0. These checks cover the current implementation, not the remaining
remote-control or complete W7 acceptance requirements.

## Admitted remote MCP server ping replies

Server pings in bounded SSE responses now produce one-shot child POSTs through
the existing admitted HTTPS transport. The child has its own bounded operation
record, parent-correlated safe observation flow, control-slot reservation,
destination/custody checks, and two-second deadline. It can carry provisional
initialization session state privately. Its local DTO and content observation
withhold the upstream-selected ID rather than copying potentially secret-bearing
server text. The protocol component validates acknowledgment headers/status;
the engine requires an empty body through EOF and rejects trailers.

The child cannot reuse parent approval. Applicable item/global/session/route
approval causes an observed skip without secret resolution or a human wait.
Dispatched child failures invalidate context authority. Cancellation interrupts
DNS/store admission as well as network I/O; no independent connector or detached
cleanup loop is introduced.

The three initial real-HTTPS tests failed on the missing-child boundary before
implementation and now pass. A targeted cancellation test then demonstrated
that a child stalled in DNS ignored its own cancellation until the attempt
deadline; it failed before adding that cancellation watch and now passes.
Two additional conformance tests cover bounded reserved capacity, destination
denial, required-recorder loss, and credential rotation during child admission.
All six tests use synthetic custody and real parent/child HTTPS exchanges.

This completes the first server-ping dispatch integration, not remote MCP as a
whole. Cancellation notifications/local cancel children, endpoint DELETE,
protocol-level observation, multiple-account and broader capacity evidence,
and actual daemon/CONNECT acceptance remain pending, alongside the other
proof-of-concept gates recorded above.

All 174 unit tests, twelve daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both;
stable formatting, warning-free Clippy, and warning-free documentation pass.

## Local-first remote MCP cancellation

Admitted MCP cancellation notifications and the existing-ID local cancel API
now stop owned local work before store access, human interaction, control-slot
admission, or remote I/O. The protocol component resolves a live mapping and
marks it cancelled without allocating another protocol mapping. Unknown and
completed MCP IDs are ignored. MCP initialization cancellation is ignored;
explicit local operation cancellation invalidates a handshake immediately,
including an outstanding response that has not yet been dropped or consumed.

For dispatched work only, a one-shot cancellation child uses the same admitted
control path as server ping replies. It has independent policy, custody, DNS,
observation, capacity, and acknowledgment checks. Approval-required children
are skipped without another human wait. Failure or refusal cannot undo local
cancellation, claim remote rollback, or replay the work. Child observation
correlates to the cancelled operation and withholds both native identifiers and
the agent-supplied cancellation reason. No detached task retains a password to
finish cleanup after revocation.

Three engine tests were observed failing before implementation: missing child
correlation and store-dependent cancellation of ignored or approval-pending
work. They now pass. Additional conformance covers both cancellation interfaces
under approval, exhausted control slots, a locked store, and remote refusal;
initialization retirement before response drop; and two pure ownership tests
for one-shot mapping, full control capacity, and initialization semantics.
The retained-response test uses smaller explicit response ceilings so both
old and new reservations fit the unchanged aggregate memory budget.

MCP notifications remain subject to ordinary request framing, resource, and
operation-tracking admission. Existing-ID local status/cancel remains the
non-allocating-parent control interface. Full aggregate-buffer/capacity stress,
protocol-specific observation, DELETE, multiple-account evidence, and actual
daemon/CONNECT remote-MCP fixtures remain acceptance work. The broader TCP,
confinement, reuse, maintenance, and native-store gates remain open.

All 181 unit tests, twelve daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both;
stable formatting, warning-free Clippy, and warning-free documentation pass.

## Local-first remote MCP session termination

An admitted empty DELETE now closes the selected local MCP generation before
store access, approval, capacity admission, DNS, or upstream I/O. Outstanding
response delivery loses authority immediately. Native-session cleanup, if any,
is a separately tracked child with current custody, policy, observation, and
reserved-control checks, no additional human wait, and a two-second deadline.
Closed authority cannot be restored by an acknowledgment or late response.

Local HTTP 204 carries only the fixed `x-aap-remote-cleanup` outcome. Empty,
safe upstream 200/204 confirms termination; empty safe 405 reports unsupported;
predispatch denial or absent native authority skips the attempt. Other responses
or postdispatch interruption remain unknown. No upstream body, cookie, native
session, or secret becomes a cleanup result. The credential-free MCP adapter
validates the header's exact value, uniqueness, method, status, and empty bodies
before preserving it; all other private proxy headers remain filtered.

Closure and fresh-generation admission share the same selection lock. A
one-shot cleanup owner excludes reinitialization only while the attempt is
live; completion, timeout, cancellation, and task drop release the barrier.
Repeated DELETE does not dispatch again or release the first owner's barrier.
The closed generation and operation history remain retired.

Three engine cases failed before implementation with unsupported DELETE or
missing cleanup dispatch, and now pass. Two MCP adapter cases failed with a
discarded safe outcome or silently accepted invalid binding, and now pass.
Additional conformance covers timeout, owner drop, child cancellation, repeated
closure, locked/rotated custody, unavailable capacity, approval-required and
stateless contexts, accepted/rejected acknowledgment headers, and no replay.
These tests include real SQLCipher and controlled HTTPS exchanges; the held
transport cases also verify interruption before the fixture receives bytes.

Actual daemon/CONNECT MCP fixtures, broader account/capacity evidence and
protocol-specific observation remain remote-gateway acceptance work. TCP,
confinement, external reuse, maintenance, and native-store gates remain open.

All 188 unit tests, twelve daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both;
stable formatting, warning-free Clippy, and warning-free documentation pass.

## Remote MCP daemon transport acceptance

Four additional real-process tests exercise the pinned remote profile through
the standalone daemon, credential-free client/stdio bridge, and inspected
CONNECT. They use actual SQLCipher entries for two synthetic accounts at one
controlled HTTPS endpoint. Two local sessions on the same account and another
on a different account receive distinct native sessions; closing one does not
revoke another. The fixture verifies both credential-account and native-session
ownership, not merely different caller-visible aliases.

The JSON and bounded SSE variants verify initialization ordering, reviewed tool
listing, exact arguments, denied tool/method/resource inputs before upstream
receipt, private headers, mapped IDs, and suppression of echoed credentials and
native sessions. SSE includes server ping requests whose independently admitted
children remain private. A real stdio bridge carries the same HTTP envelopes
and preserves the fixed DELETE outcome. CONNECT and the local client share one
context, while caller-selected native/version headers and ambiguous account
selection fail without upstream requests.

A delayed remote call is cancelled through the daemon's separate local API.
Delivery stops, exactly one correlated cancellation notification carries the
owned mapped ID, repeated cancellation sends nothing further, and status remains
uncertain. A disconnect after fixture receipt also preserves uncertain status
without replay on duplicate submission. Explicit different actions remain
separately authorized; ordinary response loss does not itself revoke an otherwise
valid context. Explicit DELETE followed by initialization creates fresh authority
without replaying that earlier action. Captured request counters verify this.

An independent observer pages through all fixture records without gaps and
checks both metadata and decoded content for credential/native-ID leakage and
child correlation. This proves the implemented sanitized HTTP views, not the
still-pending parsed MCP-message/context-lifecycle observation contract.
These are integration conformance tests of existing library behavior, not a
claim that earlier commits failed newly discovered regression cases.

All 188 unit tests, sixteen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target workspace checks pass on both;
stable formatting and warning-free Clippy pass. No runtime dependency was added.
Protocol-level observation, aggregate capacity/race acceptance, the TCP relay,
actual confinement, external reuse, maintenance, and native-store gates remain
open. These process tests do not by themselves complete W7 or the proof.

## TCP framing foundation

The credential-free `aap-types::stream` module now implements strict opening
and control DTOs, bounded five-byte frame headers, zero-copy DATA encoding,
incremental payload decoding, and shared directional sequence checks. Header
type/length/state checks precede payload allocation or consumption. Early agent
input is rejected before even collecting a header. Control parsing rejects
duplicate/unknown members and bounds depth, structural tokens, and byte size.

Opening identity, optional one-time pending notification, both half-close
orders, narrowed byte limits, the 65,536-frame ceiling, and terminal counters
are validated. Missing/truncated terminal delivery remains incomplete. An
abnormal outcome after opening cannot claim known non-dispatch, and orderly
completion requires both directional ends and matching admitted byte counts.
The engine must still supply real write counts and enforce authorization,
observation, aggregate reservations, deadlines, and cancellation.

Eight new tests were observed failing against the initial stubs and now pass.
They cover exact binary fixtures, every split across coalesced frames, truncated
inputs, field/limit rejection, both directional endings, and payload left unread
after a rejected header. All 196 unit tests, sixteen daemon process tests, and
the compile-fail doctest pass on Rust 1.95.0. Workspace all-target check and
warning-free Clippy pass; all fourteen `aap-types` tests also pass on Rust 1.88.0.
No dependency was added. These are framing foundations, not an operational TCP
endpoint: policy, dialing, engine relay, HTTP upgrade, client, and actual sandbox
integration remain W7 work.

## TCP enrollment and session grants

`TcpProfile` now validates canonical host/port enrollment, bounded byte/time and
per-resource concurrency limits, explicit inspection classification, and exact
address policy. TCP and HTTP resource aliases share one namespace and a combined
256-profile ceiling. A raw endpoint cannot duplicate another raw endpoint or
overlap an inspected HTTP/provider/MCP host and port. Catalog credentials cannot
bind to raw resources. Different service aliases still need operator review;
canonical-name comparison does not discover remote forwarding behavior.

Complete resolver-result admission rejects wrong ports, unapproved candidates,
scope/flow overrides, and replacement of a literal IP before selecting one
address for a future single attempt. No DNS or network work occurs in policy.
The same checks run during daemon configuration validation/loading and embedded
broker construction. The optional `tcp_profiles` field defaults to empty for
existing daemon input; trusted session grants now recognize enrolled raw aliases.
An HTTP execute request cannot use that raw grant or discover provider items.

Three policy tests, one engine test, and one real daemon process test failed
before implementation and now pass. The process test specifically observed
validation accepting the inspected/raw endpoint collision before the loader
check was added; it now rejects it. Positive fixtures still validate and receive
a TCP-only session attachment, without upstream requests or secret resolution.
All 200 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0, with all-target checks on both and warning-free
stable Clippy/formatting. No dependency was added. Connector, stream execution,
relay limits/approval/observation, HTTP upgrade, and client integration remain
pending; configuration acceptance alone does not establish TCP support.

## Admitted TCP connector

`aap-transport::tcp` now provides a trusted connector interface and a concrete
single-attempt connector over an admitted socket address. Canonical endpoint,
port, literal-IP, and scope checks precede connection. No hostname lookup, TLS,
authentication, local stream framing, retry, failover, or connection task is
hidden inside it. A ten-second maximum absolute establishment deadline and
cancellation bound the attempt; late successful sockets are dropped, and
abnormal attempted connections retain uncertainty even without payload bytes.
The returned owned I/O remains inside the trusted host.

Four new tests failed on their initial stubs and now pass. A real TCP fixture
uses an unresolvable enrolled name with the admitted loopback address, preserves
binary bytes, and exercises both half-close orders, including a reply only
after the client ends its send direction. Deterministic paused-clock tests
prove pre-cancelled/expired attempts are not polled, started attempts are not
retried or detached, late success is discarded, and native diagnostics remain
private. Tokio's existing test-time support is enabled only as a development
feature; no runtime dependency was added.

All 204 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target checks pass on both; stable formatting,
warning-free Clippy, and warning-free workspace documentation pass. Documentation
checking found and corrected an IPv6 example mistakenly parsed as a Rustdoc link.
The engine-owned duplex operation, shared approval/quotas/observation, local
upgrade, agent client, and confinement acceptance remain unimplemented TCP
integration gates. These connector tests do not complete W7.

## TCP engine admission and connection lifecycle

The trusted engine now owns one pending TCP attachment per operation, separate
from HTTP execution but inside the same operation-ID namespace and retained
tracking budget. Admission checks grants without DNS, store access, or dialing.
Duplicates return status without acquiring another attachment. Connection
preparation binds separate connection-level consent, full address admission,
required opening observation, and one admitted connector attempt. No dummy
credential lease or store metadata/read call is used for TCP.

Pending attachments have per-session/broker ceilings of 16/128. Preparation
shares HTTP's 16 pending approvals/4 MiB and eight active session slots. Active
TCP additionally reserves a per-resource slot, one of 64 broker slots, and
128 KiB from an 8 MiB payload pool. Cancellation closes retained sockets and
releases reservations without waiting for their owner to poll or drop them.
Unpolled connected handles expire under the original idle/session/lifetime
bounds; reported opening lifetime decreases rather than restarting the clock.

Thirteen added tests cover shared identity, immutable connection approval,
late/denied/absent consent, drop/cancel/revoke, pending/active/global/payload
capacity, shared HTTP approval retention, observation finality, and timing.
Initial admission tests failed against compiling stubs. Subsequent draft tests
exposed retained pending capacity after cancellation, stale reported lifetime,
post-cancellation observation, and ready approval/DNS/connector results winning
at expired deadlines. Those assertions were observed failing before their fixes
and now pass. The 64-connection fixture needed a larger bounded recorder to test
connection capacity without first exhausting required observation storage;
its capacity assertions and required-recording mode were preserved.

All 217 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0, with all-target checks on both and warning-free
stable Clippy. Tokio I/O helpers were enabled only for engine development tests;
no runtime dependency was added. This foundation does not yet forward TCP
application bytes or expose an agent endpoint: duplex/half-close, payload
observation, local upgrade, client/service binding, and actual confinement
remain open W7 gates, alongside the other recorded proof requirements.

## Bounded TCP duplex primitive

`aap-transport::tcp::relay` now owns bounded bidirectional application I/O with
one 32 KiB-or-smaller buffer per direction, independent byte ceilings, exact
accepted-prefix write counters, and both half-close orders. It alternates work
and performs at most sixteen I/O steps per poll. There is no spawned driver,
unbounded queue, disk spool, retry, or credential lookup. The caller must reserve
aggregate capacity and supply a trusted admission gate before forwarding each
chunk/end; the primitive does not implement payload sanitization or export.

Absolute lifetime and inherited idle deadlines cannot restart at handoff.
Successful writes alone refresh inactivity; opposite-direction progress does
not extend a stalled write. Both cancellation and timeout wake a blocked driver.
Explicit owner termination closes I/O and releases buffers without polling or
flushing, while retaining actual partial-write counts and any committed outcome.
Calling termination cannot manufacture an orderly end without the two-ended
relay path. Engine terminal recording and lifecycle commitment remain separate.

Eleven tests cover real binary TCP exchanges, both half-close orders, replies
after send-end, admission failure/cancellation before writes, partial delivery,
exact and exceeded directional limits, end-recording failure, idle/lifetime and
stalled-write deadlines, blocked-driver wakeups, bounded continuously ready I/O,
and immediate owner termination. Eight tests were observed failing against
their initial compiling stubs and now pass; three additional tests exercise
existing draft behavior rather than claiming new regression discovery.

All 228 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0, with all-target checks on both. Stable formatting,
warning-free Clippy, and warning-free workspace documentation pass. No dependency
or Cargo feature was added for this primitive. Engine payload observation and
terminal integration, explicit framed send-end/attachment-loss handling, local
upgrade/client APIs, and the actual daemon/sandbox demonstration remain pending.
Raw application EOF in these native fixtures does not prove that an agent-wire
EOF is accepted as an orderly end; the future framed adapter must reject it.

## Engine-owned TCP payload and observation

`ConnectedTcp::relay` now transfers a trusted application attachment directly
into the operation's owned state. Its future drives bounded duplex forwarding,
with paired safe agent/upstream observation before each chunk/end and final
recording before completed status. Plaintext, opaque, and metadata-only modes
remain distinct; empty safe content still requires recording admission. Flow
close counts actual application write prefixes, while content offsets/endings
count sanitized bytes. No TCP path calls any secret-store method.

Immediate conservative placeholder suppression masks possible token suffixes
without waiting for another application message. Subsequent continuation stays
hidden, including after a mismatch; boundary false positives affect observation
only. This avoids interactive deadlock without changing actual forwarded bytes.
Recognition is bounded to the documented representations, not arbitrary covert
encodings. Each relay uses 16 KiB-or-smaller core buffers per direction within
its pre-reserved payload budget, with separately bounded recorder storage.

Cancellation, revocation, drop, and the dynamic watchdog close retained I/O and
release capacity without a second driver poll. Successful application progress
refreshes idle time without extending absolute lifetime. Terminal commitment
wakes the waiting owner before dropping its cancellation registration; arbitrary
I/O adapters need not supply a drop wakeup. Accepted partial-write counts remain
available after resources are released, and later cancellation cannot replace
an already committed outcome.

Three new authentication tests and nine engine tests cover all supported token
representations/splits, interactive binary traffic, both half-close orders,
all inspection classes, required and best-effort recorder outages, final-batch
refusal, partial counts, unpolled cancellation/revocation/drop, dynamic idle and
absolute lifetime, and completion/wakeup ordering. The initial redactor and four
engine integration tests failed against their compiling stubs before
implementation. Further deterministic tests exposed an expired-timer rearm and
lost owner wakeup before their fixes; additional passing draft checks are
conformance evidence, not claims of new regression discovery.

All 240 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target checks pass on both; stable formatting,
warning-free Clippy, and warning-free documentation pass. No dependency or Cargo
feature was added. The local HTTP upgrade, credential-free service/client API,
framed send-end/attachment-loss behavior, reserved control capacity, and real
daemon/confinement fixtures remain pending. Trusted native-I/O forwarding does
not complete W7 or establish an operational agent TCP endpoint.

## Runtime-neutral stream service seam

`AgentService::open_stream` now exposes the engine's existing TCP admission
through credential-free owned handles. It returns either retained status or
the sole pending attachment; approval/DNS/dialing wait for explicit connection
work. A connection reports safe opening metadata or its committed terminal
result. Adapter delivery failure remains a separate error, never an invented
terminal outcome, reattachment, or automatic retry.

The connected handle immediately owns a runtime-neutral application adapter
when forwarding is requested, even before the returned future polls. Bounded
read/write/directional-end callbacks are distinct from terminal completion.
Reported byte counts are checked before buffer advancement/accounting. Fixed
local adapter failures preserve invalid-frame, limit, loss, and internal causes;
native diagnostics and upstream errors cannot masquerade as those controls.
Public contracts gained no runtime, socket, custody, or protocol dependency.
Concrete engine use still requires its host's Tokio runtime.

Five engine tests failed with the unsupported service stub before wiring and
now pass. They cover object-safe admission, duplicate/conflicting identity,
abandonment before connection, missing approval, no reconnect, real binary
traffic and directional end, immediate ownership before polling, all fixed
adapter failure classes, and oversized callback counts. The failure-class test
also observed invalid framing being reduced to attachment loss before typed
propagation was added. A sixth conformance test checks that upstream/native
diagnostics retain fixed private causes. All TCP fixtures observe zero calls
to every secret-store method.

All 246 unit tests, seventeen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. All-target checks pass on both; stable formatting,
warning-free Clippy, and warning-free documentation pass. No dependencies or
Cargo features changed. HTTP upgrade, its framed application adapter, actual
client/daemon TCP support, reserved status/cancel capacity, and confinement
remain separate incomplete gates. Other AgentService adapters still explicitly
reject stream opening by default rather than falsely claiming wire support.

## Daemon TCP upgrade and reserved control capacity

The session listener now implements strict HTTP Upgrade for an enrolled TCP
resource, followed by bounded binary framing. It validates raw singleton
headers before normalization, forbids pre-OPENED payload, writes OPENED before
application forwarding, and preserves both explicit half-close orders. Shared
engine admission, approval, destination checks, observation, and single-attempt
connection remain authoritative. Operator and inspected CONNECT routes do not
expose this endpoint. The credential-free client integration is still pending.

The framed adapter reports actual accepted payload prefixes, handles split and
coalesced frames, and monitors forbidden input after the agent's directional
end. A partially written output frame cannot be replaced by terminal control.
Final delivery has a two-second ceiling; losing it never rewrites the committed
engine result. Payload is released with the engine reservation, without waiting
for final control delivery. Stop-only service handles interrupt blocked OPENED
writes without acquiring new authority or inventing a terminal outcome.

Session listeners reserve four of 32 local connection slots for bounded
classification and status/cancel service. HTTP work, CONNECT, and TCP attachments
share at most 28 work permits. Complete incoming session metadata has one
ten-second deadline. TCP approval, preparation, and connected lifetimes retain
their separate bounds instead of inheriting the ordinary HTTP response timer.
Explicit expiry checks reject already-ready metadata after its deadline, for
both TCP opening and ordinary HTTP body collection.

Seventeen added unit tests cover framing, exact write counts, early/after-end
input, loss during approval, fixed limits, payload release, blocked-control
cancellation, final-delivery timeout, metadata expiry, and exhausted work slots
with responsive controls. Initial parser/framing/integration tests failed against
compiling stubs. Further failing assertions exposed expired ready metadata,
control-slot exhaustion, and cancellation blocked behind OPENED delivery before
their fixes. Supplemental already-passing draft checks are conformance evidence,
not regression-discovery claims.

The additional daemon process test uses the real session socket, TCP fixture,
and owner observation endpoint. It verifies binary forwarding without local
framing at the peer, explicit send-end, completed terminal/status, paired final
observations, no duplicate connection, malformed headers, and operator-route
separation. Engine TCP fixtures continue to observe zero secret-store calls.

All 263 unit tests, eighteen process tests, and the compile-fail doctest pass on
Rust 1.95.0 and 1.88.0. All-target checks pass on both; stable formatting,
warning-free Clippy, and warning-free documentation pass. The HTTP adapter uses
the already-transitive `httparse` package directly and scoped Tokio features;
no external package was added. Client delivery, broader adversarial/shared-limit
acceptance, reuse examples, and actual confinement still prevent a complete W7
or proof-of-concept claim. See [the implemented endpoint](tcp.md) for its exact
current scope.

## Credential-free TCP client

`DaemonSessionClient` now implements the same owned stream service as the engine,
over the real session Upgrade endpoint. Strict response validation distinguishes
new admission, existing status, and safe errors before handing bounded read-ahead
to the common frame decoder. Identity, narrowed limits, explicit directional
ends, terminal sequence, and actual-written counter bounds are checked locally.
There is one opening attempt, no redirect or direct upstream connector, and no
automatic reconnect, reattachment, or replay.

The client has one attachment owner through pending, connected, and relaying
states. Moving that owner does not restart deadlines. Immediate relay ownership,
drop/abort cleanup, and an owner-scoped watchdog release sockets and application
state even when the consumer never polls again. Only bounded control input is
retained before OPENED. Connected forwarding uses bounded bidirectional buffers
and per-poll work; explicit half-close keeps the terminal control path alive.
Connection/preparation and connected timeouts remain distinct from ordinary HTTP.

Client delivery errors never invent a daemon outcome. A valid abnormal terminal
can be reported without claiming complete delivery; missing/truncated terminal
records and failed application writes remain local errors. Errors retain the
original request ID for separate status/cancel calls. A later completed status
does not recover lost application bytes or authorize a replacement attachment.

Thirteen client tests cover real synthetic session sockets, strict HTTP/control
identity, split/coalesced input, binary duplex with both end orders, existing
status, missing/impossible terminal records, and no retry. Owned-state tests
also cover unpolled expiry/drop/abort, actual partial-write counter bounds,
cross-frame byte ceilings, invalid callbacks, and application delivery failure.
The first three tests failed against the unsupported client before implementation.
Later tests exposed immediate-terminal handling after a written SEND_END,
case-sensitive close-token validation, missing request IDs on owned-handle
errors, and retained caller-task wakeups after completed polls before their
corrections. Remaining passing draft checks are conformance
evidence, not additional regression discoveries.

An additional daemon process test uses the public client for binary request/reply,
explicit send-end, independent cancellation, and drop before relay polling. It
checks retained status and duplicate results after all three paths, with no
additional upstream accepts. The inspected HTTPS fixture receives no TCP traffic.
This supplements, rather than replaces, the raw-wire daemon endpoint test.
That fixture's malformed-header cases now deliberately withhold their bodies
and require early rejection. This avoids racing a body write against a valid
server close while preserving rejection and no-operation-admission assertions.

All 276 unit tests, nineteen daemon process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0, with all-target checks on both. Stable formatting,
warning-free Clippy, and warning-free documentation pass. The client uses the
already-present `httparse` package directly and explicit Tokio I/O/sync/macro
features; no external package or custody dependency was added. Its normal/build
dependency tree and package-only check contain no trusted engine/store code.
Full allocation/concurrency/loss-injection acceptance, independent consumer and
embedding parity, and the actual sandbox proof remain incomplete W7/W8 gates.

## First Linux confinement evidence

The optional [confinement fixture](confinement.md) now runs a separate Rust
provider client inside real Linux user/network/mount/PID/IPC/UTS namespaces.
Only one session socket and the probe's individual runtime files are projected;
the daemon, private catalog, SQLCipher vault, and operator/observer listeners
stay outside. The external test harness composes Bubblewrap and finite resource
limits without introducing a sandbox dependency into the daemon or libraries.

Unconfined positive controls first prove that both the probe and its descendant
can reach live IPv4/IPv6 TCP/UDP and filesystem/abstract Unix canaries, private
fixture files, known host processes, and deliberately inherited authority
handles. The confined runs deny those paths, remove the synthetic environment
canary, drop capabilities, retain no-new-privileges, and deny further user
namespaces. Trusted receipt counters remain unchanged. The client still obtains
the redacted provider response; the TLS fixture receives the private API key,
and both correlated observation views close completely.

Revocation prevents further dispatch. A separate working attachment fails
after abrupt daemon death and remains unusable after restart, while a newly
projected attachment succeeds. Required collector overflow and an unavailable
approval mechanism each deny provider dispatch without changing the isolation
boundary. Removing that collector requirement restores its provider path.

The original acceptance test failed at the direct TCP reachability assertion
with ordinary process execution before the isolated launcher was implemented.
The extended lifecycle and failure checks are additional conformance evidence.
The fixture remains opt-in: a regular test-suite skip is not a confinement pass,
and an explicitly requested run fails if prerequisites are absent. The guide
records the kernel, launcher, identity mapping, exact coverage, and remaining
gates, including the limits of testing inside an already-containerized host.

All 276 unit tests, nineteen ordinary daemon process tests, and the compile-fail
doctest pass on Rust 1.95.0 and 1.88.0; the additional confinement process test
passes when invoked explicitly on both toolchains. All-target checks pass on
both; stable formatting, warning-free Clippy, and warning-free documentation
pass. The probe adds only an existing `rustix` development dependency on Linux;
the normal client dependency graph remains credential-free.

This is partial W4/W8 deployment evidence, not complete confinement or a
production launcher. Confined website/CONNECT/MCP/TCP paths, protocol-specific
and alternate-family bypasses, stronger process-escape/teardown coverage, and
the rest of the deployment matrix remain required. W0-W9 are not marked
complete by this provider-only demonstration.

## Confined MCP website and TCP paths

Two further opt-in process tests extend the same Linux boundary to the actual
password-manager and owned TCP interfaces. They do not add custody or sandbox
management to agent-facing libraries. The development probe uses the public
credential-free MCP adapter in a real child process, including initialization
and stdio tool calls. Every tool child repeats the same bypass probes before
handling its call. Only the one projected session attachment is available.

The website test completes both form and JSON login through MCP search, fake
credential issuance, private pre-login/auth cookies and profiled CSRF, protected
requests, status, and logout. Two confined sessions cannot use each other's
contexts, and logging out one does not revoke the other. The controlled HTTPS
origin verifies actual credentials; agent responses and decoded observation
content contain neither those values nor the private cookies/CSRF values.
Both recorded views close completely for each successful request.

The TCP test uses the public owned client for binary duplex, explicit half-close,
exact terminal counters, and directional observation from two confined sessions.
Duplicate opening returns retained status without reconnecting; an identical
public request ID on the other attachment identifies that session's own operation.
Revoking one session does not stop the other. The actual plaintext peer is also
a positive-control direct-network target, with separate connection and payload
counters: no direct sandbox connection reaches it.

Both new paths reject protected work when required observation cannot accept
it or approval is unavailable. Removing only the deliberately tiny collector
restores the affected session's path. The website test checks the visible
observation gap and resumes its cursor to verify later successful flows. Its
first draft incorrectly inspected only the first page after the intentional
gap; the fixture now consumes bounded pages instead of weakening the required
completion assertions.

Each new action path was first tested against a compiling unsupported probe
stub and failed before implementation. The additional lifecycle/failure cases
are conformance evidence, not newly discovered production regressions. The
three opt-in confinement tests are serialized because their positive controls
deliberately change inheritance of synthetic descriptors in the test process.
Their documented command runs separately from the ordinary test suite; skips
still do not count as confinement passes.

All 276 unit tests, nineteen ordinary process tests, and the compile-fail doctest
pass on Rust 1.95.0 and 1.88.0. The three confinement tests pass when invoked
explicitly on both toolchains. All-target checks pass on both; stable formatting,
warning-free Clippy, and warning-free documentation pass. The example adds only
the existing `aap-mcp` crate and scoped Tokio features as Linux development
dependencies. The normal client dependency graph remains unchanged and contains
no engine/store code.

The [confinement guide](confinement.md) records the updated evidence and limits.
CONNECT, remote MCP, broader protocol-specific and alternate-family bypasses,
process-escape/teardown coverage, and the remaining W0-W9 acceptance requirements
are still incomplete. These tests do not complete the full proof of concept.

## Confined CONNECT and remote MCP paths

Three more opt-in fixtures extend the Linux proof to inspected provider and
website requests and to remote MCP. The development probe has a bounded
CONNECT/HTTP client using only the projected Unix socket and a supplied public
CA certificate. Its Rustls dependencies are Linux development-only, reuse
already selected packages, and do not alter the normal client's dependency
closure. There is no ambient trust, private-key input, redirect, retry, or
direct-network fallback in that action.

The synthetic HTTPS origin now counts TCP accepts separately from HTTP
requests. Unconfined parent/descendant controls must reach that exact listener;
all subsequent accepts must correspond to expected mediated operations. This
detects connections which never finish TLS, not just unexpected HTTP requests.
It does not establish the separate DNS/HTTPS/QUIC protocol-level bypass gates.

Provider CONNECT succeeds with a sanitized stream while wrong CONNECT
authority, Host, SNI, or trust root causes no additional upstream connection.
A one-event required collector rejects the second admission check before the
TLS upgrade; an unavailable approval provider rejects the protected operation.
Removing the collector restores access without changing the sandbox boundary.
Observation includes TLS admission and one complete ending per HTTP view.

The website fixture covers form and JSON submission, private CSRF/cookies,
MCP-issued fake credentials, and a 303 without automatic authenticated follow-up.
Two confined sessions cannot select each other's contexts; logout of one leaves
the other usable. Headers, trailers, response bodies, and decoded observation
content exclude the synthetic private values. Each successful HTTP operation
has exactly one completion in each observed view.

The remote fixture covers JSON and SSE using actual stdio tool children and
CONNECT interchangeably within each local session. Two sessions for one account
and a third for another create three distinct native upstream contexts. Forged
session/protocol headers fail; confirmed DELETE invalidates only its context.
Required-recording and approval failures deny both ingress paths. A server
which receives a call then disconnects produces an uncertain outcome, an
incomplete ending in each view, and no repeat dispatch on status or duplicate
submission. Cleanup/control subrequests retain parent correlation.

The origin counter first failed against a zero-returning stub; after its
implementation, the provider test failed against an unsupported CONNECT action.
The actual client then passed that test. Website, remote, and additional failure
cases are conformance coverage, not claims of newly discovered daemon bugs.
Draft expectations were corrected to the existing typed errors after inspecting
the owning code: cross-session website handles are policy denials, while remote
calls without an initialized/live context are request-state conflicts. The
no-dispatch and private-state assertions were retained.

One combined run with concurrent host compilation ended early in the existing
MCP website probe. Its precise cause was not captured; host resource pressure
is a possibility, not an established diagnosis. A subsequent standalone serial
run passed all six confinement tests without changing their limits. The guide
now advises keeping build workloads separate from this UID-limited fixture.

All 276 unit tests, nineteen ordinary daemon process tests, and the compile-fail
doctest pass on Rust 1.95.0 and 1.88.0. All six confinement cases pass when
invoked explicitly on both toolchains; the three new cases were also rerun on
1.95.0 after strengthening their per-view ending assertions. All-target checks
pass on both toolchains. Stable formatting, warning-free Clippy, warning-free
documentation, and changed-document relative-link checks pass. Normal/build
dependency inspection confirms the client still has no engine, store, MCP, or
Rustls dependency; the added TLS packages are development-only.

Full protocol/physical-connection observation, the remaining confinement
matrix, operational recovery, independent embedding demonstrations, and native
Keychain delivery remain open; W0-W9 are not marked complete.

## Independent public-API consumers

The first W8 delivery adds separate client and embedded SQLCipher consumer
workspaces with explicit manifests, committed lockfiles, READMEs, and a shared
credential-free scenario driver. No production crate, public export, or new
registry package/version was needed. Their source dependencies come from this
checkout; their lockfiles do not inherit the root workspace's feature selection.
See [the integration guide](reuse.md) and
[runnable commands](../examples/reuse/README.md#run-both-consumers).

The actual client executable receives only two admitted socket paths and a
synthetic origin, runs with a cleared environment, and returns bounded public
evidence. A separate trusted harness provisions the encrypted store, admits
sessions, and checks private origin receipts and authorized observations.
The embedded host opens that same real backend through public composition
APIs in a caller-owned runtime, without a daemon dependency or implicit startup.

Both paths exercise provider key injection, form and JSON login, private CSRF
and cookies, two-session separation, logout, revocation, repeated and conflicting
IDs, policy denials, cancellation, and origin-recorded response loss. Each
encoding/path combination verifies eight completed and two uncertain operations
with exactly ten upstream receipts. Repeating completed or uncertain operations
does not dispatch again. The harness examines twelve complete/partial public
responses, five discovery/login metadata results, seven typed errors, and
decoded observations for seeded secrets. Each operation has exactly one
complete or incomplete ending in each observation view.

Retained embedded clones and daemon client attachments reject work after
revocation. Additional embedded checks reject a wrong key without damaging
the existing vault and refuse missing stores without creating replacements.
The initial composition/scenario tests failed against their example stubs.
The stronger response-evidence and cancelled-ID checks also failed when the
driver omitted that evidence, then passed after it was supplied. These are
example/conformance checks, not newly discovered production regression fixes.

The three independent integration tests pass on Rust 1.95.0 and 1.88.0; each
client run uses a daemon built with the matching compiler. Separate normal
builds and dependency checks pass on both. The client normal/build closure has
no credential-custody, configuration, store, or trusted upstream component;
the embedded closure contains neither the daemon nor test support. All resolved
third-party package versions already occur in the root lockfile. Stable example
formatting, warning-free Clippy, and warning-free documentation pass. The new
CI matrix records these gates; remote CI has not been run.

Root all-target checks, all 276 unit tests, nineteen ordinary daemon process
tests, and the compile-fail doctest pass on both compilers. Root formatting,
Clippy, and warning-free documentation pass on 1.95.0. Six opt-in confinement
tests were not rerun in this delivery; their preceding evidence is separate.
No personal credentials, global trust changes, or Goose/Loupe changes were used.

The first R1-R8 reuse slice is demonstrated, but W8 remains open. This does not
prove counted pre-resolution denial, two-account isolation, custom store/approval
composition, full shutdown and shared quotas, remote MCP/TCP equivalence, or
OS confinement of these executables. Those scenarios and the remaining custody,
observation, confinement, and native Keychain gates are still required.

## Host-supplied custody, approval, and observation

The third independent consumer, [reuse-adapters](../examples/reuse/adapters/README.md),
now composes a counted test-only `SecretStore`, bounded asynchronous approval
inbox, and acknowledged observation handoff through public APIs. It installs
no runtime or listeners. Real verified HTTPS requests demonstrate actual key
injection and sanitized responses, including newly approved work after rotation
or trusted recovery from store lock/outage. The fixture store is not exported
from the library and is not an operational fallback.

Six tests exercise immutable approval input, policy denial before metadata
access, zero secret resolution while approval is pending, positive/negative
decisions, full/closed approval queues, cancellation, revocation, dropped
execution/approver, store lock/outage/interaction requirements, deletion,
rotation, and late decisions. Invalidation denies stale pending work with no
resolution or upstream receipt; applicable recovery paths require new approval
against the changed lease before a successful request.

The observation helper transfers bounded subscription pages to a bounded
channel, waiting for explicit consumer acknowledgment before advancing its
cursor. Dropped pages, full/closed queues, expiry, and late acknowledgments
retain the cursor; a repeated delivery keeps its original delivery ID.
Acknowledging observation does not approve a pending operation. Consumer
disconnect is tested separately from failure of the configured local recording
boundary: only the latter immediately denies required-mode work before secret
resolution. JSON and decoded content are checked for synthetic private values.

The initial approval/forwarding tests failed against the example stubs. A
deterministic test then failed when a receipt and its expired deadline were both
ready: the timeout wrapper accepted the receipt first. The new helper now gives
expiry priority, and the test passes while proving the cursor remains unchanged.
This corrects the new example, not an existing production broker component.

All six tests, minimal normal builds, and all-target checks pass on Rust 1.95.0
and 1.88.0. Stable formatting, warning-free Clippy, and warning-free public docs
pass. The independent workspace root and resolved normal/build/test dependency
graphs were inspected: neither SQLCipher nor Apple store bindings are selected;
normal code also excludes the daemon and test-support package. Registry package
versions are already present in the root lockfile. CI now includes this third
consumer, but remote CI has not been run.

Root all-target checks, 276 unit tests, nineteen ordinary process tests, and the
compile-fail doctest also pass on both compilers. Root formatting, Clippy, and
warning-free documentation pass on 1.95.0. The unchanged first two consumers
retain their preceding evidence; the six opt-in confinement tests were not
rerun here. No production crate API or runtime dependency changed.

W8 remains open: these in-process fixtures do not establish signed human
approval, native unlock behavior, cookie-backed approval parity, the complete
shared failure matrix, remote MCP/TCP reuse, or broker-wide shutdown. Backend
conformance, operational recovery, remaining observation/confinement cases,
and native Keychain delivery remain part of the full proof of concept.

## Broker-wide admission closure

`Broker::close()` now irreversibly closes session admission and revokes all
currently live sessions. Session publication and the closure snapshot share
one ordering boundary; retained clones observe the same closed authority.
`is_closed()` reports this admission state, not successful resource drain.
Closure notifies every session before attempting local cleanup, continues
across cleanup errors, and stays closed after a poisoned registry or session
lock. Repeated/concurrent closure is supported without locking shared stores.

The daemon's signal shutdown uses this same public operation before dropping
its session/observer attachments. The independent embedded consumer exercises
closure through public APIs, retaining its original per-session revocation
checks and separately verifying rejection of live clones and new admission.
No runtime dependency, agent wire method, or credential-bearing client API was
added. Configuration reload remains a separately owned generation lifecycle.

Eight new engine tests failed against the no-op closure stub, then passed with
the implementation. They cover every session entry point, sixteen rounds of
concurrent creators/closers, pending approval with zero resolution/dispatch,
late decisions, stable completed outcomes, uncertainty after origin receipt,
polled response cancellation, poisoned cleanup, and independent brokers sharing
the actual SQLCipher store. Form/JSON positive login controls precede cookie
and placeholder invalidation; JSON/SSE MCP handshakes precede closed-context
reuse and retained initialization-response rejection. A real retained TCP
connection closes at the peer and returns its capacity, while a retained
pending handle terminates without becoming connected.

The embedded consumer's initial closure check also failed against the stub.
Its two tests pass on Rust 1.95.0 and 1.88.0, including both login encodings.
Root all-target checks, 284 unit tests, nineteen ordinary daemon process tests,
and the compile-fail doctest pass on both compilers. Root/embedded formatting,
warning-free Clippy, and warning-free public documentation pass on 1.95.0.
The unchanged independent client/custom-adapter tests and six opt-in confinement
tests were not rerun in this delivery; their preceding evidence is separate.

This establishes the initial closure cases L1/L2/L7 and partial context/stream
evidence from the [lifecycle contract](../plan/lifecycle.md), not complete
W4/W8 shutdown. A retained unpolled HTTP body can still own its connection
driver; the host must drive cancellation or drop it. No aggregate task/socket
drain result, native-call completion guarantee, or complete dispatch-commit
race proof is introduced here. Deterministic late native results, late private
state writeback, all-adapter drain/deadline/failure handling, reload retirement,
and shared daemon/embedded lifecycle parity remain required. Operational store
recovery, native Keychain, and the other open proof-of-concept gates also remain.

## Rejecting ready store results after closure

Five deterministic regression tests exposed a gap in the initial broker-close
integration: a successful store future could close the broker and return ready
in the same poll, after the outer cancellation branch had already been checked.
The provider path could then start another secret lookup after revalidation;
provider and remote MCP paths could prepare credentials after resolution.
Website processing reached a revoked placeholder instead of discarding the
late result at the session boundary. The tested cases made no extra upstream
request, but they still crossed the intended custody/preparation boundary.

All four resolution paths now use one engine-owned check immediately before
starting the store call and after it returns: provider, form/JSON website,
remote MCP application work, and remote MCP control/cleanup. A result returned
after closure is discarded before the caller uses it for authentication.
This does not change the store trait or interrupt a native call.

The tests use a counted real SQLCipher adapter wrapped by a one-shot closure
barrier, positive HTTPS/website/MCP controls, exact native resolution and origin
receipt counts, and per-operation authentication observations. JSON/SSE remote
calls and an independently authorized DELETE cleanup are covered. All five
tests failed on the pre-fix production code, passed with the correction, and
failed again with only the production correction removed before restoration.
No assertion was weakened and no fixed sleep selects the closure ordering.

All-target checks, 289 unit tests, nineteen ordinary daemon process tests, and
the compile-fail doctest pass on Rust 1.95.0 and 1.88.0. Formatting, warning-free
Clippy, and public documentation pass on 1.95.0. Independent consumer and opt-in
confinement tests were not rerun in this correction. No dependency or public
API was added. Broader dispatch/writeback ordering, native-work accounting, and
aggregate resource drain remain open; this is not the complete L3/L4 contract.

## SQLite native work after caller cancellation

A new backend conformance test uses the actual SQLCipher connection and native
worker path, pausing a worker after it reads a synthetic credential. Dropping
that caller and seven other admitted callers does not free their eight native
reservations. A further lookup and a request to lock the store both report
`Unavailable`, rather than admitting more native jobs or claiming a locked
backend. Explicitly releasing the worker disposes of its abandoned result;
all capacity returns and the original credential lease still resolves.

The fixture uses explicit entry/release/disposal barriers and finite waits,
not sleeps to infer native progress. It checks encrypted backing files before
teardown. This is additional evidence for existing worker ownership, not a
regression fix or a claim that cancellation interrupts native work. No production
store code changed. Tokio's timer feature is added only to this crate's test
dependencies so isolated tests do not rely on workspace feature unification.

The isolated backend test and the full workspace pass on Rust 1.95.0 and 1.88.0:
290 unit tests, nineteen ordinary process tests, and the compile-fail doctest.
All-target checks pass on both; formatting, warning-free Clippy, and public docs
pass on 1.95.0. Independent consumers and opt-in confinement tests were not
rerun. Broker-wide native-job accounting, bounded daemon/store shutdown, and
operational recovery remain open; a cancelled caller alone is not a drain result.

## Ordered final dispatch and authority retirement

The engine now orders final HTTP/MCP dispatch and TCP dialing with broker closure
and individual session revocation. All provider, website password/cookie, remote
MCP application, and remote MCP control paths use the same authority boundary.
The operation-state transition to `Dispatching` commits while that boundary is
held; transport calls, observation, native access, and cancellation notifications
occur outside it. A separate session revocation flag permits publication before
waking callers or walking retained operations. Registry poisoning remains a
fail-closed error, with notification and cleanup still attempted.

Seven deterministic regressions pause actual operations at `Ready`, after their
earlier preparation checks, and hold the session operation registry so the
revocation walk cannot cancel them yet. Closure/revocation is confirmed before
the operation resumes. Before the gate, each path handed one extra prepared
request/endpoint to its counted real transport or connector. Testing only the
returned error or eventual origin receipts would miss that unauthorized handoff.
The gate rejects it and preserves a pre-dispatch `Cancelled` terminal state.

Positive controls use actual SQLCipher custody, HTTPS origins, and a TCP peer.
Form and JSON password submissions, cookie-only requests with no new resolution,
JSON/SSE MCP calls, and an independently authorized DELETE control child are
covered. Already completed operations remain completed; revoking one session
leaves another usable. An eighth new test confirms origin receipt before closure
and retains `OutcomeUnknown` without retry. Existing retained-TCP closure tests
also continue to verify uncertainty, peer EOF, and released capacity.

The seven regressions failed on pre-gate production code, passed with the gate,
and failed again after restoring only those production files, before restoring
the implementation. Test-only barriers do not exist in production builds.
Tokio's multi-thread runtime feature is added only to engine test dependencies;
no production dependency, public signature, or agent wire schema changed.

All-target checks and the full workspace pass on Rust 1.95.0 and 1.88.0: 298 unit
tests, nineteen ordinary daemon process tests, and the compile-fail doctest.
The three independent consumers also pass on both compilers: one client test,
two embedded tests, and six custom-adapter tests, using matching daemon builds.
Formatting, warning-free Clippy, and warning-free public documentation pass on
1.95.0. These consumers establish their existing integration scenarios, not a
new daemon/embedded final-race matrix.

All six opt-in Linux confinement fixtures also pass serially on both compilers,
using each compiler's matching credential-free probe and daemon. These rerun
the existing provider, MCP website, CONNECT, remote MCP, and TCP sandbox paths;
they do not close the broader bypass or physical-observation gaps documented in
[the confinement evidence](confinement.md).

This establishes the engine's L4 dispatch ordering, not aggregate shutdown or
all lifecycle cases. A dispatch committed before closure may reach its origin
later; cancellation does not imply rollback. Late private-state writeback,
unpolled response ownership, aggregate task/native-work drain and deadlines,
reload retirement, and complete daemon/embedded lifecycle parity remain open.
Operational recovery, native Keychain delivery, and the other unchecked proof
gates remain required; this change does not complete W4/W8 or the overall goal.
