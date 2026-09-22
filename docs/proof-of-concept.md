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
