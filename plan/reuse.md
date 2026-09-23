# Reuse and integration acceptance plan

Status: proposed W8 acceptance contract, not evidence of completed integration.
Keep the existing names. This document makes the reuse requirements in the
[workspace design](rust-workspace.md) testable without choosing final Rust
signatures or modifying Goose or Loupe.

## Three supported integration paths

| Path | Consumer receives | Consumer must not receive |
| --- | --- | --- |
| External agent client | An already admitted session attachment and the credential-free client/MCP surface | Broker administration, store handles, private configuration, CA keys, or upstream credentials |
| Trusted broker host | Reusable engine plus explicitly selected store, transport, policy, approval, and observation components | An implicit sandbox guarantee or automatically installed listeners, runtime, logging, or trust roots |
| Component consumer | One documented component and its explicit dependencies | A claim that using a parser, store, or policy component alone implements the complete broker boundary |

The external daemon remains the default integration. Embedding is for a trusted
host process outside the agent sandbox, not a way to place a password manager
inside an untrusted agent. The host and every injected store, connector, or
approval adapter join the trusted computing base. Trait implementations are
not isolated plugins; Rust interfaces cannot constrain a malicious host.

Agent-facing and host-facing APIs remain separate. An agent may learn a safe
session identifier for correlation, but cannot turn that identifier into a new
session handle. Only the trusted host grants access or attaches a session to
an ingress. Cloning or wrapping an existing session handle must preserve its
identity, revocation state, and shared limits.

## Required example consumers

Examples are small executable acceptance fixtures with their own README and
manifest, not a new integration framework. Use synthetic credentials and local
controlled origins; no production account or personal vault is required.

| Fixture | Required demonstration | Dependency boundary |
| --- | --- | --- |
| External client | Discover an allowed item, obtain placeholders, log in, fetch a protected response, observe status, cancel, and log out through the daemon | `aap-client` and public non-secret contracts; no trusted workspace crates in its normal dependency closure |
| Embedded broker | Run the same provider and website scenarios in a caller-owned runtime, using the real SQLCipher adapter and a session-scoped service | Select trusted components explicitly; no daemon binary or CLI dependency |
| Host-supplied adapters | Supply a test-only `SecretStore`, asynchronous approval provider, and bounded observation consumer through public extension points | No SQLCipher or Apple framework linkage; fixture store is never an operational fallback |

The adapter fixture must exercise a real request through the broker, not merely
compile a trait implementation. Store lock, version change, approval denial,
and collector failure must reach the normal engine lifecycle. Distinguish
acceptance by the configured recording channel from later delivery to a
consumer: a disconnected consumer does not automatically mean that recording
failed. Required-mode tests must fail the configured acceptance boundary.

Examples use public APIs only. Do not enable extra production exports solely
for tests, import private modules, or give an agent-facing client administrative
conveniences. Test orchestration may provision stores and grant sessions from
a separate trusted harness; those capabilities stay out of the client program.

## Public composition and lifecycle contract

The trusted host supplies immutable validated configuration, store bindings,
admitted transport components, and observation/approval policy when constructing
the broker. The broker owns common admission and operation state. Frontends
translate calls to the session service; they cannot substitute a separate
authentication, retry, cookie, or policy path.

Keep effect ownership explicit:

- The host owns its runtime, process signals, logging subscriber, provisioning,
  sandbox, listeners, and any application-specific approval interface.
- The engine owns grants, operation IDs, policy decisions, credential-use
  ordering, quotas, private contexts, and terminal outcomes.
- The store owns native access and coherent credential snapshots. Store unlock
  is not approval of an operation, and operation approval cannot bypass a
  store denial.
- Each adapter owns only its protocol framing and bounded resources. A
  transport may dial an admitted endpoint; it may not independently select
  destinations, resolve credentials, redirect, or retry uncertain work.

Construction must not read ambient daemon configuration, start listeners,
install a process-global runtime, change environment variables, or install a
CA. The selected concrete store may open the explicitly supplied backing store;
that does not grant libraries permission to discover unrelated host files.

Expose explicit cancellation, revocation, and bounded shutdown behavior to
embedders. Dropping an execution future or response stream must follow the
same cancellation/uncertainty rules as losing the corresponding daemon operation
attachment.
Pending approval must not leave detached work that later dispatches after its
owner disappears. Native blocking calls may not be immediately interruptible;
bound their concurrency and the caller's wait, discard late results after
revocation, and document any backend work that cannot be forcibly stopped.

Shutdown stops admission, cancels pending work, prevents new credential use,
and closes live streams within the declared deadline. It does not claim to undo
remote effects or erase every memory copy. All clones of revoked handles must
reject further work, including clones retained by HTTP and MCP adapters.

The [broker lifecycle contract](lifecycle.md) separates irreversible authority
closure from confirmed resource drain. It defines concurrent admission,
dispatch/native-call races, held response bodies, shared-store ownership, and
the shutdown acceptance cases. Delivering closure alone does not close W8.

## Shared behavioral suite

Define scenario inputs and expected security outcomes once, then run them
against an in-process session service and a real daemon client using the same
profiles, synthetic store contents, and controlled upstream behavior. Use
separate fresh sessions and upstream state for each run.

Compare logical results, final operation states, sanitized content, and counted
upstream/store effects. Do not require byte-identical envelopes, random IDs,
timestamps, chunk boundaries, or interleavings. Wait at explicit fixture
barriers for race tests rather than assuming a transient state lasts long
enough for a wall-clock sleep.

| Scenario family | Required outcome on both paths |
| --- | --- |
| Provider and website success | The origin receives the enrolled real credential; the client and authorized observer do not; protected cookie access succeeds without exposing cookies |
| Wrong resource, account, or session | Denied before secret resolution or upstream dispatch; possession of a foreign placeholder/context never supplies authority |
| Duplicate and changed operations | Repeated execution IDs cannot dispatch twice; changed input or operation kind conflicts; placeholder issuance follows its separately specified bounded reuse contract |
| Approval | Pending status and cancellation stay responsive; deny, expiry, missing provider, changed binding, and late approval cannot release credentials or dispatch |
| Store availability and rotation | Lock, outage, changed lease, and deletion prevent stale credential use; cached contexts follow their documented invalidation rules |
| Dispatch uncertainty | An origin records receipt and drops the connection; no client or adapter retries it, and status never claims non-execution |
| Stream loss and revocation | Dropped futures/bodies, revoked grants, session expiry, and shutdown stop further delivery; partial work is not labeled complete |
| Observation | Sanitized content ordering, explicit endings, gaps/resume, collector isolation, and required recording failures preserve their documented semantics |
| Shared limits | Concurrent calls through multiple adapters/handle clones consume the same session budgets; creating a new wrapper does not reset them |
| Remote MCP and TCP | Each admitted profile passes its own lifecycle, custody, cancellation, framing, and no-replay contract through both integration paths |

Only compare operations within each adapter's declared capabilities and limits.
For TCP, apply the [client lifecycle contract](tcp-client.md): the remote
daemon may begin connecting immediately after its HTTP upgrade, whereas an
embedded pending handle starts that work when driven. Both must preserve one
attachment, cancellation, deadlines, and no replay. Compare the daemon's final
operation outcome separately from successful local application delivery.

For example, the MCP tool's bounded result envelope need not support every
stream size available to the direct client. Test those narrower limits as
explicit errors; do not buffer unbounded data or silently reduce the common
suite to avoid a difference. The core conformance driver need not introduce
a new production dependency or package.

Positive controls are mandatory: an allowed operation must reach the live
fixture before a denied variant is credited with blocking it. For isolation
tests, first prove each independent session/account can perform its own allowed
operation, then attempt cross-use. Examine request counts and sanitized records,
not just an error returned to the caller. A regression test must also fail on
the pre-fix code with the expected assertion.

## First provider/website delivery

Narrow the first W8 change to two independent consumers and a shared scenario
driver. This establishes a useful integration baseline without claiming that
the entire matrix above is complete. Repeat it with form and JSON login
profiles, fresh encrypted stores, and two separately admitted sessions.

Keep three pieces distinct:

- The credential-free driver receives session-scoped service access and safe
  fixture destinations. It issues ordinary agent operations and returns a
  bounded report of public results, operation IDs, and terminal states.
- The external client executable receives only pre-admitted attachments and
  that safe input. It has no provisioning, observer, operator, or store access.
  Launch the actual executable in the daemon test; a trusted test process that
  calls the client library alone does not establish this program boundary.
- Trusted orchestration creates the SQLCipher store, supplies its unlock key,
  enrolls profiles, admits sessions, runs the HTTPS origin, and reads authorized
  observations. Only this code knows the real synthetic credentials and private
  cookie values. It checks the driver's report against independently recorded
  effects; the report is not itself proof of non-disclosure or non-dispatch.

The embedded consumer composes the public engine, real store, and transport in
a caller-owned runtime. It must not start the daemon or depend on its CLI.
Share scenario inputs and assertions, not privileged handles or a second
implementation of authentication. Fixture-only support may be development code
or shared source; it does not require a new published crate or framework.

| Case | First-slice acceptance |
| --- | --- |
| R1: provider stream | The origin receives the enrolled key; the client receives bounded sanitized output; observed content and terminal records agree with the outcome |
| R2: operation reuse | Repeating a completed ID returns retained state without dispatch; changed input conflicts; cancelling completed work does not change its outcome |
| R3: admission | An ungranted resource and an unenrolled destination fail with no new origin receipt; first demonstrate that the allowed route works |
| R4: website flow | Discover the enrolled item, obtain fake fields, fetch profiled CSRF metadata, submit login, and read a protected response; native values and private cookies never reach the driver |
| R5: context isolation | Both sessions authenticate successfully, receive distinct placeholders, and use distinct private cookie jars; cross-session context use is denied |
| R6: logout and revocation | Logging out one context prevents its reuse without breaking the other session; revoking a session also invalidates retained handle clones and its existing attachment |
| R7: interrupted delivery | After the origin records receipt, a disconnect or cancellation produces the specified uncertain/incomplete outcome; status and repeated execution never resend the operation |
| R8: sanitized evidence | Inspect agent-visible bodies, headers, errors, and trusted observation exports for seeded secrets; check correlated complete/incomplete endings and count upstream effects independently |

Case IDs label acceptance evidence, not new protocol fields. Define explicit
expected request counts for each fixture transcript; redirects, duplicate IDs,
status polling, and cancellation must not hide extra credential-bearing work.
Use origin/driver barriers to establish receipt or stream progress before
injecting cancellation. A fixed sleep is not evidence that dispatch occurred.
Do not require a common chunk size or scheduler ordering between consumers.

Two sessions using one account establish session isolation only. The later
cross-account case still needs two enrolled accounts with distinct credentials
and independent positive controls. Likewise, zero upstream receipts do not
prove zero secret resolution: the host-supplied, counted-store fixture must
separately verify the pre-resolution policy and approval boundary.

After each scenario, revoke remaining sessions and stop owned work within a
deadline. Record any missing public cancellation, revocation, or shutdown
contract as follow-up W8 work; do not give the example private engine access
to simulate a supported lifecycle. This first delivery does not close approval,
rotation, shared quotas, remote MCP/TCP, full shutdown, or confinement gates.

## Independent builds and dependency checks

Build the consumers outside the root Cargo workspace, without inherited
workspace dependencies, root feature unification, or neighboring repositories.
An isolated local Git checkout at an exact commit can supply package sources;
publishing or contacting a registry with new packages is unnecessary. Document
the tested revision and lockfile. A future external Git dependency pins a
revision, not a moving branch.

Each acceptance consumer has its own explicit manifest and committed lockfile;
the production workspace retains its root lockfile. Local path dependencies
may refer to the checkout, but consumer manifests must not inherit root
workspace dependencies. Run minimal normal builds separately from tests so
development dependencies and test-only features cannot mask missing exports
or feature declarations. Verify the resolved workspace root for each consumer.

Check resolved normal/build dependency closures, not only direct manifests:

- The agent client cannot pull in `aap-engine`, `aap-auth`, `aap-secrets`,
  `aap-config`, native stores, trusted upstream connectors, or private remote
  MCP custody. Ordinary client networking and public protocol types are allowed.
- The embedded broker does not depend on `aap-daemon`. A custom-store consumer
  does not link SQLCipher or Apple frameworks merely because the workspace
  contains those backends.
- `aap-test-support` and fixture stores are development-only, never selectable
  production backends. A test-enabled build is not evidence of a safe release
  dependency closure.
- Minimal supported feature sets and the declared MSRV are checked separately
  from a full workspace build. Do not add a feature that disables authorization,
  redaction, or TLS verification to make a consumer compile.

The SQLCipher embedding fixture documents its native linkage requirements.
If a host already links an incompatible SQLite library, report the conflict;
do not silently switch to plaintext SQLite or a different credential store.
Using the external daemon remains a supported way to avoid native linkage
inside the host application.

Run these checks for the pinned compiler and declared MSRV. Evidence must name
the consumer manifest, lockfile, feature set, source revision, and commands.
Record formatting, normal compilation, tests, and dependency-boundary results
separately. A passing root-workspace test run does not cover independent
consumers, and adding CI jobs does not establish that remote CI has passed.

## Ordered W8 delivery and exit gate

1. Add the independent client and embedded SQLCipher fixtures for the existing
   provider/website paths using [R1–R8](#first-providerwebsite-delivery); identify
   any missing public lifecycle contracts. Record each case on both paths and
   for both login encodings, marking unsupported or unrun variants explicitly.
2. Add the host-supplied adapter fixture, dependency closure checks, and shared
   approval/store/observation failure scenarios.
3. Extend the shared suite with remote MCP and the completed TCP path as their
   W7 capabilities become available. Do not report W8 complete without them.
4. Add cross-adapter quota, shutdown, and race checks, then repeat the actual
   [confinement suite](deployment.md#confinement-acceptance-suite) for every
   supported agent-facing attachment.
5. Record runnable commands, exact scope, toolchain/dependency evidence, and
   remaining platform exclusions in the delivery tracker and operator guide.

Reusable API compilation and semantic equivalence do not prove OS confinement.
The sandbox fixture remains a distinct mandatory gate for the complete Linux
proof. Likewise, Linux examples cannot establish native Keychain compatibility.
Neither gate may be marked passed because the corresponding test was skipped.

A real Goose integration, signed human-approval transport, native macOS runtime
validation, package publication, and product renaming remain separate work.
This plan adds no runtime dependency, new crate, or new upstream authentication
protocol.
