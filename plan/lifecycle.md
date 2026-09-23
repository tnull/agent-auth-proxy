# Broker closure and bounded shutdown

Status: proposed W4/W8 lifecycle contract. This defines required behavior, not
an implemented shutdown API or evidence that native work has stopped. Keep the
existing project names and crate boundaries; no new dependency is required.

## Two distinct responsibilities

Revoking authority and finishing resource cleanup are different events. The
trusted host needs both an irreversible broker-wide closure operation and a
bounded way to establish what has actually stopped. A successful closure alone
MUST NOT be described as complete shutdown.

| Phase | Required guarantee | Not guaranteed by this phase alone |
| --- | --- | --- |
| Accepting | Sessions and operations may be admitted under current policy | Eventual approval, dispatch, or completion |
| Closed | No new authority is admitted; all existing sessions are revoked and cancellation is initiated | Caller-owned futures have been dropped, sockets have closed, or native calls have returned |
| Drained | Tracked work and resources within the declared ownership boundary have stopped | Undoing remote effects, erasing all memory copies, or stopping unrelated users of a shared store |
| Drain deadline exceeded | Authority remains closed; incomplete cleanup is reported safely | Successful shutdown or permission to resume old work |

These are conceptual lifecycle states, not additions to the agent wire schema.
Draining may continue after its deadline, but closure never reverses. Resuming
service requires a newly constructed broker and fresh sessions. Repeating or
concurrently requesting closure is safe and does not reset deadlines or revive
authority. No Rust signature or task-tracking mechanism is selected here.

## Admission and revocation boundary

Closure has one ordering point shared with session admission. A concurrent
session creation either precedes closure and is included in its revocation,
or is rejected. A session returned by a racing call may already be revoked;
there must be no live session that escaped the closure snapshot.

Every clone and frontend retains the same authority state. This includes
provider routes, direct HTTP, inspected CONNECT, MCP tools, pending TCP handles,
and embedded callers. After closure, new agent operations, discovery, credential
preparation, and status access through the revoked session return the existing
`session_invalid` outcome. A local adapter may instead report attachment loss
when its socket has already closed. Neither result permits replay. Trusted
diagnostics may retain bounded safe terminal evidence outside that session.

Revocation MUST invalidate placeholders, private cookie/token contexts, pending
approvals, and upstream MCP session bindings. Late approvals, store results,
network responses, and cleanup callbacks cannot restore them. Notify all
affected sessions even if one cleanup step fails; a failure is reported without
reopening admission or silently leaving other sessions authorized.

An independent broker is a separate authority domain, even if it shares a
store or transport object. Closing one broker MUST NOT lock the shared store,
cancel the other broker's work, or change its grants. The host decides when an
exclusively owned backend can be locked or released.

## Races with credential use and dispatch

Preparation is not permission to dispatch. Check current authority before
starting credential resolution and when accepting its result. Closure ordered
before resolution admission prevents that lookup. A native lookup already
started may finish afterward; its result must be discarded, never injected,
exported, or committed into a usable authentication context.

The final dispatch commitment must be ordered with closure. If closure wins,
no new dispatch is permitted, including cookie-authenticated work that never
reads a password. If dispatch wins, initiate cancellation and conservatively
record uncertainty unless an existing terminal outcome is already known.
Bytes already handed to a transport or operating system can still reach the
origin afterward. Local closure is not a resource-side rollback or a promise
that receipt occurs before the closure call returns.

Do not hold a broker-wide admission lock while waiting for approval, native
store access, network I/O, or observation delivery. Cancellation must remain
available while those operations are pending. Generation checks on private
state writeback prevent an earlier response from recreating revoked contexts.

Never rewrite a completed operation into a cancellation. Work cancelled before
dispatch remains non-dispatched; possibly dispatched work follows the common
`outcome_unknown` contract. Retain deduplication and terminal state for the
period required by the common protocol, until session teardown; cleanup cannot
make an old ID reusable through a revoked session.

## Completion and private-state publication

Receiving an upstream success is not the same as completing a local operation.
The engine must finish the profile's response validation and redaction, accept
required ending records, and establish that the operation still has authority
before publishing success or reusable authentication state. This is a local
consistency boundary, not a transaction with the upstream resource or collector.

Treat response-derived cookies, CSRF mappings, and upstream MCP session tokens
as provisional until that boundary. They may be used internally to sanitize the
same response and prepare an explicitly permitted redirect within the same
exchange, but other operations cannot use them. Every redirect still requires
its own destination, dispatch, and observation checks. Provisional state counts
toward the same finite context/buffer budgets as committed state.

Completion has one ordering point with session/broker revocation and generation
retirement. Recheck operation cancellation, expiry, policy/context generation,
and the store validity required by the backend contract. A prior check before
response parsing or an observation wait is insufficient. Backend revalidation
may happen before this boundary; do not claim atomic exclusion of an external
Keychain edit that the backend cannot provide.

| Ordering | Required local result |
| --- | --- |
| Completion wins | Publish the validated context transition and terminal operation state consistently; later revocation invalidates the context but does not rewrite the completed operation |
| Revocation/cancellation wins | Discard provisional state; never publish a successful ending or usable context; retain the appropriate cancelled or uncertain outcome |
| Required recording cannot accept completion | Do not publish successful completion or reusable state; stop delivery and report an incomplete outcome without retrying upstream work |
| Best-effort recording loses completion | A valid completion may still commit; report observation loss under the existing gap contract, never invent collector acceptance |

Publishing a successful ending must not precede committing the corresponding
operation/context transition. Conversely, accepted required recording must be
secured before committing that transition. Capacity checks or reservation may
precede the short authority commitment, but no approval callback, native store
call, network delivery, or collector wait may run while holding its exclusion
boundary. Reservations must be bounded and released on rejection/cancellation.
This specifies behavior without choosing a Rust signature or locking primitive.

For a bounded group of ending records, failed completion must not leave some
views reporting success while others report cancellation. Abandoning a proposed
success batch must not evict previously accepted records or manufacture a gap
for records never committed. Genuine best-effort drops and required-recording
failures retain their existing explicit loss semantics. If even an incomplete
ending cannot be recorded, report recording loss; do not replace it with a
successful ending to make the stream look closed.

The boundary also applies to local-only operations that publish placeholders or
advance protocol state. They need no invented upstream dispatch: cancellation
before publication remains non-dispatched. Invalidation is different from
creation of authority. Logout, revocation, and deletion of local context state
must take effect even when observation is unavailable; they are never deferred
until a success record can be delivered.

An HTTP status, a final response chunk, or a completed broker operation does not
prove the agent received or processed the response. Supported streaming may
release already checked chunks before local completion; subsequent failure is
an incomplete stream, not a retraction of those chunks. Dropping a body before
completion discards its tentative authority. Dropping it after completion does
not roll back remote effects or replay the operation. Both cases remain subject
to the separate resource-drain requirements below.

## Resource ownership and drain contract

The embedding host owns its listeners, execution tasks, response consumers,
and runtime. The engine and each adapter must document the tasks, connection
drivers, permits, and buffers they create and expose a way to stop and account
for them. Dropping a broker variable is not a substitute for explicit closure
while session clones or responses remain alive.

A held, unpolled response body is a mandatory shutdown case. Waking its
cancellation token alone does not prove that its connection driver or socket
has stopped. The supported composition must either cancel those resources
independently or require the host to drop/drive the owned body and confirm
cleanup. State that obligation explicitly; never report drained while tracked
network work still runs. Apply the same rule to pending TCP attachments,
half-closed relays, MCP streams, and dropped execution futures.

Native calls that cannot be interrupted require bounded outstanding capacity
and a bounded caller wait. Cancellation of an async wrapper does not establish
that the native call has ended. Report such work separately, discard its late
results, and do not claim that store locking erased an in-flight secret copy.
A timed-out native task must retain safe ownership until it actually finishes.

The initial host shutdown budget is two seconds from initiation, measured with
a monotonic clock. This is a proposed cooperative cleanup budget, not a promise
that arbitrary native work can be terminated. All phases share the deadline;
per-session waits, terminal delivery, observer draining, and store cleanup do
not each receive a new two seconds. A caller may supply a different finite
budget under its deployment policy. Zero never means unlimited.

The daemon and embedding example follow the same ownership sequence:

1. Close broker authority and stop admitting new host attachments. A request
   racing listener shutdown is still rejected by the closed broker.
2. Cancel pending approval/execution and invalidate private contexts. Stop
   owned streams; cancel or drop response consumers and join owned tasks.
3. Record an incomplete ending for each unfinished stream through the configured
   observation boundary, without duplicating or rewriting an existing ending.
   Deliver retained terminal evidence within the remaining budget; do not wait
   indefinitely for a slow collector or invent a successful delivery.
4. Release listeners and owned resources. Lock/release an exclusively owned
   store only under its backend lifecycle contract; report incomplete native
   work or locking rather than silently treating it as drained.
5. Return a safe outcome distinguishing closure, confirmed drain, timeout,
   and cleanup failure. Keep authority closed in every case.

Collector failure must not prevent revocation. Preserve existing explicit loss
semantics when an ending cannot be recorded/delivered. Shutdown cannot dispatch
an extra upstream logout, token refresh, or MCP cleanup request merely to tidy
state after authority has been revoked. Local invalidation is always required;
remote effects and remote cleanup outcomes remain separate.

Successful reload is not reopening a closed broker. Prepare and validate the
candidate before committing a generation replacement. Publication and authority
retirement must be coordinated so there is no window admitting new work under
retired grants; drain the retired generation afterward. Failure before that
commit leaves existing authority unchanged, as specified by the catalog
contract. Failure in subsequent cleanup is reported as a committed reload with
incomplete cleanup, not a failed reload that supposedly left the old generation
active. It cannot restore old sessions or silently roll authority back.

## Acceptance cases and delivery order

Use controlled origins, counted store calls, explicit barriers, and independent
positive controls. Exercise both daemon and embedded paths where applicable.
Returning a local error is insufficient evidence that nothing was dispatched.

| Case | Required evidence |
| --- | --- |
| L1: admission race | Concurrent session creation and closure leave no usable session; every retained clone rejects further work; repeated closure is harmless |
| L2: approval race | Closing while approval is pending prevents resolution and origin receipt even after a late affirmative decision |
| L3: native completion | Close after a counted store call starts; complete it later; no credential injection, usable context, or upstream receipt follows |
| L4: dispatch boundary | Close before commitment and prove non-dispatch; separately close after a confirmed origin receipt and retain uncertainty without a retry |
| L5: active resources | Retained unpolled HTTP bodies, MCP streams, pending/connected TCP handles, and half-closed relays stop under the documented host obligations; verify actual task/socket termination |
| L6: private state | Authenticate first, then close; late login/MCP responses cannot restore cookies, tokens, placeholders, or upstream session bindings |
| L7: ownership isolation | Two brokers sharing a store work before closure; closing one leaves the other's permitted operations and store access functional |
| L8: partial failure | A stuck native call, blocked collector, or cleanup failure cannot keep other sessions authorized; total waiting is bounded and incomplete cleanup is reported |
| L9: restart and reload | Fresh generations reject old handles/approvals; invalid candidate configuration does not revoke the valid generation; retirement never resurrects old authority |

### L6 completion acceptance cases

Use barriers immediately before the completion commitment, not only before
network receipt. Test both possible orderings with independent positive controls
and count upstream receipts separately from local outcomes.

| Case | Required evidence |
| --- | --- |
| C1: website staging | Form and JSON login return sanitized data while new cookie/CSRF state remains unavailable to another exchange; successful completion alone enables the next protected request |
| C2: late website response | Revoke the session, close the broker, or retire its generation after the response arrives but before completion; no authenticated context reappears and no protected follow-up is sent |
| C3: late MCP handshake | Repeat for JSON and SSE initialization and initialized-notification responses; neither a private session token nor readiness becomes usable after retirement |
| C4: recording boundary | Required capacity failure prevents successful publication; best-effort loss permits otherwise valid completion with a gap; rejected success batches preserve earlier accepted records and coherent endings |
| C5: completion first | Complete a positive provider/login/MCP exchange, then revoke; terminal evidence remains completed, private state becomes unusable, and repeated IDs never redispatch |
| C6: local publication | Retire authority during placeholder issuance or local protocol work; no new live binding or successful local completion escapes, and no upstream dispatch is invented |

For all dispatched race cases, prove incomplete/uncertain local outcomes without
claiming non-execution at the origin. Include response-body abandonment and
cookie refresh/deletion failures: discarding a tentative update must not restore
an old jar as if upstream session state had rolled back. Run the applicable
cases through both daemon and trusted embedded paths before closing L6.

First deliver broker-wide admission closure and clone revocation (L1/L2/L7),
without advertising complete shutdown. Next prove dispatch/native-result races
and private-context invalidation (L3/L4/L6). Finally establish resource drain,
deadline/failure reporting, and daemon/embedded parity (L5/L8/L9). Add tests
before each behavior change; demonstrate regression failures on pre-fix code.

W4/W8 shutdown remains open until the ownership and drain cases pass, even if
closure tests succeed. Record any non-interruptible backend work explicitly in
the delivery evidence. No production approval UI, upstream challenge-response
scheme, process-global runtime, or new crate is introduced by this contract.
