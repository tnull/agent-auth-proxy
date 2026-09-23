# aap-engine

Trusted composition of session-scoped policy, approval, custody, observation,
and transport. Only `Broker` creates/revokes sessions. A session handle implements
the credential-free `AgentService`; an opaque session ID cannot create a handle.
The host supplies store adapters, resolver, transport, request inspector, and
optional asynchronous approval provider. No process-global configuration or
runtime is installed. Embedding this inside an untrusted agent is not isolation.

Implemented paths include API-key brokerage, authorized catalog discovery,
fake username/password issuance, and a bounded form/JSON website login through
protected cookie access. The standalone daemon exposes the same service over
its private local binding and owns configuration reload. MCP and optional
CONNECT adapters use the same session service and authorization pipeline.
Execution futures wait for approval asynchronously; independent status/cancel
calls remain usable. Dropping execution cancels preparation, or marks uncertain
delivery once dispatch starts. Response-body completion controls final status.
Repeated identical request IDs report existing state, never dispatch again;
changed bytes conflict. Results themselves are not retained for replay.

Finite ceilings currently include 64 live session handles per broker, a
one-hour session lifetime, 4,096 retained operation IDs and 8 MiB tracking per
session (64 MiB per broker), eight active dispatches per session, and sixteen
pending approvals with a shared 4 MiB retained-request ceiling. Approval waits
are capped at five minutes and operations at ten minutes/session expiry.
These are admission ceilings, not production capacity claims. Further quota,
expiry, restart/reload, and multi-thread race coverage remains part of W1/W4.

## Broker-wide authority closure

`Broker::close()` permanently stops session admission and revokes every live
session, including clones retained by other adapters. Creation racing closure
either fails with `SessionInvalid` or returns a session included in revocation.
Repeated/concurrent closure is safe. `Broker::is_closed()` reports admission
state, not successful resource cleanup. Restart requires a new broker.

Closure cancels all session signals before attempting their local cleanup. A
poisoned registry or session cleanup reports `InternalError`, keeps admission
closed, and does not skip cancellation of other sessions. Repeating closure
retries cleanup; it cannot repair poisoned state or promise full cleanup.
Independent brokers and shared backing stores are not closed or locked.

This synchronous operation is not complete shutdown. Hosts still stop their
listeners, cancel/drop execution futures and response bodies, and join owned
tasks with a finite deadline. In particular, an unpolled HTTP body can retain
its connection driver until the owner drives cancellation or drops it. Native
work may still finish later, and already dispatched effects cannot be undone.
TCP revocation closes the sockets and capacity owned by retained TCP handles;
that does not establish the broader drain contract for all adapters.
See the remaining [lifecycle acceptance gates](../../plan/lifecycle.md).

## TCP admission and connection ownership

The separate `Configuration.tcp_profiles` collection is validated at broker
construction and participates in session resource grants. A TCP-only grant
cannot execute HTTP or discover another resource's credential items.

The trusted `Session::admit_tcp` entry point registers one attachment without
DNS, store access, or connection work. Its ID shares the HTTP/issuance namespace;
duplicates return existing status without a second attachment. Owning and then
dropping the pending handle cancels the operation. `PendingTcp::connect` performs
separate connection-level approval, complete address admission, required opening
observation, shared capacity admission, and one attempt through the injected
`Configuration.tcp_connector`. No credential lease or store call is involved.
Existing approval providers deny connection consent unless they implement it.

Pending attachments are bounded to sixteen per session and 128 per broker.
TCP shares the eight active session slots and the sixteen/4 MiB approval budget
with HTTP; it additionally reserves one of 64 broker stream slots and 128 KiB
of an 8 MiB relay payload pool. Per-resource active limits apply independently.
Cancellation releases pending/connected reservations and closes owned sockets,
even if a caller retains an unpolled handle. Retained operation IDs still cannot
reconnect. Approval, preparation, idle, and lifetime deadlines do not extend when
a late future becomes ready; connection attempts have conservative uncertainty.

`ConnectedTcp` retains the socket privately and reports opening limits with the
remaining original lifetime. Its `relay` method immediately transfers a trusted
application attachment into engine ownership and returns a `TcpRelay` future.
Cancellation, revocation, drop, or a watchdog closes both directions and releases
capacity, even if that future is not polled. Successful writes refresh idle
time but never extend the original lifetime or a stalled opposite direction.
Actual accepted-prefix byte counts survive termination. Both orderly ends and
successful required terminal observation are needed for completion.

Payload observation records paired, ordered agent/upstream views with the
declared plaintext, opaque, or metadata-only inspection class. Conservative
placeholder suppression does not delay interactive bytes or modify application
traffic. Every chunk needs fresh required-observation admission, including a
fully withheld chunk. These TCP paths make no secret-store calls. Each relay
uses at most 16 KiB of core buffering per direction, leaving space in its
128 KiB reservation for framing buffers and redaction scratch.

The session's `AgentService::open_stream` now exposes the same ownership path
through runtime-neutral `stream::service` contracts. Its pending handle does no
connection work until explicitly consumed; duplicates return status, never a
replacement handle. The connected handle accepts a trusted `ApplicationIo`
adapter without exposing the upstream socket. Reads, writes, and directional
end callbacks remain distinct from the final relay result. The engine checks
callback byte counts and preserves fixed local framing failures; arbitrary
native errors remain private. No callback may reenter the same broker.
Pending/connected handles expose a stop-only `StreamAbort` capability and a
termination wakeup for independent adapter monitors. Neither permits a new
destination, replay, approval, or successful outcome. Stopping an already
committed operation cannot rewrite it.

The [HTTP adapter](../../docs/tcp.md) now supplies a daemon TCP endpoint using
these same handles: OPENED precedes payload, SEND_END is explicit, raw EOF fails,
and bounded final-control delivery is separate. Engine tests exercise that
adapter through real TCP with a spy asserting no store access. The agent client,
broader race/overload acceptance, and actual confinement remain pending.

## Remote MCP integration


The initial `Authentication::Mcp` path handles pinned initialization, initialized
acknowledgments, reviewed tool listing/calls, and bounded JSON/SSE responses over
the admitted HTTPS transport. Contexts are owned by one local session/resource
and its enrolled credential lease. Private upstream headers never become caller
headers; message validation runs before secret resolution. The local MCP tool
list is not dynamically expanded by remote tools.

Initialization is staged until the response is consumed successfully. Dropping
it invalidates that handshake; tooling cannot skip the initialized notification.
Custody is rechecked after response inspection, before body delivery, and at
completion. Rotation, observed access loss, failed secret preparation, rejected
trailers, and revoked/expired bindings prevent reuse. An uncertain call is never
replayed by a duplicate local operation ID, status query, or fresh handshake.

Provider, website, and remote operations share the bounded approval helper.
MCP approval includes an independent safe `context_id`, not the native session
header. Pending approval holds no newly resolved password. Context lifetime is
at most ten minutes, with a thirty-second handshake; both are capped by current
session/custody lifetime. Remote generations retain up to sixteen tombstones per
session and share the broker's sixty-four-context ceiling with website contexts.

Work uses the session's eight active slots; control messages have two additional
slots shared across remote contexts. Protocol reservations are bounded to 8 MiB
per session and 64 MiB per broker: twice the input length plus 64 KiB while
preparing, and six times the admitted response ceiling during response work.
Control replies have a narrower 64 KiB ceiling. Reservations cover simultaneous
encoded/transformed buffers, not a measurement of total process heap usage;
byte ceilings may admit fewer simultaneous operations than the slot ceilings.
These counters need further adversarial allocation/concurrency evidence before
the complete remote MCP gate can pass.

Server ping replies now use separate tracked child operations with independent
DNS, custody, control-slot, and required-observation admission. Their safe flow
IDs correlate to the parent without retaining private server IDs in operation
DTOs or telemetry. Initialization pings can use the provisional private native
session. A reply must receive an empty, trailer-free HTTP 202 acknowledgment;
unsafe or uncertain dispatched children invalidate the context.

Children have a two-second attempt deadline capped by the parent lifetime and
reserve 256 KiB of the shared protocol budget. A child cannot borrow the parent's
approval: an approval-required reply is skipped with a safe denial event,
without another human wait or secret read. Cancellation interrupts admission
as well as transport. The engine does not start a second client or retry loop.

Local `request.cancel` now also prepares a one-shot mapped MCP cancellation
child for dispatched tool work. Admitted `notifications/cancelled` messages
use the same local-first path. Unknown/completed MCP IDs need no store access;
pending work stops without a notification. The local operation is cancelled
before any child admission or I/O, and status remains available while a bounded
cleanup attempt runs. Child permission failure does not undo local cancellation.
Initialization is never sent an MCP cancellation notification: local cancellation
invalidates its context immediately, including a response not yet consumed.
New MCP notification submissions still share normal input/tracking admission;
the existing-ID `request.cancel` endpoint allocates no new parent operation.

An enrolled empty endpoint DELETE now closes local authority before any store
access or remote work. Its optional authenticated child has the same current
policy/custody/observation checks and two-second bound. No native session,
changed/locked custody, missing capacity, or approval requirement skips that
child. A local HTTP 204 reports closure with `x-aap-remote-cleanup` equal to
`confirmed`, `not_supported`, `skipped`, or `unknown`; it never reports business
rollback. Only empty, safe upstream 200/204 or 405 acknowledgments establish
confirmed or unsupported cleanup. Reinitialization is excluded while the
attempt is owned, with the barrier released on completion, timeout, or drop.
Repeated closure does not release someone else's barrier or dispatch again.

This is not the complete remote gateway.
Actual daemon/bridge/CONNECT fixtures now exercise JSON/SSE, account/session
isolation, control children, cancellation, cleanup, and no-replay uncertainty.
Protocol-specific observation metadata and broader race/overload coverage
remain pending. These tests must not be described as completing W7.

## Password-manager sessions

An optional `SessionOptions.items` list further narrows a resource grant to
explicit enrolled item aliases. `None` permits the items of the granted
profiles; an empty list permits none. This applies to provider keys as well as
website discovery and login. Input messages cannot override the host's grant.

Search returns at most 50 safe catalog records per page. Its opaque cursors are
session/query-bound, with at most 64 retained cursors; substring filtering is
case-sensitive. Preparation is metadata-only and pins the credential lease
without resolving a password. Issuance and execution share operation-ID
uniqueness, retained-count, and byte budgets. Duplicate issuance returns the
same active placeholders; changed input conflicts, pending work reports
`auth_in_progress`, and terminal failure/revocation cannot mint new authority.

At most 16 contexts are retained per session and 64 per broker, including
tombstones until session teardown. Context lifetime is at most ten minutes,
capped by the session and store metadata lease. Expiry/logout/version loss
invalidate fake credentials and jars. Logout is local and idempotent; remote
logout is explicitly unsupported. Metadata/version checks are asynchronous,
bounded, and repeated on use; no native invalidation-notification guarantee is
implied. Local logout does not revoke other contexts for the same item; learned
store access/version loss invalidates that session's contexts for the item.

## Supported website profile

The fixture uses JSON login metadata with virtualized CSRF, a form or JSON
credential POST, and JSON protected responses, all bounded to 256 KiB and fully
inspected before delivery. Login success needs both the profile's explicit JSON
value/status and its expected private cookies. HTTP 200 or a cookie alone is
insufficient. Ordinary nonempty website request bodies must be JSON; unsupported
content types, streaming website routes, and undeclared redirects fail closed.
Model output still streams on the separate provider path.

An optional `post_login_redirect` is the exact canonical, query-free HTTPS URL
of a separately enrolled same-origin GET route. It requires `success.status: 303`
and the usual explicit JSON success evidence plus expected private cookies in
that login response. Only a matching absolute or origin-relative Location is
accepted; the engine returns the safe canonical Location without following it.
It refuses the login page/POST target as a destination, other 3xx statuses,
cross-origin/undeclared targets, ambiguous Location headers, and known-secret
echoes in the destination. Login response bodies remain bounded sanitized JSON.
Generic HTML/empty-body redirect logins and 302 semantics are not supported.

Consume the successful response to completion before issuing a separate GET
with the same context. That operation receives its own ID, policy, approval,
DNS and store-version checks; no password body is carried forward. Dropping
the response still invalidates uncertain context state. Redirect permission
does not authorize an unseen next hop or confer permission to other resources.

One exchange per context is admitted at a time. Login attempts are limited to
five per item/session and twenty per item/broker in a ten-minute window;
issuance/logout cannot reset these counters. Approvals bind the immutable request
and lease; no password is resolved while waiting. Protected cookie operations
still enforce global/session/action and item `always` approval, with fresh store
revalidation even though they need no password resolution. Native lock and
uncertain delivery invalidate local authority rather than trigger a retry.

Private redaction patterns are retained only within bounded context state to
suppress later ordinary echoes, including after cookie/CSRF rotation. They are
cleared on observed context invalidation; this is not a memory-erasure promise
or defense against a deliberately malicious recipient's covert encoding.
Website responses are recorded in a separately placeholder-redacted view before
agent delivery; the agent still receives the fake values needed for submission.

The recorder is a bounded local memory acceptance channel. Required recording
must succeed before dispatch and before releasing each sanitized response
chunk. It is not a durable audit log or a detector approval. Observation export
is provided by the daemon; the complete planned envelope/views remain pending.
