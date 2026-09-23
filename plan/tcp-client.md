# Credential-free TCP client delivery plan

Status: proposed next W7 integration step, not completed client support. Keep
the existing names. This document refines the client side of the
[local TCP binding](tcp-binding.md) without changing its wire format, introducing
an authentication protocol, or granting the client access to credentials.

## Responsibility and public contract

Implement the stream operations on `DaemonSessionClient` in `aap-client`, using
the shared contracts in `aap-types`. The client connects only to its host-provided
session attachment. It never resolves the resource, dials an upstream address,
loads trusted configuration, or imports the engine or a store backend.

The daemon remains authoritative for policy, approval, budgets, observation,
upstream effects, and retained operation state. Client validation protects local
callers from malformed responses and accidental misuse; it is not a substitute
for daemon checks against a malicious agent. A resource alias or operation ID
never authorizes a new attachment by itself.

Use the same owned admission, pending, connected, and relay interfaces as an
embedded session. Preserve these observable distinctions:

| Result | Meaning for the caller |
| --- | --- |
| Existing operation | Safe retained status only; no stream attachment or replay |
| New pending attachment | Validated HTTP upgrade; upstream opening may still be pending |
| Connected stream | Validated `OPENED` metadata for this exact operation and resource |
| Terminal record | The daemon's validated final result, separate from application end-of-direction |
| Local delivery error | No complete usable result; retained daemon status may differ |

The remote adapter cannot promise that the daemon waits for the caller to poll
its pending handle before starting connection work. The daemon may proceed as
soon as it sends the upgrade. Delayed polling must not restart deadlines, issue
another open, or imply that no upstream connection has occurred. Admission is
not human approval, and `OPENED` is not approval of future application actions.

## Opening and response validation

Validate the request locally, then send exactly one opening request on one
session connection. Never automatically retry an ambiguous write, use a new ID,
follow a redirect, attach to an existing operation, or fall back to another
proxy or direct networking. Keep the original ID available to the caller for
independent status/cancel requests.

Bound the response header section to 16 KiB and 32 fields, and non-upgrade JSON
to 16 KiB. These are client-side ceilings, not permission to enlarge the opening
request limits. Reject ambiguous or duplicate framing and singleton control
headers before normalization can hide them. In particular:

- Accept only HTTP/1.1 `101` with the expected single `Connection: upgrade` and
  `Upgrade: aap-stream/1`, and no Content-Length or Transfer-Encoding.
- For duplicate-operation results, require the existing-operation marker,
  matching request ID, strict status JSON, and the specified 200/202 distinction.
  Do not turn that result into a fresh pending handle.
- For safe errors, require the existing local error envelope and marker. Other
  statuses, redirects, unexpected informational responses, and malformed
  envelopes are protocol failures, not application payload.
- Do not maintain cookies, accept authentication challenges, or send caller
  authentication headers on this attachment. Native store identifiers and
  upstream credentials have no place in any client response.
- Preserve bytes read beyond a valid 101 header as bounded frame input. A
  coalesced `OPENED` must not be lost or mistaken for an HTTP response body.

Before a complete `OPENED`, consume only valid daemon control frames. `PENDING`
is optional; its absence is not failure. Validate request IDs, resource binding,
state transitions, and narrowed limits using the shared frame contract. Do not
read or queue application output for transmission while approval is pending.

## Duplex ownership and completion

One owner controls the attachment throughout pending, connected, and relaying
states. Moving between those states transfers ownership; it does not clone a
stream, create a second connection, or leave an unowned background operation.
Cloning the session client may issue independent operations but cannot clone an
existing stream attachment.

Keep application payload and framing separate. Only DATA payload reaches the
application, and only application bytes become outbound DATA. Preserve binary
octets, ordering, and both half-close orders. A local application end becomes
`SEND_END`, not a shutdown of the attachment's write direction. Daemon
`SEND_END` ends inbound application delivery while leaving outbound work and
terminal controls available.

Use bounded incremental framing and backpressure in both directions. The
client's retained payload is capped at 64 KiB per direction, with 64 KiB total
control/parser memory, counting read-ahead and copies. These are separate from
the daemon's reservations; they cannot enlarge server limits. Validate declared
lengths before allocating payload, enforce negotiated byte/frame limits across
all chunks, and keep no approval-time application queue or disk spool.

Completion has two facts: the daemon's terminal outcome and delivery to the
local application. The daemon's byte counters describe its successful writes,
not consumption by the client application. Reporting complete local delivery
requires an orderly completed terminal result and delivery of preceding
admitted inbound payload and its directional end. An abnormal terminal remains
a valid reported outcome, not a claim of complete delivery. If application
delivery fails, report local failure even if a received or subsequently queried
daemon status says `completed`.

Bare EOF, truncated frames, impossible counters, wrong IDs, controls in the
wrong state, or missing TERMINAL never imply success. A status query cannot
recover lost payload or replace a missing stream result. Do not fabricate a
daemon terminal record from local byte counts or an application callback error.

## Cancellation and phase deadlines

Dropping pending/connected ownership or the relay future closes the attachment
and stops local tasks and payload reads. The stop-only abort capability must
wake blocked local work, including a task waiting to write. It does not claim
that the daemon has already observed the close, that remote effects were
undone, or that its local reason became the daemon's final cause.

Explicit cancellation and status use separate bounded connections through the
same session client. Neither may wait behind the stream's payload queue or
require its reader to drain. Local drop needs no asynchronous network cleanup
to complete; callers needing confirmation use the separate cancel/status path.

Keep timeout phases distinct from the ordinary HTTP response timeout:

| Phase | Required client behavior |
| --- | --- |
| Session connection and HTTP handshake | Bounded connection and complete-response waits; ten seconds for each, with no approval wait before 101 |
| After 101, before OPENED | At most 310 seconds for optional approval plus preparation; earlier failure/terminal controls stop the wait |
| After OPENED | Anchor the local lifetime ceiling when OPENED is first validated; delayed polling or handle transfer cannot restart it |
| Payload delivery | Bound inactivity and each blocked direction using the negotiated limits; controls and opposite-direction progress cannot preserve a stalled write indefinitely |
| Final outcome | Allow the binding's bounded terminal-delivery phase; EOF without its complete record remains incomplete |

The daemon owns the authoritative monotonic deadlines. Client watchdogs bound
local resource use; receipt of remaining durations cannot extend server
authority. PENDING never restarts the overall pre-opening ceiling. Failure to
receive a terminal record within a local deadline is a delivery error, not proof
that the daemon expired or denied the operation. Check expiry before accepting
ready results as well as while awaiting I/O; ready data must not renew a deadline.

## Ordered implementation and acceptance

Add no production crate or credential-custody dependency. Reuse the existing
HTTP, framing, and async stack; justify any new direct dependency on an already
present parser at the adapter boundary. Keep concrete Rust signatures and
internal scheduling choices within the owning crates.

1. Test opening responses with a controlled session-socket peer: valid upgrade,
   existing status, safe errors, duplicate/ambiguous headers, oversized input,
   wrong IDs, and HTTP/frame read-ahead. Count connections and submitted opens.
2. Add the owned pending/connected lifecycle and phase deadlines. Cover optional
   PENDING, denial, delayed polling, drop/abort in every phase, and a terminal
   record arriving before OPENED. Every case must make at most one opening
   request and no direct upstream connection.
3. Add bounded duplex delivery. Exercise each header/payload split, coalesced
   frames, binary payloads, concurrent directions, both half-close orders,
   partial writes, and blocked application callbacks. Check exact application
   bytes, retained-memory limits, local failure, and daemon counters separately.
4. Use the actual daemon and TCP fixture through `DaemonSessionClient`, not a
   hand-written test client. Prove observation, status/cancel responsiveness,
   duplicate-open behavior, and zero store calls. Inject lost 101/OPENED/TERMINAL
   delivery and a reset after upstream acceptance; assert no reconnect/replay.
5. Run the shared embedded/client cases in [reuse](reuse.md), verify the client's
   resolved dependency closure, and rerun the actual confinement suite for this
   attachment. Only then close the corresponding W7/W8 gates.

Use deterministic fixture barriers for races and clock control for deadline
tests. New behavior starts with failing tests; regression guards must fail on
the pre-fix implementation for the intended assertion. Parser/unit passes do
not establish real daemon integration, isolation, or complete TCP coverage.
