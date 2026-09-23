# Local TCP stream binding, version 1

Status: W7 wire contract. Pure DTO/framing validation, trusted engine relay,
and the runtime-neutral service seam are implemented. Session upgrade and
agent client integration remain pending. This binds
[`stream.open`](tcp.md) to the existing session attachment. It changes neither
upstream authentication nor the credential-store interface. Project names and
the provisional protocol token can be renamed together before release.

## Transport choice and authority

Use HTTP/1.1 Upgrade on the session's existing Unix-domain socket, followed by
a length-delimited binary protocol named `aap-stream/1`. One connection owns
one stream operation. No second socket, bearer attachment token, WebSocket
dependency, multiplexing, resumption, or additional MCP tool is introduced.
The HTTP upgrade mechanism permits switching protocols on an existing
connection; the upgraded protocol must still satisfy the original request.
[RFC 9110, section 7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)

This is a local application binding, not an upstream wire protocol or registered
public protocol claim. Only the host-bound session listener exposes it; operator
listeners, provider mounts, ordinary forward requests, and inspected CONNECT
connections do not. `Host: aap.local` is routing validation, not authentication.
The request names a resource alias, never an address or another session.

## Opening request and HTTP responses

The client sends `POST /aap/v1/stream/open` with exactly these requirements:

- HTTP/1.1, origin-form path, no query, and a single `Host: aap.local`.
- One `Connection` field containing only the `upgrade` token, and one
  `Upgrade: aap-stream/1`. Compare protocol names and HTTP tokens without case
  sensitivity; the version is exactly `1`. Do not negotiate other versions.
- One `Content-Type: application/json` without parameters, and one decimal
  `Content-Length` matching the entire body. The body is at most 16 KiB.
- No transfer/content encoding, trailers, `Expect`, cookies, authentication,
  forwarding, or proxy-context headers. Apart from the five required fields,
  only one bounded `User-Agent` is allowed and has no effect on authority.
- At most 8 header fields and 16 KiB for the request line/header section, with
  a ten-second deadline to receive the complete HTTP request. Reject conflicting
  or duplicate singleton fields before interpreting the operation.

The strict UTF-8 JSON body has exactly two string fields:

```json
{"request_id":"AAAAAAAAAAAAAAAAAAAAAA","resource":"echo-fixture"}
```

The request ID follows the [common contract](protocol-common.md); the example
is synthetic. Resource aliases use the catalog's existing validation. Unknown
or duplicate members, non-string values, and any payload/destination/limit
overrides are invalid. JSON depth is at most 8 and structural tokens at most
128. Equality for duplicate operations uses the decoded operation kind, ID,
and resource, not whitespace or object-member order.

Before upgrading, validate the session, resource type, grant, operation identity,
and local attachment/tracking capacity. Atomically register one frozen operation
and its sole attachment. Do not resolve credentials or start an upstream
connection as part of the HTTP handshake. Existing-ID status lookup does not
need a fresh stream/approval reservation; frozen operation kind participates
in conflict detection against HTTP requests and credential issuance as well.

| Outcome | HTTP behavior |
| --- | --- |
| New admitted attachment | `101 Switching Protocols`, `Connection: upgrade`, `Upgrade: aap-stream/1`; no HTTP body, Content-Length, or Transfer-Encoding |
| Same ID and same frozen operation | Existing `OperationStatus` JSON, `x-aap-operation-state: existing`, HTTP 202 while pending or 200 when terminal; no upgrade or second attachment |
| Same ID with different operation/resource | Existing safe `request_conflict` error binding; no upgrade |
| Malformed, unauthorized, unsupported, or over capacity | Existing safe local HTTP error binding; no upgrade or upstream dispatch |

Non-upgrade responses close the connection. Clients never interpret their body
as stream data, follow redirects, retry an open automatically, or fall back to
CONNECT/direct networking. A malformed or missing upgrade response is failure.

HTTP 101 admits the local attachment, not the upstream connection. Afterward
the daemon completes approval, DNS/address checks, observation admission,
shared upstream-capacity admission, and dialing through the engine. This work
is cancellable and visible through `request.status`. The first frame is either
`PENDING`, `OPENED`, or `TERMINAL`; the original operation is never resubmitted.
The daemon finishes writing `OPENED` before forwarding application bytes in
either direction. An upstream greeting cannot overtake the opening control.

The client sends no bytes after the HTTP request until `OPENED`. Reject already
buffered trailing/pipelined input at handoff; monitor input during approval
without allocating an application-payload queue. Forbidden input detected
after dialing has begun still requires an uncertain outcome, not a claim that
the peer saw no connection. No application bytes are forwarded before opening.

## Binary frames

Every frame is a one-byte type, an unsigned four-byte big-endian payload length,
and exactly that many payload octets. Length excludes the five-byte header.
There are no flags, padding, stream IDs, compression, or implicit text encoding.
Validate type, direction, state, length, and remaining budgets before allocating
or accepting the payload. A larger declared length cannot trigger a large read
or allocation. Socket read boundaries do not delimit frames or messages.

| Type | Name | Sender | Payload and validity |
| --- | --- | --- | --- |
| `0x01` | `PENDING` | Daemon | JSON; at most once before opening, only for pending approval |
| `0x02` | `OPENED` | Daemon | JSON; exactly once on successful connection, before any data |
| `0x03` | `DATA` | Either | 1–32,768 binary octets; only after opening and before that sender's send-end |
| `0x04` | `SEND_END` | Either | Zero bytes; at most once per sender, after opening |
| `0x05` | `TERMINAL` | Daemon | JSON; one terminal outcome, then the attachment closes |

Unknown types, wrong-direction controls, duplicate controls, zero-length data,
nonempty send-end, data after send-end, and incomplete frames fail the binding.
Never skip an unknown frame or reinterpret invalid framing as raw TCP. A client
cannot send a terminal-success claim or an approval decision.

Control JSON uses the same strict parsing rules as the opening body, with a
16 KiB ceiling per frame. Fields below are required; unknown fields/enums are
invalid in version 1. Numbers are nonnegative JSON integers, never floats or
numeric strings. Limits may be narrowed by policy, not enlarged by either peer.

`PENDING` contains `request_id` and `expires_in_ms`, the remaining approval wait
as measured when emitted, at most 300,000 ms and capped by relevant lifetimes.
It exposes no approval token, approver identity, native store reference, or UI
URL. A delay in receipt cannot extend the daemon's monotonic deadline.

`OPENED` contains `request_id`, `resource`, `max_data_bytes`, `send_limit`,
`receive_limit`, `idle_timeout_ms`, `remaining_lifetime_ms`, `inspection`, and
`observation`. Send/receive are from the agent's perspective. Initial ceilings
are 32,768 bytes per DATA frame, 33,554,432 bytes per direction, 60,000 ms idle,
and 600,000 ms remaining connected lifetime. Inspection is the truthful
`plaintext_bytes`, `opaque`, or `metadata_only` classification defined in
[the relay contract](tcp.md); observation is `best_effort` or `required`.
Report only aliases and safe policy facts, not internal resolved addresses.

`TERMINAL` contains `operation`, `cause`, `sent_bytes`, and `received_bytes`.
`operation` is the existing `OperationStatus` object with `request_id`, terminal
`state`, and `status: null`: TCP has no upstream HTTP status. Counters exclude
framing and count application bytes successfully written by the daemon toward
the upstream socket or local attachment, respectively. They do not prove that
the receiving application processed those bytes; failed writes can leave
additional remote effects uncertain. Partial writes count their accepted prefix.

The closed set of causes is `orderly_end`, `cancelled`, `session_ended`,
`policy_changed`, `approval_denied`, `approval_timeout`, `interaction_unavailable`,
`observation_unavailable`, `capacity_exhausted`, `upstream_unavailable`,
`invalid_frame`, `limit_exceeded`, `timeout`, `attachment_lost`, or
`internal_error`. No free-form error text or upstream payload enters a control
frame. The cause explains termination; it cannot override dispatch uncertainty.

Minimal byte fixtures, with spaces only for readability:

```text
DATA containing ff 00 0a: 03 00 00 00 03 ff 00 0a
SEND_END:                04 00 00 00 00
```

## Half-close, cancellation, and completion

```text
POST -> 101 -> [PENDING] -> OPENED -> bidirectional DATA / SEND_END -> TERMINAL
              \---------- failure before OPENED -------------------> TERMINAL
```

Either sender can end first. Agent `SEND_END` drains only already admitted
outbound bytes and shuts down the upstream write direction. Upstream orderly
EOF drains already admitted inbound bytes and produces daemon `SEND_END`.
The other direction remains usable, including a response generated only after
the agent's send-end. This reflects TCP's independent directional closure.
[RFC 9293, section 3.6.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1)

Do not use local socket EOF as send-end: the attachment must remain open to
carry controls and the final result. A FIN, reset, partial frame, or disconnect
without a complete terminal record is incomplete delivery. An explicit
`SEND_END` carries the application half-close; it does not close the attachment.

Cancellation uses the existing status/cancel HTTP endpoints on a separate
connection to the same session socket. There is no in-band cancel frame that
can become trapped behind queued payload. Dropping the stream handle closes
its attachment and cancels nonterminal work; it never detaches a task that can
later dial after approval. Cancellation/expiry/revocation stop both directions
without flushing remaining application payload. Required observation failure
has the same fail-closed forwarding behavior.

`completed` with `orderly_end` requires both orderly application ends, drained
admitted data, and successful required recording. It means transport-level
completion, not business success. Before dialing, failure can be denied,
expired, cancelled, or failed under the common lifecycle. Once connection
initiation has started, an abnormal end is `outcome_unknown`, even with zero
payload counters. An upstream accept or greeting can already have effects.

Commit terminal engine state once; a later cancellation or failed delivery of
the terminal frame cannot rewrite it. If the terminal frame is missing, the
client reports incomplete local delivery and may query retained status without
reattaching. Even a retained `completed` state cannot recover lost payload or
prove that the client consumed it. Never synthesize success from bare EOF.

Bound terminal transmission to two seconds and release all socket/buffer
resources afterward. If a partially written DATA frame prevents clean framing,
close the attachment instead of inserting a control frame into its payload.
Control reservation cannot overcome a peer that refuses to read; retained
status is the recovery path, not a promise that every terminal frame arrives.

## Parser, capacity, and scheduling requirements

The [relay budgets](tcp.md#bounds-and-backpressure) apply without resetting at
frame boundaries. Additional binding limits are:

| Budget | Ceiling / behavior |
| --- | --- |
| DATA frames | 65,536 per direction; tiny frames cannot create unbounded parsing/event work |
| Control/parser memory | 64 KiB per attachment, separate from the 128 KiB relay payload budget; includes HTTP read-ahead, decoded metadata, and control serialization |
| Attachments not yet opened | 16 per session, 128 per broker; pending approvals also consume their shared approval budgets |
| Local session connections | 32 total, at most 28 admitted work connections; four slots reserved for bounded classification and status/cancel servicing |
| HTTP handshake | 10 seconds, including full metadata body; no approval wait inside this timer |
| Pre-connect preparation after approval, or after 101 without approval | 10 seconds including DNS, observation/capacity admission, and the single connection attempt |
| Terminal delivery | 2 seconds; cancellation never waits for delivery before taking effect |

Work connections include HTTP responses, CONNECT tunnels, stream attachments,
and pending approvals across adapters. A classification slot cannot become a
long-lived work connection without a work permit. If all work slots are used,
deny new work while still parsing bounded status/cancel requests. Apply the
same request deadline and safe errors to hostile/incomplete headers. This
protects controls from stalled work, not from arbitrary denial-of-service by
an actor flooding every control slot; host resource limits remain necessary.

Enforce active-stream and global payload reservations before dialing. Approval
waits reserve neither upstream capacity nor relay payload. There is no unbounded
wait queue for capacity after approval: fail safely if reservation is unavailable.
Pending attachment capacity is released or transferred atomically on opening;
there is no unaccounted transition between the two pools.

Only successful application forwarding refreshes the idle timer. Receiving a
partial frame header, polling status, or delivering control metadata does not.
All I/O waits race cancellation and the appropriate deadline. Each direction
also has a 60-second stalled-write ceiling once it has pending payload; progress
in the opposite direction cannot preserve a blocked write indefinitely.
Connected lifetime is at most ten minutes, further capped by session/grant
expiry. The client must support the distinct approval, connection, and connected
phases; it cannot reuse a total HTTP timeout that unintentionally cuts off the
allowed approval-plus-stream lifetime. No timer silently extends another.

Reserve and account for the entire next DATA frame before consuming its body.
Copies and pending writes count toward relay-owned memory; framing cannot
bypass directional byte limits. No application queue is allocated during
approval. Bounded control serialization and cancellation state remain available
when data buffers are full. Socket buffers and observation retention retain
their independent configured bounds; neither is an unbounded overflow queue.

## Crate contracts and implementation acceptance

Keep credential-free frame/DTO validation and logical stream outcomes in
`aap-types`, the Upgrade adapter in `aap-http`, and its agent-safe client in
`aap-client`. The engine owns policy, approval, operation identity, cancellation,
and observation admission; `aap-transport` owns admitted dialing and duplex I/O.
No new crate or protocol dependency is needed for this binding.

Embedded callers use bounded application read/write/end callbacks without
serializing HTTP locally. The implemented `stream::service` seam separates
admission, connection, and forwarding through owned handles; directional end
is distinct from the relay future's terminal outcome. It obeys the same
single-consumer, no-resume, drop-cancels contract. A runtime-neutral interface
does not remove the concrete engine's requirement for its host's Tokio runtime.

Before advertising W7 TCP support, demonstrate all [relay acceptance
checks](tcp.md#crate-ownership-and-acceptance), plus:

- Strict upgrade/version/path/header/body validation; no upgrade on operator
  or inspected upstream routes; duplicate IDs produce status only.
- Byte fixtures with every header/payload split, multiple frames in one read,
  binary content, and both half-close orders. No local control bytes at the peer.
- Oversized lengths rejected before allocation; wrong-direction, unknown,
  empty-data, duplicate-control, truncated, and after-end frames fail safely.
- Early/pipelined data, approval denial/expiry, and attachment loss while pending
  never dispatch buffered payload or revive work after a late approval.
- Lost 101, lost OPENED, reset after accept, partially written frames, lost
  TERMINAL, and duplicate opens never cause reconnect or implicit replay.
- Byte/frame/global-buffer limits, stalled-write and lifetime deadlines, and
  status/cancel responsiveness with all work slots and data buffers occupied.
- Daemon and client agree on limits, counters, causes, and uncertain outcomes;
  a secret-store spy observes zero calls throughout all TCP cases.
- Actual daemon sockets and confined-agent fixtures, plus the same lifecycle
  for a trusted embedded consumer. Parser-only tests do not prove confinement.

Use the existing dependency stack and synthetic fixtures. This contract defines
the next implementation target; it does not certify the current listener,
client, or runtime as supporting the new endpoint or reserved control capacity.
