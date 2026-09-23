# aap-client

Credential-free `AgentService` client for one host-provided Unix session socket.
It has no engine, credential store, private cookie, CA, or upstream TLS
dependency. Identity comes from the attachment, never a caller-supplied session
ID. The sandbox must expose only its own socket; peer UID alone is insufficient
to isolate same-user agents.

Calls use one bounded HTTP/1.1 connection, with no redirect or retry. Errors
after sending begins may be uncertain; use the same request ID for status or
duplicate submission, or call cancel explicitly. Dropping a response closes
the local connection but is not proof that upstream work was undone.

## TCP streams

`AgentService::open_stream` now implements the session-socket
[TCP binding](../../plan/tcp-binding.md). It sends one strict HTTP Upgrade request
and returns either existing status or the sole owned pending attachment. An
existing ID never reattaches, resumes, or replays bytes. The daemon may start
connection work immediately after its upgrade, before the caller drives the
pending handle; the handle does not promise deferred upstream side effects.

The pending handle reports a validated OPENED or a pre-opening terminal outcome.
The connected handle exposes safe limits and accepts the runtime-neutral
`ApplicationIo` callbacks for bounded duplex delivery. Application send-end is
an explicit frame, not socket EOF. Both half-close orders work, including a
reply sent only after the client's outbound end. Control/framing bytes never
reach the application. A complete daemon terminal result remains separate from
successful delivery to the local application; EOF without it is always failure.

Opening headers and non-upgrade JSON are capped at 16 KiB each; headers are
validated before singleton normalization. The client verifies operation/resource
identity, frame sequence, byte/frame limits, actual-written counter bounds,
and existing-status/error envelopes. Unexpected redirects, cookies, ambiguous
framing, unsupported controls, and impossible completion are not accepted.
No caller credentials or upstream address can be added to this protocol.

Each attachment retains at most 64 KiB of payload per direction, with separately
bounded control/read-ahead. It has no unbounded queue or spool. Partial writes
preserve payload ordering and actual accepted-prefix accounting. Per-poll work
is bounded, with backpressure toward the application as well as the daemon.

Ownership transfers immediately when relay is requested, before its future
polls. Drop or the stop-only abort handle closes the socket and releases owned
application buffers/callbacks; it never submits an asynchronous retry or claims
remote rollback. A caller-owned-runtime watchdog expires unpolled handles and
wakes blocked work. The watchdog owns no independent socket and is stopped with
the attachment. Abort completion is not a received daemon terminal result.

Session connection and HTTP response each have a ten-second ceiling. After
upgrade, optional approval plus preparation has a separate 310-second ceiling.
OPENED establishes bounded idle/absolute lifetimes; handle transfer does not
restart them. Each stalled direction retains its own deadline. After both
application ends, final-control receipt is bounded to two seconds. Local expiry
is a delivery error, not an assertion about the daemon's retained state. Errors
on admitted handles retain the original request ID for separate status/cancel.

Run `cargo test -p aap-client` for synthetic-peer and lifecycle checks and
`cargo test -p aap-daemon --test process daemon_tcp_client` for real-daemon
binary delivery, cancellation, unpolled drop, and duplicate-operation checks.
Broader aggregate-budget/concurrency, independent embedding parity, and actual
confinement remain proof-of-concept gates. This library creates no sandbox.
