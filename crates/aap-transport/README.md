# aap-transport

Trusted HTTPS execution against an already admitted socket address, with
independent certificate/hostname verification. DNS resolution and dialing are
separate: callers authorize the complete resolver result before constructing
an endpoint. This crate owns no grants, credential store, redirects, or retries.

Caller-provided trust roots and the existing Tokio runtime are used explicitly;
there is no global TLS provider installation or process configuration change.
Only HTTP/1.1 is advertised initially. Response bytes/headers from this low-level
interface are private upstream data and must pass the engine's authentication
capture and sanitization before reaching an agent or observation consumer.

Execution checks authority/port and framing before opening a socket, connects
once to the supplied address, disables TLS early data, and uses finite request,
response, header, connection, inactivity, and total-duration limits. Dropping
the response or execution future cancels its connection driver. Cancellation
and driver deadlines run independently of response-body polling; retaining an
unpolled body cannot keep that upstream socket alive indefinitely. Only consumed
nonempty body data refreshes response inactivity, never the total deadline.
Once request
dispatch starts, transport failure is conservatively `outcome_unknown`; neither
that condition nor a redirect causes a second request. Consumers must poll the
body to its terminal outcome, not mistake received headers for completion.

Thirteen endpoint/resolver/HTTPS tests include real local TLS with untrusted and
mismatched certificates, record upstream reception, and exercise redirection,
ambiguous disconnects, stream cancellation, deadlines, framing, body limits,
and separate resolution.
Held-response tests also check joined server connections without polling the
client body and prove that cancelling one request leaves another live.
The interception module additionally validates a narrow self-signed root profile
and consumes an explicitly supplied PKCS#8 key to issue a short-lived identity
for an already admitted CONNECT authority. Two tests cover actual scoped-trust,
SNI/ALPN/IP handshakes and invalid, expired, non-CA, or mismatched key material.
It owns neither store lookup nor admission.

## HTTP driver ownership

`HttpsTransport::http_drivers()` returns a cloneable trusted ownership handle.
It retains established HTTP driver tasks until they have actually been joined.
`status()` reaps completed drivers and reports pending tasks plus a sticky join
failure flag; each new driver admission also reaps completed tasks. A failed
join does not discard other work. Completed handles are not accumulated across
successive requests without reaping.

After stopping admission and cancelling owned operations, a host can call
`wait_until_idle(absolute_deadline)`. A timed-out or dropped waiter does not abort
or forget tasks. Concurrent waiters serialize joins without renewing their
individual deadlines. Two conformance tests cover caller cancellation, concurrent
waits, failure retention, and continued joining after a driver panic.

The handle covers one transport instance, including every broker sharing it;
waiting does not cancel another broker's requests. A zero pending count is an
idle snapshot, not authority closure or whole-host drain. DNS/connect/handshake
futures are caller-owned and excluded, as are retained response buffers, engine
permits, observation, and native store jobs. Keep an ownership handle until joins
are confirmed: dropping the last owner aborts outstanding tasks without joining
them. The daemon's aggregate retirement/shutdown accounting still needs to
integrate this handle; its `drain_confirmed` flag remains false.

## Admitted TCP connector

The `tcp` module offers a separate trusted `TcpConnector` seam and
`SystemTcpConnector` for one already admitted `TcpEndpoint`. Endpoint construction
checks canonical authority/port and literal-IP consistency. The connector uses
only the supplied socket address: no DNS lookup, TLS, credential resolution,
proxy negotiation, implicit framing, retry, failover, or connection reuse.

The caller supplies an absolute deadline at most ten seconds away. Pre-cancelled
or expired work never polls a connection attempt; cancellation, timeout, or
failure once an attempt can have started is conservatively uncertain. A late
successful socket is discarded if cancellation or expiry won. Dropping a pending
future drops its attempt rather than leaving a background connection task.

The returned owned duplex I/O belongs to the trusted engine, not the agent.
After connection, that owner must enforce authorization, cancellation, relay
buffers/deadlines, observation, framing, and terminal write counters. Four tests
cover strict endpoints, real binary traffic with both half-close orders, and
deterministic attempt cancellation/expiry/failure/drop. They do not yet establish
an operational agent TCP relay; engine and local adapter integration is pending.

## Bounded duplex I/O

`tcp::relay::Duplex` now supplies an owned, explicitly polled application-byte
relay. It uses at most 32 KiB per direction, alternates directional work, and
limits each poll to sixteen I/O steps. It spawns no driver or queue. The engine
must reserve aggregate capacity before construction and terminate retained work
when its authority ends; a cancellation token alone requires the owner to poll.
Explicit `terminate` immediately closes I/O, releases buffers, and preserves
actual accepted-prefix counters and an already terminal result.

A mandatory trusted gate admits each chunk and directional end before output.
It must implement safe required-observation acceptance, not export raw payload.
The relay itself owns no recorder, sanitizer, credentials, or grants. Partial
writes count only their accepted prefixes. Each direction preserves half-close;
both ends are needed for an orderly transport outcome. That outcome still
requires final engine observation and lifecycle commitment before the broker
can report completion.

Independent byte limits, inherited absolute lifetime/idle deadlines, and a
directional stalled-write deadline bound every I/O stage. Only successful
application writes refresh inactivity; opposite-direction activity cannot
extend a stalled writer. Cancellation or gate failure stops forwarding and
does not flush remaining payload. Low-level I/O errors become fixed causes,
not peer-provided diagnostics. A one-byte EOF probe at a byte ceiling is never
forwarded if it contains excess data.

A trusted local adapter may wrap a fixed `stream::service::AttachmentError`
inside its I/O error to preserve invalid-frame/limit/loss/internal causes.
Only that concrete local classification is recognized. Upstream errors and
arbitrary native diagnostics retain the conservative fixed transport cause;
they cannot impersonate local framing failures or successful completion.

Eleven tests include real binary TCP traffic and both half-close orders,
required-gate rejection, cancellation before writes, partial-write accounting,
exact/exceeded directional limits, real driver wakeups, idle/lifetime/stall
deadlines, bounded ready-peer polling, and unpolled owner termination. The
[engine](../aap-engine/README.md#tcp-admission-and-connection-ownership) now adds
owned lifecycle, observation, and final commitment for trusted application I/O;
the local framed protocol is still pending. A framed
adapter must map explicit SEND_END to application EOF, unexpected attachment
EOF to failure, and maintain separate bounded final-control delivery; these
native-stream fixtures do not establish those agent-wire semantics.
