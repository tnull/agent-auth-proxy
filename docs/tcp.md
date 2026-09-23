# Local TCP stream endpoint

The daemon now implements the server side of the
[version 1 stream binding](../plan/tcp-binding.md). This is a separately enrolled,
credential-free byte relay, not automatic authentication for arbitrary TCP.
The agent client API, broader adversarial acceptance, and actual confinement
demonstration remain pending; this does not complete W7.

## Enrollment and opening

Enroll a `tcp_profiles` entry in the private daemon configuration and grant its
alias when creating the session. The profile fixes a canonical host/port,
address policy, byte/time/concurrency limits, inspection class, and optional
connection approval/required observation. Raw and inspected canonical endpoints
must not overlap. There is no destination supplied by an agent, implicit raw
fallback from CONNECT, credential injection, or secret-store read.

On that session's private Unix socket, send HTTP/1.1
`POST /aap/v1/stream/open`, `Host: aap.local`, `Connection: upgrade`,
`Upgrade: aap-stream/1`, `Content-Type: application/json`, and a single exact
decimal Content-Length. The JSON body contains only `request_id` and `resource`.
The full wire contract and control fields are in the linked specification.

Opening headers/body are bounded to 16 KiB each, with at most eight headers,
ten seconds for the complete incoming request, and no chunking, trailers,
authentication headers, or pipelined data. The only optional header is one
User-Agent of at most 1 KiB. Duplicate headers, including identical repeated
Content-Length, are checked before HTTP normalization. Unknown/duplicate JSON
fields and expired ready metadata fail before operation admission.

New admission produces 101 without Content-Length or Transfer-Encoding. Only
after writing 101 does the engine begin approval, DNS, and its one connection
attempt. Identical duplicate operations return retained status as JSON (202
pending, 200 terminal, `x-aap-operation-state: existing`), never another stream.
Other failures use the existing safe HTTP error binding and close the socket.
Neither operator endpoints nor inspected CONNECT subrequests expose this route.

## Frames and lifecycle

The daemon finishes OPENED before forwarding application bytes in either
direction. It currently omits the optional PENDING frame; independent status
requests still expose pending approval. Any client byte before OPENED aborts
the operation, including during approval. No application queue is allocated
while waiting for consent, and a late approval cannot revive abandoned work.

Each frame has a one-byte type and four-byte big-endian length. Only DATA
payload reaches the upstream socket. The binding accepts binary bytes, limits
DATA to the enrolled maximum (at most 32 KiB), caps each direction at 32 MiB and
65,536 frames, and checks headers before allocating a declared payload. Framing
work and read-ahead are bounded; there is no detached forwarding queue.

SEND_END explicitly ends an application direction without closing the local
attachment. Either direction may end first. Bare attachment EOF is failure,
not send-end or completion. A separate monitor detects forbidden input after
agent send-end even when the engine no longer needs application reads.
Stop-only operation handles preserve actual partial-write counts and wake
blocked control writers on cancellation or revocation.

TERMINAL is distinct from directional end. Completed status requires both
orderly ends and successful required terminal observation. Failure after a
connection attempt remains uncertain even with zero forwarded bytes. Terminal
delivery has a two-second deadline; a started but unfinished output frame
causes closure instead of inserting a terminal into its payload. Missing local
terminal delivery never rewrites the committed engine result. Query status
without reattaching; neither lost payload nor remote rollback is implied.

The engine keeps its original idle/lifetime deadlines across the handoff.
Approval, preparation, connected I/O, and terminal delivery have separate
budgets. The listener's outer TCP ceiling is 922 seconds, covering the maximum
10-second request, 300-second approval, 10-second preparation, 600-second
connection lifetime, and two-second final delivery. Actual authority may be
shorter. The ordinary HTTP response timer is not reused for this stream.

## Capacity and observation

Each session listener permits 32 connections, at most 28 of them work. HTTP
responses, CONNECT tunnels, and stream attachments share those work permits.
Four slots remain for bounded classification and status/cancel servicing.
This protects controls from occupied work slots, not an attacker flooding
every classifier; host resource limits and sandbox exposure remain necessary.

The engine reserves 128 KiB per connected stream from its 8 MiB payload pool.
Core buffers are at most 16 KiB per direction. Framing retains one at-most-32-KiB
decoded/input payload and 1 KiB of read-ahead; outgoing application writes use
the caller's bytes and report actual accepted prefixes, excluding headers.
Dropping the application adapter releases payload immediately, before the
bounded final-control owner is released. Recorder storage remains separately
bounded. Comprehensive aggregate allocation/race acceptance is still pending.

The same [TCP observation](observation.md#trusted-tcp-relay-observation) gate
applies to native and framed forwarding. It preserves declared plaintext,
opaque, or metadata-only inspection without inventing application semantics.
Raw TCP does not authenticate an upstream peer or provide TLS confidentiality.

## Verification and reuse

`cargo test -p aap-daemon --test process daemon_tcp_upgrade` exercises the real
daemon/socket, binary forwarding, explicit half-close, final status, duplicate
opens, malformed headers, and operator-route separation. Engine/adapter tests
also cover both half-close orders, pending approval loss, forbidden input,
cancelled blocked OPENED, partial frame writes, frame/byte ceilings, payload
release, terminal timeout, and full work-slot admission with usable controls.
These are controlled fixtures, not proof of a sandbox network boundary.

Trusted hosts may reuse `aap_http::stream::serve_upgraded` after their own
validated admission and completed HTTP upgrade. It consumes the existing
session-owned pending handle and performs no independent authorization or
reconnection. Direct embedded callers can still use the runtime-neutral
`AgentService::open_stream` interface without serializing HTTP.
