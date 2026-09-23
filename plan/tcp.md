# Destination-bound TCP relay

Status: W7 contract. Enrollment, framing, single-attempt connection, engine-owned
duplex lifecycle/observation, and the daemon session upgrade are implemented.
The credential-free client also has real-daemon coverage. Full adversarial
acceptance and actual confinement remain pending; see
[current coverage](../docs/tcp.md). Keep the existing
project and crate names. This extends the [architecture](architecture.md) and
[common operation contract](protocol-common.md); it introduces neither an
authentication scheme nor a new secret-store backend.

## Scope and security claim

The first profile relays ordinary TCP bytes to one explicitly enrolled,
credential-free fixture service. It demonstrates bounded duplex transport,
session authorization, cancellation, and directional observation. It does not
authenticate an arbitrary application protocol or expose a general-purpose
SOCKS proxy. Password substitution, cookie custody, provider authentication,
and MCP interpretation remain on their existing protocol-aware paths.

Byte visibility is not semantic inspection. Arbitrary bytes can contain an
encrypted or encoded conversation even when the fixture normally uses plain
text. Recognizing a TLS prefix or denying a few ports cannot establish that
all payloads are plaintext. Deployments requiring parsed operations or verified
application plaintext MUST deny this relay profile until a corresponding
protocol adapter exists. There is no automatic raw relay on TLS, HTTP, or MCP
inspection failure.

No secret is resolved or injected by this profile. Plain TCP provides no TLS
server-identity check; destination authorization alone does not authenticate
the peer. The controlled first fixture uses synthetic, non-sensitive payloads.
Production enrollment needs a separate review of the service and its network
trust assumptions. Managed credentials still require verified HTTPS in the
initial product.

## Resource enrollment and admission

The trusted operator enrolls a TCP resource with these immutable facts:

- A safe resource alias, one canonical hostname or literal IP, one port, and
  permitted resolved addresses. No caller-supplied destination, wildcard port,
  URL userinfo, alternate resolver, or upstream proxy selection.
- An explicit byte-relay grant, inspection classification, observation policy,
  connection approval requirement, and finite byte/time/concurrency limits.
- No account, store reference, authentication context, or credential fields.
  Reject configuration that attaches an HTTP authentication profile to it.

As for HTTPS, the engine resolves the enrolled name, checks every candidate
address, and supplies an admitted endpoint to the connector. The connector
does not resolve again. Private, loopback, link-local, and other special
addresses need exact operator enrollment; a permitted hostname does not admit
other ports. The first profile makes one connection attempt with no automatic
reconnect, failover, or connection reuse between operations or sessions.

Reject a raw relay enrollment sharing the canonical host and port of an
inspected HTTP/provider/MCP resource: it would offer an alternate unparsed
route to that service. The operator must also review aliases and service
behavior; name comparison cannot prove that two different services do not
forward to one another. DNS servers, forward proxies, tunnel gateways, and
remote-command services are not part of the first profile. A remote service's
further traffic remains outside observation, just as for remote MCP tools.

The initial configuration uses a separate `tcp_profiles` collection, empty
when omitted, with at most 256 HTTP and TCP profiles combined. Resource aliases
are unique across both collections; one raw endpoint cannot have multiple
aliases that reset its per-resource ceiling. TCP limits additionally cap active
streams for that resource within one session at 1–8, still sharing the session's
eight upstream slots and the broker's global relay limits. Enrollment validation
does not itself activate a relay or imply application inspection.

Use a distinct logical stream operation, not a less restrictive interpretation
of existing CONNECT. Ordinary CONNECT continues to select inspected HTTPS and
fails if that coverage is unavailable. HTTP's CONNECT specification itself
warns about arbitrary tunnel destinations; this plan uses narrower resource
enrollment rather than a generally available tunnel.
[RFC 9110, section 9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)

## Agent interface and operation identity

`stream.open(request_id, resource)` is a proposed asynchronous addition to the
session-scoped agent interface. It freezes the selected profile, policy
generation, destination, limits, and observation requirement. The ID shares the
existing session-wide operation namespace and tracking budget. The returned
stream belongs to that ingress and operation; an identifier is not authority
to attach from another connection or session.

`request.status` and `request.cancel` apply to the stream operation. Duplicate
open with identical inputs returns existing status, never a second connection,
another stream attachment, or replayed payload. Different inputs conflict.
Streams have one consumer and are not resumable. Reopening after disconnect
requires a new explicitly authorized operation; the client must not do so
automatically.

The local transport binding must distinguish open/accepted control, data,
directional send-end, and terminal complete/incomplete status. It must:

- Keep framing local: only application data reaches the TCP peer.
- Preserve binary data, ordering, and half-close in both directions. Frame and
  read boundaries do not become application message boundaries.
- Reject data before admission, data after that direction's send-end, duplicate
  open, and unsupported control messages. No payload is buffered for approval.
- Report a missing terminal record as incomplete, not successful EOF. Status
  on a separate admitted connection remains available after attachment loss.
- Keep cancellation/status responsive when data buffers or stream slots are
  exhausted; a client need not drain its payload to revoke the operation.

The proposed [version 1 local binding](tcp-binding.md) uses an HTTP/1.1 upgrade
on the existing session socket, then bounded binary frames with explicit
directional end and terminal outcome. Its parser, capacity, and negative
fixtures are W7 implementation gates. This is not an additional MCP tool in
the first profile: the bounded JSON tool surface is not a duplex byte channel.
A later credential-free sandbox bridge may adapt ordinary local TCP clients
to one fixed enrolled resource, without gaining direct egress.

## Approval and lifecycle

Global, session, and resource requirements compose restrictively. Because this
profile has no credential item, no per-item policy applies. If approval is
required, submit the frozen connection facts to the existing `ApprovalProvider`
before dialing. An absent provider fails closed. The request must clearly say
that it authorizes a bounded byte channel, not each future application action:
future bytes cannot be displayed as an already frozen operation. A policy
requiring action-by-action approval cannot use this profile.

After approval, recheck session/grant lifetime, policy generation, destination,
capacity, and required observation before connecting. No store metadata or
secret read is needed. Cancellation, expiry, policy invalidation, and daemon
shutdown stop admission and cancel both relay directions. Late approval cannot
create a connection. Waiting for approval does not consume an active upstream
slot or hold a global lock.

Treat connection initiation conservatively as dispatch: a server can act on
accept or send a greeting without receiving application bytes. If interruption
occurs after connection initiation and its remote effects cannot be excluded,
report `outcome_unknown`. Zero forwarded payload bytes are not proof of no
remote effect. Status queries and retries never reconnect implicitly.

Each direction drains only its already admitted bounded bytes, then propagates
an orderly send-end while leaving the opposite direction open. This preserves
protocols that reply after client half-close. TCP closes its two directions
independently; a one-sided EOF is not whole-flow completion.
[RFC 9293, section 3.6.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.6.1)

Both orderly ends and successful required recording establish transport-level
completion, not success of an unknown business action. Reset, timeout, limit,
lost attachment, or cancellation closes both directions and reports incomplete
delivery. Never add an error string to the application stream or keep flushing
queued data after revocation. Already delivered bytes cannot be recalled.

## Bounds and backpressure

These proposed initial ceilings supplement the [first-proof limits](proof-of-concept.md).
Session/resource settings may narrow them; none can select unlimited operation.

| Budget | Initial ceiling |
| --- | --- |
| Active streams per session | Shares the existing 8 active upstream operations; no independent extra pool |
| Active TCP streams per broker | 64 across all sessions |
| Local open/control metadata | 16 KiB; no application payload |
| Individual data frame/read chunk | 32 KiB |
| Relay-owned retained payload | 64 KiB per direction, 128 KiB per flow, 8 MiB per broker |
| Total forwarded bytes | 32 MiB in each direction, independent counters |
| Connection establishment | 10 seconds |
| No application progress / total connected lifetime | 60 seconds / 10 minutes, capped by session/grant expiry |
| Pending approval | Existing shared 16 operations / 4 MiB / 5 minutes per session |

Reserve capacity before accepting data; account for copies and pending writes,
not just the nominal reader buffer. Socket and observation buffers have their
own explicit bounds and are not covered by the relay payload allowance.
Successful forwarding in either direction counts as application progress;
keepalive, status polling, and empty local frames do not refresh the timer.
Each direction also has a 60-second stalled-write ceiling while payload is
pending; opposite-direction activity cannot keep a blocked writer alive.
Half-closed streams retain the same absolute deadline. The [local binding's
additional limits](tcp-binding.md#parser-capacity-and-scheduling-requirements)
cover framing, pending attachments, and reserved status/cancellation capacity.

Apply backpressure when a receiver is slow; do not create unbounded tasks,
queues, or disk spools. In required observation mode, record the sanitized
chunk before forwarding it. Failure stops that flow, retaining partial-delivery
state. Best-effort collector loss follows the existing bounded gap contract
without dropping application bytes silently. Neither a slow collector nor a
stalled peer may prevent session revocation or unrelated status requests.

## Observation and privacy

Assign a trusted flow ID and retain the opening request ID even though payload
messages are not parsed. Export directional ordered bytes, sanitized offsets,
transport byte totals, policy decisions, and explicit end causes through the
existing observation interface. Do not invent HTTP requests or MCP messages.
The fixture may establish `plaintext_bytes` coverage for its known exchange;
arbitrary unparsed traffic is `opaque`, not decrypted/parsed. A profile claiming
stronger inspection than the adapter can establish is rejected, not silently
downgraded.

Sanitize known local placeholders in exported views using bounded streaming
state, without changing application data. Never enumerate or read stored
passwords to build a relay redaction dictionary. Payloads may contain other
sensitive user data; their export requires explicit consumer authorization and
retention policy. If safe payload observation cannot be supplied, withhold it
with explicit metadata-only coverage, or deny if policy requires content.

## Crate ownership and acceptance

Keep policy/data contracts in `aap-types` and `aap-policy`; admission, approvals,
tracking, and cancellation in `aap-engine`; and admitted dialing/duplex I/O in
`aap-transport`. Use `aap-observe` for safe export. The daemon composes the local
binding with `aap-client` and the existing ingress boundary. The proposed
[HTTP Upgrade binding](tcp-binding.md) belongs in `aap-http`, with credential-free
frame contracts in `aap-types`; do not add a crate or protocol dependency just
for a copy loop. Embedders use the same engine semantics.

W7 needs real sockets and an actual daemon fixture, not only an in-memory copy
test. Implement behavioral tests first, including:

- Binary round trips, arbitrary chunk splits, simultaneous sends, and both
  half-close orders; a server response produced only after client send-end.
- Wrong session/resource, undeclared destination/port, address-policy changes,
  and raw access to an inspected resource; zero unauthorized connections.
- Duplicate IDs, conflicting IDs, disconnect and reset after server acceptance;
  no second connection or replay and honest uncertain status.
- Approval denial, late approval, expiry/revocation races, and unconfigured
  approval; no secret-store access in any TCP path.
- Independent directional totals, shared HTTP/TCP slot exhaustion, global
  buffer admission, slow peers, idle/total deadlines, and responsive cancellation.
- Ordered observation, placeholder splits, authorized consumer scope, gaps,
  required recorder failure before connection and midway through a direction.
- No raw fallback after failed HTTPS/MCP inspection; no claim of decrypted
  content for arbitrary encrypted or encoded bytes.
- Actual sandbox bypass probes and the same reusable-library/daemon behavior,
  as required by [deployment](deployment.md) and W8.

Report the exact fixture and inspection class proven. Passing byte-relay tests
does not establish generic TCP authentication, semantic action approval,
arbitrary plaintext detection, or visibility into the remote peer's egress.
