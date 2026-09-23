# Current communication observation

This documents the implemented subset of the
[observation design](../plan/observability.md), not completion of W7.

## Envelope and identity

The daemon's owner observation endpoint returns bounded JSON batches of
`aap_observe::Record`. The outer fields are `schema_version` (1),
`daemon_epoch`, `event_id`, `time_unix_ms`, and `event`. The event contains
assigned session/flow/request/optional parent IDs, `policy_version`, `protocol`,
`inspection`, `redaction`, `direction`, `view`, `stream_id`, `sequence`, and
`data`. The event discriminator is `data.event_type`, using snake_case names.
This is a developing local binding, not a published stable protocol.

Each logical HTTP operation has one random flow ID. Within that flow, the four
stream IDs are `outbound.agent`, `outbound.upstream`, `inbound.agent`, and
`inbound.upstream`. Each starts at sequence zero and advances independently,
including on recording loss. Use epoch/flow/stream for ordering and
epoch/event ID for redelivery deduplication. Wall-clock timestamps do not
establish causality. No global order is promised across concurrent flows.

`flow_open` means allocation of a logical request attempt, not establishment
of an upstream TCP connection or successful TLS negotiation. Policy events
report pending, allowed, or denied admission. A post-dispatch transport failure
does not retrospectively invent a policy denial. `flow_close` reports logical
completion, sanitized directional byte totals, and a safe terminal reason.

## Content views

`request_start` and `response_start` contain conservative structured headers.
Known authentication headers retain their names with `[redacted]` values;
unknown names and values become `[withheld]`. Only selected constant protocol
values survive. Request targets omit queries. Transformed framing, lengths,
and connection headers are omitted.

`content_chunk` carries base64 data, an offset in that sanitized view,
`encoding: "base64"`, and a media type when known. `content_end` states whether
the stream completed and counts its sanitized bytes. Chunk boundaries are not
message boundaries. HTTP parsing does not imply semantic parsing of every
provider response message or arbitrary application body.

Provider requests record both views after required inspection and final
authentication insertion. The upstream header view identifies the inserted
header without its value. Provider response content currently uses the same
known-secret-sanitized stream for both views; header views still distinguish
captured Set-Cookie from the response permitted to reach the agent.

Website login agent views structurally replace the declared credential and
CSRF selectors before serialization. This handles valid percent-encoded form
placeholders and escaped JSON placeholders without resolving a password.
Upstream login views redact the actual substituted values. Website responses
remain wholly inspected before delivery: the upstream observation is based on
the received body, while the agent observation reflects CSRF virtualization
and response sanitization. Current-context placeholders are suppressed from
both website observations. Cookies are captured before body observation.

A further observation-only filter recognizes complete username/password/CSRF
placeholders even when quoted outside their context, including in provider
prompts and responses. It accepts their canonical raw shape, mixed percent or
JSON ASCII escapes, and individually base64-encoded tokens. This does not
authorize their use, query a secret store, or rewrite the original application
traffic. Arbitrary encodings are not covered by this bounded recognizer.

These are logical, transformed views, never raw credential-bearing captures.
Known-value suppression is bounded defense in depth, not proof that a hostile
authorized recipient cannot invent a new encoding of a secret. Prompts and
other ordinary data can still be sensitive after managed-secret redaction.

## Acceptance, endings, and limitations

The recorder accepts up to sixteen events / 256 KiB per atomic update, with
128 KiB per serialized event and finite configured retention. Paired provider
chunks and final view endings use atomic updates. Required-mode failure stops
dispatch or delivery; it cannot undo remote effects or bytes already delivered.
Acceptance currently means local bounded memory, not durable or remote receipt.

Placeholder recognition retains at most 305 undecided bytes between feeds.
For streamed responses, the corresponding original agent suffix is retained
as well: each source prefix is released only after its redacted observation is
accepted. This preserves required-mode ordering without dropping placeholders
from the actual agent response or collecting an entire provider stream.
Tiny trailing responses may wait for the next bytes or EOF within the existing
transport deadlines. Cancellation and observation failure discard undecided
bytes and report incomplete execution.

Dropping or cancelling a response attempts explicit incomplete endings for
started streams and closes both logical views. Successful completion is not
reported unless the terminal batch is accepted. If recording itself is
unavailable, terminal events cannot be guaranteed: consumed event IDs and the
resume/gap mechanism expose missing coverage. An incomplete or missing ending
must never be inferred to be success.

## Trusted TCP relay observation

The engine's native-I/O TCP relay now emits logical opening/policy records,
paired directional content and endings, and final flow records. Inspection
is explicitly `plaintext_bytes`, `opaque`, or `metadata_only` from enrollment;
raw byte forwarding does not manufacture HTTP, MCP, or authentication events.
Both views carry the same sanitized bytes because this relay performs no
authentication substitution. It never accesses a secret store.

Interactive streams use immediate conservative placeholder suppression:
possible token suffixes are masked at once, then their continuations stay
hidden. This permits false positives at chunk boundaries but avoids waiting
for another application message. Actual application bytes remain unchanged.
Metadata-only content is withheld. Empty safe chunks still establish fresh
required-recording acceptance before forwarding withheld source bytes; they
are not empty application frames. Content offsets and endings count sanitized
bytes; TCP flow-close totals instead count actual application write prefixes,
which can be smaller after a partial write or cancellation.

Only two orderly ends and an accepted required terminal batch permit completed
status. Cancellation/drop/timeouts attempt incomplete endings and preserve
actual write counts. Required recording outages stop new forwarding; best-effort
loss follows the existing gap contract. The [local framed endpoint](tcp.md) now
uses the same engine gate, with a real daemon TCP fixture. Broader concurrency,
physical connection coverage, and confinement acceptance remain pending.

## Scoped collectors

The operator can enroll up to sixteen private collector attachments through the
[daemon endpoint contract](daemon.md). Each grant selects existing session IDs,
agent/upstream views, and metadata/content classes. Enrollment is forward-only,
with no history or implicit future sessions. Metadata includes safe targets,
headers, aliases, sequence/lifecycle and byte counts; content additionally
exposes redacted payload chunks. The grant is immutable for the attachment.

Scoped read returns `deliveries`, not the owner's `records` array. Each delivery
has its own `delivery_id` plus the canonical source `record`. Only selected
events consume delivery IDs. Resume and gaps use delivery IDs, so excluding
content or a different session is not mislabeled recording loss. Source flow
sequences may still have gaps due to selection. Source event IDs remain shared
across authorized readers for correlation; their aggregate numbering is not a
traffic-anonymity guarantee.

The cursor includes the subscription ID, daemon epoch, and last delivery ID.
It is not a credential: the private attachment authenticates its scope. Foreign
cursors, wrong epochs, and positions beyond an issued page are rejected.
Reconnecting to the same live attachment can replay retained deliveries.
Revocation/restart requires fresh enrollment; it cannot silently continue an
old stream.

One canonical stored event can have an owner claim and several collector
claims. Acknowledging a claim does not acknowledge any other. Storage is charged
once against global limits and an 8 MiB per-session retained-content limit;
each collector also has explicit event/byte queue ceilings. Required recording
atomically accepts the update in every selected queue, or fails. A required
record remains protected until all applicable claims are acknowledged or
closed. Operators must therefore drain the owner channel as well as collectors.
Best-effort consumer-local overflow loses that consumer's whole update without
discarding another queue's data; global/session exhaustion can cause broader
eviction or loss. All loss consumes source/delivery identities and produces
resume gaps.

The daemon revokes collectors on explicit operator revocation, expiry, loss of
an enrolled session, successful reload, or shutdown. Private sockets and peer
UID checks still require a launcher that exposes only the intended attachment,
not the complete runtime directory. No collector gains policy-write, session
creation, approval, or credential-store authority.

Still pending: physical TCP/TLS connection lifecycle and tunnel/subrequest correlation;
remote MCP protocol coverage; parsed message convenience events; and expanded
auth state events. These limitations prevent claiming complete communication
observation or checking off W7.
