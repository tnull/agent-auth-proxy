# Observation stream contract

## Purpose and visibility

The daemon exports bidirectional communication and policy events to independent
consumers for anomaly detection, IDS analysis, or other authorized processing.
Detection algorithms and automatic response rules are outside this phase.
Export alone does not mean a request was reviewed before execution.

Observation is a separate authenticated interface, unavailable to the agent.
Consumers receive only authorized tenants/sessions and content classes. Managed
authentication secrets are excluded. Prompt bodies, tool arguments, documents,
and model output may still contain sensitive user data, so access and retention
must be explicit even after credential redaction.

Expose two content views where the protocol is understood:

- **Agent view:** what the agent submitted or was permitted to receive, with
  private metadata and placeholders redacted according to policy.
- **Upstream view:** the final logical request or received response after
  protocol transformations, with secrets removed and modifications identified.

These are redacted logical streams, not byte-identical packet captures. A
consumer can tell that authentication was inserted or a cookie captured without
learning its value. Raw credential-bearing capture is not a baseline mode.
Ciphertext relays expose connection metadata and optional ciphertext bytes;
they must never be labeled decrypted or fully inspected.

## Event envelope

Version 1 defines logical event records. Export transport, framing library,
compression, collector product, and storage technology are deferred. A JSON
binding encodes binary payloads with base64 and preserves integer precision.

| Field | Requirement |
| --- | --- |
| `schema_version` | Integer `1` |
| `daemon_epoch` | Unique opaque identifier changed on daemon restart |
| `event_id` | Unique within that epoch; stable on redelivery |
| `session_id`, `flow_id` | Authorized pseudonymous session and connection identifiers |
| `request_id` | Operation identifier when meaningful; absent for unparsed TCP |
| `parent_request_id` | Optional trusted correlation for local tool/subrequest relationships |
| `stream_id`, `sequence` | Logical directional view and monotonically increasing record number |
| `time` | UTC observation timestamp; ordering relies on sequence, not wall-clock equality |
| `protocol`, `direction`, `view` | Declared protocol, traffic direction, agent/upstream view |
| `event_type` | One of the types below |
| `inspection` | `parsed`, `plaintext_bytes`, `opaque`, or `metadata_only` |
| `policy_version` | Policy decision version for this event |
| `redaction` | Complete, transformed, withheld, or truncated content; safe reason codes |
| `data` | Event-specific safe metadata or payload |

Agent-supplied trace headers are marked untrusted and cannot replace assigned
identity. Filters are not access control. Do not expose native secret-store IDs,
secret fingerprints, grant internals, or private usernames in the envelope.

| Event type | Contents |
| --- | --- |
| `flow.open`, `flow.close` | Destination, TLS/inspection status, lifecycle, totals |
| `request.start`, `response.start` | Safe method/target/status and redacted structured headers |
| `content.chunk` | Ordered sanitized bytes, offset in this sanitized view, encoding, media type |
| `message` | Optional parsed MCP/JSON-RPC, SSE, or WebSocket message with stream correlation |
| `auth.transition` | Profile, login/context state, safe item alias, outcome |
| `policy.decision` | Allow/deny/pending, safe reason, decision version |
| `content.end` | Complete/incomplete, sanitized byte count, terminal cause |
| `observation.gap` | Missing sequence interval or unavailable epoch/cursor, loss scope, reason |

Chunk boundaries are transport artifacts, not message boundaries. Consumers
reassemble by stream and offset. Parsed events are convenience views of the
same content, not additional network requests. Streams end explicitly on
cancellation, denial, parse failure, limits, or disconnect. Never report a
partial body as complete.

Also record daemon authentication, metadata, and refresh subrequests,
linked to their parent where applicable. Export approved raw TCP bytes with
direction and order without pretending to parse unknown protocols. Identify
unmediated remote tool activity as outside coverage; do not invent downstream
traces that the daemon did not observe.

## Redaction and streaming

Redact authentication headers, private Cookie/Set-Cookie values, passwords,
refresh/access tokens, secret-store responses, credential placeholders, and
private CSRF fields. URLs, nested bodies, errors,
MCP results, redirects, trailers, and compressed responses are in scope too.
Never export an unkeyed password/token hash as a correlation identifier; use
independently assigned identifiers.

Redact outbound traffic structurally and report credential insertion as metadata.
On inbound authentication responses, capture/classify secrets before emitting
affected content. Redaction must span chunk boundaries and bound decompression.
A profile requiring whole-message inspection cannot expose that message to an
agent or consumer before the check finishes.

Approved ordinary response streams use bounded redaction state and incremental
export. If a format cannot be safely sanitized, withhold payload observation
and mark it `metadata_only`; if it also cannot be safely returned to the agent,
fail the application request. Withholding observation alone does not make a
secret-bearing response safe to forward.

Offsets refer to sanitized bytes. Remove stale Content-Length, digest, and
signature fields from transformed logical views. Aggregate transport byte counts
may be reported separately without implying byte identity. Known-value suppression
is defense in depth, subject to the architecture's malicious-recipient limit.

## Ordering, delivery, and overload

Guarantee ordered records within each logical directional view. No total order
is promised across concurrent streams, connections, or views. Deduplicate
redelivery by `(daemon_epoch, event_id)`. Connection/session correlation does not
imply matching TCP chunk boundaries across views.

Support subscription filters, acknowledgments, and resume from an opaque cursor
within bounded retention. Acknowledgment means acceptance by the configured
export channel, not detection success. Unavailable cursors produce a gap;
restart never silently claims continuity. Retained events may arrive more than
once. Delivery is neither unlimited nor exactly-once.

Every deployment declares finite queue, retention, content-size, expansion,
and time limits, plus one policy per route:

| Policy | Behavior |
| --- | --- |
| `best_effort` (default) | Forward permitted traffic; drop observation content on overflow; retain a bounded coalesced gap marker and counters |
| `required` | Forward a request/chunk only after its required redacted observation is accepted by the configured bounded recording channel; otherwise deny/stop |

No consumer can induce unbounded memory/disk growth. Gap signaling has reserved
bounded capacity; repeated loss can be coalesced. A disconnect remains visible
on reconnect and in operator health state even when immediate delivery fails.

In `required` mode, accepted local recording may await remote delivery only if
policy expressly permits that durability boundary. An unavailable required
recording service causes denial before dispatch where possible. Midstream
failure closes the stream and records partial execution; it cannot undo already
delivered bytes or remote effects. A synchronous detector gate is a separate
future authorization feature.

Consumers have no direct credential, policy-write, or approval authority. Later
IDS responses must use independently authorized control-plane actions bound to
the intended session and current policy.

## Acceptance scenarios

- Model streaming, MCP calls/results, form login, and plaintext TCP export
  retain useful content order, identity, and inspection classification.
- Secrets spanning chunks, encoded form fields, nested tokens, error cookies,
  and store failures do not leak managed credentials.
- Consumers correlate views and substitutions without confusing sanitized
  data with a packet capture.
- Slow/offline consumers, retention expiry, restart, redelivery, and overload
  produce gaps or required-mode denial, never silent completeness or unbounded
  storage.
- Filters, cursors, and error paths cannot cross tenant/session boundaries or
  retrieve real credentials.
