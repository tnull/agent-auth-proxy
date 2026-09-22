# aap-observe

Bounded trusted recording of already-sanitized logical events. The broker must
remove credentials before handing data to this crate; it never accepts a store
snapshot or authenticated request type. An independent collector gets a
host-scoped recording handle, not agent, approval, or store authority.

The initial in-memory recorder has an epoch-bound cursor, acknowledgments,
bounded bytes/events, explicit missing intervals, and required/best-effort
admission. Required means acceptance into this bounded local memory channel,
not remote delivery or disk durability. Offline/full required recording denies
admission; best-effort eviction remains visible as a gap. Restart changes the
epoch. The daemon exposes an owner recording endpoint and independently
enrolled, session/content-scoped collector endpoints.

`Flow` owns a random flow ID and four finite sequence counters, one per
directional agent/upstream view. Its clones serialize sequence assignment and
recording without a global stream registry. Correlation uses assigned session,
request, optional parent request, and policy revision. The caller declares
protocol, inspection, and redaction explicitly; the recorder does not inspect
traffic or confer authority on its caller.

`record_batch` accepts at most sixteen events / 256 KiB atomically. Capacity
failure consumes event identities but retains none of that update. Best-effort
eviction cannot remove unacknowledged required records; required acceptance
never evicts earlier records. Atomic updates let the engine record paired
views and complete endings without falsely accepting half a required update.

See the [current HTTP observation binding](../../docs/observation.md) for
logical-view semantics, limitations, and the remaining coverage work.

`Recorder::subscribe` grants a forward-only immutable set of sessions, views,
and metadata/content classes. At most sixteen subscriptions have independent
bounded queues, delivery sequences, cursor validation, and acknowledgments.
Enrollment includes no historical records or future session wildcard. A handle
can read/ack only its own queue; closing/dropping it revokes that authority.

Canonical records are retained once across all claims, within configured
global event/byte limits and an 8 MiB per-session content ceiling. Each consumer
has an independent retention claim, as does the owner channel. Required records
remain until every claim is acknowledged or the corresponding subscription is
closed; required admission never evicts prior records. Best-effort overflow may
drop a complete update in just the constrained consumer queue. Delivery gaps
report those losses without misreporting filtered-out events as missing.

Source event IDs remain canonical across authorized recipients; delivery IDs
and cursors are subscription-local. Session isolation is not an anonymity or
traffic-analysis guarantee: source IDs expose aggregate event numbering.
Metadata grants include safe HTTP targets/headers, aliases, lifecycle and byte
counts. Payload bytes require the content class. The trusted host, not this
crate, authenticates the operator/collector and enforces attachment lifetime.
