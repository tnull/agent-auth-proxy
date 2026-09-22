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
epoch. The daemon currently exposes one owner-only recording endpoint;
tenant-scoped export and per-consumer authorization remain pending.

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
