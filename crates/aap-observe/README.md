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
epoch. Daemon transport, tenant-scoped export, and global budgets belong to the
composition layer and remain pending.
