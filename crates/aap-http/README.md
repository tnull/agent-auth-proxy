# aap-http

Bounded local HTTP adaptation of a host-bound `AgentService`. The host supplies
a listener, its expected peer UID, and the session handle. This crate neither
selects secret stores nor grants authority from request headers. Linux private
socket creation belongs to `aap-config`; confinement remains the host's job.

The initial binding exposes only the versioned session operation/vault API,
never operator routes. It preserves sanitized response streaming and fixed
typed errors. A host can additionally enable [CONNECT inspection](../../docs/connect.md)
with a lease-bound identity provider. The adapter owns upgrade/TLS work within
the same bounded connection task and forwards parsed requests through the
session's engine. The identity-provider seam holds no store-specific dependency.
There is no opaque pass-through or provider-compatible path mount.
