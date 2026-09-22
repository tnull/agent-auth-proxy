# aap-http

Bounded local HTTP adaptation of a host-bound `AgentService`. The host supplies
a listener, its expected peer UID, and the session handle. This crate neither
selects secret stores nor grants authority from request headers. Linux private
socket creation belongs to `aap-config`; confinement remains the host's job.

The initial binding exposes only the versioned session operation/vault API,
never operator routes. It preserves sanitized response streaming and fixed
typed errors. Provider-compatible mounts, CONNECT interception, and ordinary
forward-proxy requests are separate pending adapters, not opaque pass-through.
