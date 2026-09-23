# aap-http

Bounded local HTTP adaptation of a host-bound `AgentService`. The host supplies
a listener, its expected peer UID, and the session handle. This crate neither
selects secret stores nor grants authority from request headers. Linux private
socket creation belongs to `aap-config`; confinement remains the host's job.

The binding exposes the versioned session operation/vault and TCP stream API,
never operator routes. It preserves sanitized response streaming and fixed
typed errors. A host can additionally enable [CONNECT inspection](../../docs/connect.md)
with a lease-bound identity provider. The adapter owns upgrade/TLS work within
the same bounded connection task and forwards parsed requests through the
session's engine. The identity-provider seam holds no store-specific dependency.
CONNECT has no opaque fallback; raw TCP requires separate explicit enrollment.
Provider-compatible path mounts remain separate work.

The [TCP endpoint](../../docs/tcp.md) checks bounded opening metadata before
HTTP normalization, separates admission/101 from connection work, and owns
framed application forwarding through the same engine. Explicit directional
end is not attachment EOF or terminal success. Partial output frames cannot
receive inserted terminal records, and final control delivery is bounded.
The existing `httparse` package is used directly for raw singleton/header checks;
ordinary session HTTP and CONNECT still use Hyper with preserved read-ahead.

Each session listener allows 32 connections and at most 28 work connections,
reserving four for bounded classification and status/cancel. Work permits stay
held across response bodies, CONNECT, and streams. This is not protection from
flooding every classifier. The complete incoming session metadata request has
one ten-second deadline; approval and TCP lifetime use separate phase timers.
