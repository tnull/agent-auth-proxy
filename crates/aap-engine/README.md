# aap-engine

Trusted composition of session-scoped policy, approval, custody, observation,
and transport. Only `Broker` creates/revokes sessions. A session handle implements
the credential-free `AgentService`; an opaque session ID cannot create a handle.
The host supplies store adapters, resolver, transport, request inspector, and
optional asynchronous approval provider. No process-global configuration or
runtime is installed. Embedding this inside an untrusted agent is not isolation.

The initial implemented operation path is API-key brokerage. Website login,
catalog discovery, configuration reload, and daemon adapters remain pending.
Execution futures wait for approval asynchronously; independent status/cancel
calls remain usable. Dropping execution cancels preparation, or marks uncertain
delivery once dispatch starts. Response-body completion controls final status.
Repeated identical request IDs report existing state, never dispatch again;
changed bytes conflict. Results themselves are not retained for replay.

Finite ceilings currently include 64 live session handles per broker, a
one-hour session lifetime, 4,096 retained operation IDs and 8 MiB tracking per
session (64 MiB per broker), eight active dispatches per session, and sixteen
pending approvals with a shared 4 MiB retained-request ceiling. Approval waits
are capped at five minutes and operations at ten minutes/session expiry.
These are admission ceilings, not production capacity claims. Further quota,
expiry, restart/reload, and multi-thread race coverage remains part of W1/W4.

The recorder is a bounded local memory acceptance channel. Required recording
must succeed before dispatch and before releasing each sanitized response
chunk. It is not a durable audit log or a detector approval. Observation export
and the complete planned envelope/views are later integration work.
