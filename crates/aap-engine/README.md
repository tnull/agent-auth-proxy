# aap-engine

Trusted composition of session-scoped policy, approval, custody, observation,
and transport. Only `Broker` creates/revokes sessions. A session handle implements
the credential-free `AgentService`; an opaque session ID cannot create a handle.
The host supplies store adapters, resolver, transport, request inspector, and
optional asynchronous approval provider. No process-global configuration or
runtime is installed. Embedding this inside an untrusted agent is not isolation.

Implemented paths include API-key brokerage, authorized catalog discovery,
fake username/password issuance, and a bounded form/JSON website login through
protected cookie access. The standalone daemon exposes the same service over
its private local binding and owns configuration reload. MCP and optional
CONNECT adapters use the same session service and authorization pipeline.
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

## Password-manager sessions

An optional `SessionOptions.items` list further narrows a resource grant to
explicit enrolled item aliases. `None` permits the items of the granted
profiles; an empty list permits none. This applies to provider keys as well as
website discovery and login. Input messages cannot override the host's grant.

Search returns at most 50 safe catalog records per page. Its opaque cursors are
session/query-bound, with at most 64 retained cursors; substring filtering is
case-sensitive. Preparation is metadata-only and pins the credential lease
without resolving a password. Issuance and execution share operation-ID
uniqueness, retained-count, and byte budgets. Duplicate issuance returns the
same active placeholders; changed input conflicts, pending work reports
`auth_in_progress`, and terminal failure/revocation cannot mint new authority.

At most 16 contexts are retained per session and 64 per broker, including
tombstones until session teardown. Context lifetime is at most ten minutes,
capped by the session and store metadata lease. Expiry/logout/version loss
invalidate fake credentials and jars. Logout is local and idempotent; remote
logout is explicitly unsupported. Metadata/version checks are asynchronous,
bounded, and repeated on use; no native invalidation-notification guarantee is
implied. Local logout does not revoke other contexts for the same item; learned
store access/version loss invalidates that session's contexts for the item.

## Supported website profile

The fixture uses JSON login metadata with virtualized CSRF, a form or JSON
credential POST, and JSON protected responses, all bounded to 256 KiB and fully
inspected before delivery. Login success needs both the profile's explicit JSON
value/status and its expected private cookies. HTTP 200 or a cookie alone is
insufficient. Ordinary nonempty website request bodies must be JSON; unsupported
content types, streaming website routes, and undeclared redirects fail closed.
Model output still streams on the separate provider path.

An optional `post_login_redirect` is the exact canonical, query-free HTTPS URL
of a separately enrolled same-origin GET route. It requires `success.status: 303`
and the usual explicit JSON success evidence plus expected private cookies in
that login response. Only a matching absolute or origin-relative Location is
accepted; the engine returns the safe canonical Location without following it.
It refuses the login page/POST target as a destination, other 3xx statuses,
cross-origin/undeclared targets, ambiguous Location headers, and known-secret
echoes in the destination. Login response bodies remain bounded sanitized JSON.
Generic HTML/empty-body redirect logins and 302 semantics are not supported.

Consume the successful response to completion before issuing a separate GET
with the same context. That operation receives its own ID, policy, approval,
DNS and store-version checks; no password body is carried forward. Dropping
the response still invalidates uncertain context state. Redirect permission
does not authorize an unseen next hop or confer permission to other resources.

One exchange per context is admitted at a time. Login attempts are limited to
five per item/session and twenty per item/broker in a ten-minute window;
issuance/logout cannot reset these counters. Approvals bind the immutable request
and lease; no password is resolved while waiting. Protected cookie operations
still enforce global/session/action and item `always` approval, with fresh store
revalidation even though they need no password resolution. Native lock and
uncertain delivery invalidate local authority rather than trigger a retry.

Private redaction patterns are retained only within bounded context state to
suppress later ordinary echoes, including after cookie/CSRF rotation. They are
cleared on observed context invalidation; this is not a memory-erasure promise
or defense against a deliberately malicious recipient's covert encoding.
Website responses are recorded in a separately placeholder-redacted view before
agent delivery; the agent still receives the fake values needed for submission.

The recorder is a bounded local memory acceptance channel. Required recording
must succeed before dispatch and before releasing each sanitized response
chunk. It is not a durable audit log or a detector approval. Observation export
is provided by the daemon; the complete planned envelope/views remain pending.
