# Agent authentication proxy plan

Status: proposed design, version 0.2. Reviewed against sources on 2026-09-22.

Build a freestanding daemon that mediates an agent's model, HTTP, TCP, and
MCP traffic, holds upstream credentials outside the agent sandbox, and exports
observable streams to independent consumers. The intended implementation
language is Rust. This plan specifies boundaries, behavior, and protocols;
crate choices, internal APIs, storage engines, task scheduling, deployment
scripts, and other implementation decisions are deliberately deferred.

## Documents

| Document | Purpose |
| --- | --- |
| [Architecture](architecture.md) | Trust boundaries, interception coverage, routing, and credential custody |
| [Common protocol](protocol-common.md) | Agent identity, authorization, request lifecycle, and local contracts |
| [Password manager](password-manager.md) | Secret-store custody, site/item discovery, and MCP fake-credential issuance |
| [Authentication](authentication.md) | Fake passwords, form substitution, private cookies, and API credentials |
| [Observability](observability.md) | Stream events, redaction, ordering, backpressure, and consumer isolation |
| [Sources and Loupe findings](references.md) | Standards assessment and evidence from the neighboring project |

MUST, MUST NOT, SHOULD, and MAY express requirements of this proposed design.
They describe the proxy's behavior and local interfaces. Upstream resources
continue to use their existing authentication protocols without modification.

## Desired outcome and security claims

An operator provisions credentials, grants, and resource profiles outside the
sandbox. The agent receives an authenticated, limited route to the daemon and
can request authorized work without receiving provider API keys, real
passwords, upstream access/refresh tokens, or authentication
cookies. Authentication is added only after destination and action checks.
The daemon is a password manager backed by a secret store: its MCP tools let
the agent discover authorized site/items and request usable fake login values.
Real values are resolved from the store only inside the trusted boundary.

The system makes two security claims:

1. **Credential isolation:** managed credentials stay outside the agent's
   environment, filesystem, request/response view, and ordinary telemetry.
2. **Mediated authority:** every admitted request is evaluated against a grant
   established by a trusted operator. Holding no password does not make an
   agent harmless; it can still exercise its granted authority.

Upstream passwords, cookies, and bearer tokens retain their native properties.
The proxy prevents the agent from obtaining these transferable credentials;
it does not promise to make a leaked upstream credential unusable. Fake
credentials may be reused within their authorized context until expiry or
revocation. Repeated business actions still require policy and application
idempotency controls.

Complete interception requires an enforced sandbox egress boundary. A daemon
or an HTTP proxy environment variable alone cannot deliver it. Credential
isolation also assumes that approved upstream recipients do not deliberately
encode and return secrets; arbitrary secret laundering by a malicious
recipient cannot be eliminated by response filtering.

## Proposed decisions

| Decision | Baseline |
| --- | --- |
| Deployment boundary | One trusted daemon outside otherwise disconnected agent sandboxes; session-bound ingress |
| Authentication | Proxy-managed passwords, private cookies, and API credentials for existing services |
| Resource adoption | No server protocol changes; enroll supported sites and their authentication profiles |
| Existing OAuth/MCP | Daemon acts as the upstream client and holds its tokens; keep local and upstream authorization separate |
| Password manager | Secret-store-backed item custody; MCP site/item lookup and placeholder credential retrieval |
| Form login | Explicit resource profiles; exact parsed-field substitution with random, context-bound fake passwords |
| Cookies | Private cookie jars partitioned by tenant, agent session, resource profile, and account |
| Inspection | TLS termination for enrolled clients; separate verified TLS to each approved upstream |
| Unsupported encryption | Reject in full-inspection mode; any permitted opaque relay is explicitly reported as opaque |
| Observation | Redacted logical streams by default; bounded export, explicit loss semantics, no detector built into this scope |
| Human interaction | Reserve a pending-approval lifecycle and immutable operation binding; UI and push/2FA integration follow later |

## Scope and limits

The initial design includes model-provider brokerage, inspected HTTP over TLS,
MCP mediation, constrained TCP relaying, a secret-store-backed password manager,
form login, private cookie sessions, API credential injection, and observation
export.
Generic TCP means byte relaying and connection policy; semantic authentication
injection requires an explicitly supported application protocol.

Out of scope: anomaly-detection algorithms, IDS rules, a universal browser
automation engine, breaking certificate pinning or application encryption,
arbitrary authentication protocol translation, new upstream authentication
protocols, a public identity federation, and product-specific human-approval
integrations. Credential delivery requires verified HTTPS.

Login bodies require bounded parsing before substitution. General upload
streaming and application authentication inside WebSocket or arbitrary TCP
sessions need explicit resource profiles. Streaming responses, including model
output, are part of the baseline. Unsupported flows must be rejected or
explicitly classified rather than silently bypassed.

## Work sequence and exit criteria

These are capability milestones, not a Rust implementation breakdown.

1. **Review and freeze the design.** Resolve the open decisions below; review
   trust boundaries, item access, placeholder lifecycle, and cookie ownership.
   Select initial providers and a small set of supported sites. Define expected
   request/response exchanges and failure scenarios before implementation.
2. **Establish confinement and provider brokerage.** Demonstrate isolated
   sessions, approved destinations, host-held provider credentials, streamed
   responses, revocation, and prevention of provider-side network bypasses.
   Prove that direct IPv4, IPv6, DNS, and alternate transport egress cannot
   escape the selected deployment policy.
   Include basic redacted observation from the first mediated requests.
3. **Deliver password management and form login.** Add the TLS mediation needed
   for the selected sites, secret-store-backed MCP item lookup, fake credential
   retrieval, form submission, and private cookies. Verify CSRF handling,
   context-bound reuse, expiry, rotation, redirects, logout, and failures without
   exposing real authentication material to agents or observation consumers.
4. **Broaden observation and transport coverage.** Extend HTTPS/MCP mediation,
   approved TCP streams, explicit opaque classifications, bounded export,
   consumer reconnects, and overload behavior. Expand supported sites through
   reviewed resource profiles.
5. **Add human interaction and further service integrations.** Define trusted
   approval/unlock flows and any required OAuth user interaction. Preserve the
   original operation binding and recheck authority and credential state after
   waiting for a person or refreshing an upstream session.

Each capability needs both positive and negative acceptance scenarios in its
specification. Later regression tests must be demonstrated to fail on the
pre-fix code as well as pass on the fix. This planning change contains no
implementation or executable tests.

## Decisions to settle before implementation

- Which agent runners and sandbox platforms define the first enforceable
  deployment? A host-local boundary is assumed here; a remote ingress trust
  protocol is a separate design task.
- Which initial model API surfaces, MCP transports, TCP protocols, and login
  sites must be supported? Each needs an explicit capability and limit profile.
- Which operations require human approval, and which consumer outages must
  block traffic? The proposed defaults are bounded best-effort observation and
  denial of operations needing an unavailable approval mechanism.
- What retention, sensitive-payload access, and operational recovery policies
  apply? These choices must be fixed before handling real user traffic.

These choices narrow a reviewed baseline; they must not weaken mandatory
destination binding, credential isolation, or session isolation.
