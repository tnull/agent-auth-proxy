# Agent authentication proxy plan

Status: proposed design, version 0.1. Reviewed against sources on 2026-09-22.

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
| [Challenge-response authentication](auth-challenge-response.md) | Exact proposed one-use authentication profile for cooperating resources |
| [Legacy authentication](auth-legacy.md) | Fake passwords, form substitution, private cookies, and existing API credentials |
| [Observability](observability.md) | Stream events, redaction, ordering, backpressure, and consumer isolation |
| [Sources and Loupe findings](references.md) | Standards assessment and evidence from the neighboring project |

MUST, MUST NOT, SHOULD, and MAY express requirements of this proposed design.
They do not imply that the project-specific protocol is an Internet standard.
The proposed wire profile and its field names require review before release.

## Desired outcome and security claims

An operator provisions credentials, grants, and resource profiles outside the
sandbox. The agent receives an authenticated, limited route to the daemon and
can request authorized work without receiving provider API keys, real
passwords, signing keys, upstream access/refresh tokens, or authentication
cookies. Authentication is added only after destination and action checks.
The daemon is a password manager backed by a secret store: its MCP tools let
the agent discover authorized site/items and request usable fake login values.
Real values are resolved from the store only inside the trusted boundary.

The system makes three separate claims:

1. **Credential isolation:** managed credentials stay outside the agent's
   environment, filesystem, request/response view, and ordinary telemetry.
2. **Mediated authority:** every admitted request is evaluated against a grant
   established by a trusted operator. Holding no password does not make an
   agent harmless; it can still exercise its granted authority.
3. **Replay resistance:** the new protocol admits each resource challenge at
   most once. Existing password, cookie, and bearer-token servers retain their
   native replay properties; local one-use placeholders cannot upgrade them.

Complete interception requires an enforced sandbox egress boundary. A daemon
or an HTTP proxy environment variable alone cannot deliver it. Credential
isolation also assumes that approved upstream recipients do not deliberately
encode and return secrets; arbitrary secret laundering by a malicious
recipient cannot be eliminated by response filtering.

## Proposed decisions

| Decision | Baseline |
| --- | --- |
| Deployment boundary | One trusted daemon outside otherwise disconnected agent sandboxes; session-bound ingress |
| New authentication | `AAP-CR/1`, a project profile of HTTP Message Signatures with mandatory resource-issued, single-use challenges |
| Resource adoption | Resource or trusted resource-side gateway must implement challenge issuance and verification |
| AAuth | Track as an interoperability option; do not claim its current draft alone satisfies strict one-use replay protection |
| Existing OAuth/MCP | Daemon acts as the upstream client and holds its tokens; keep local and upstream authorization separate |
| Password manager | Secret-store-backed item custody; MCP site/item lookup and placeholder credential retrieval |
| Legacy forms | Explicit resource profiles; exact parsed-field substitution with random, one-use fake passwords |
| Cookies | Private cookie jars partitioned by tenant, agent session, resource profile, and account |
| Inspection | TLS termination for enrolled clients; separate verified TLS to each approved upstream |
| Unsupported encryption | Reject in full-inspection mode; any permitted opaque relay is explicitly reported as opaque |
| Observation | Redacted logical streams by default; bounded export, explicit loss semantics, no detector built into this scope |
| Human interaction | Reserve a pending-approval lifecycle and immutable operation binding; UI and push/2FA integration follow later |

The AAuth assessment is based on revision `draft-hardt-oauth-aauth-protocol-10`,
especially section 12.8.4.2, which does not define a nonce mechanism and leaves
within-window replay caching optional. It is a work in progress, not an adopted
standard. [AAuth draft](https://datatracker.ietf.org/doc/html/draft-hardt-oauth-aauth-protocol-10#section-12.8.4.2)

## Scope and limits

The initial design includes model-provider brokerage, inspected HTTP over TLS,
MCP mediation, constrained TCP relaying, host-held credentials, strict new
authentication, legacy form/cookie compatibility, and observation export.
Generic TCP means byte relaying and connection policy; semantic authentication
injection requires an explicitly supported application protocol.

Out of scope: anomaly-detection algorithms, IDS rules, a universal browser
automation engine, breaking certificate pinning or application encryption,
arbitrary authentication protocol translation, a public identity federation,
and product-specific human-approval integrations. Plaintext HTTP credential
delivery is not a compatibility mode.

Unbounded request uploads, authentication trailers, and per-message
authentication inside WebSocket or arbitrary TCP sessions need additional
profiles. Streaming responses, including model output, are part of the
baseline. Unsupported flows must be rejected or explicitly classified rather
than silently bypassed.

## Work sequence and exit criteria

These are capability milestones, not a Rust implementation breakdown.

1. **Review and freeze the design.** Resolve the open decisions below; review
   threat boundaries and both protocol state machines. Produce independent
   wire vectors and a resource-verifier interoperability fixture. No production
   security claim depends on illustrative values in these documents.
2. **Establish confinement and provider brokerage.** Demonstrate isolated
   sessions, approved destinations, host-held provider credentials, streamed
   responses, revocation, and prevention of provider-side network bypasses.
   Prove that direct IPv4, IPv6, DNS, and alternate transport egress cannot
   escape the selected deployment policy.
3. **Deliver observation and transport mediation.** Cover HTTPS termination,
   MCP requests/results, approved TCP streams, explicit opaque classifications,
   redaction, bounded buffering, consumer reconnects, and overload behavior.
4. **Deliver strict challenge-response.** A cooperating resource verifies the
   profile. Exercise concurrent replay, modified payload/query/header attacks,
   expired challenges, authorization revocation, restart, and multiple verifier
   instances. No protected side effect occurs before verification and admission.
5. **Deliver password management and legacy compatibility.** Demonstrate
   secret-store-backed MCP item lookup, fake credential retrieval, form login, CSRF
   handling, cookie rotation, session isolation, redirects, logout, and error
   paths without exposing real authentication material to the agent or normal
   observation consumers.
6. **Add interoperability and human interaction.** Select pinned AAuth/OAuth
   profiles and human approval mechanisms. Preserve the original request
   binding when approval, token refresh, or resource challenges expire.

Each capability needs both positive and negative acceptance scenarios in its
specification. Later regression tests must be demonstrated to fail on the
pre-fix code as well as pass on the fix. This planning change contains no
implementation or executable tests.

## Decisions to settle before implementation

- Which first resource will implement `AAP-CR/1`, and who operates its
  verifier? Without that participant, only compatibility modes are usable.
- Which agent runners and sandbox platforms define the first enforceable
  deployment? A host-local boundary is assumed here; a remote ingress trust
  protocol is a separate design task.
- Which initial model API surfaces, MCP transports, TCP protocols, and legacy
  sites must be supported? Each needs an explicit capability and limit profile.
- Which operations require human approval, and which consumer outages must
  block traffic? The proposed defaults are bounded best-effort observation and
  denial of operations needing an unavailable approval mechanism.
- What retention, sensitive-payload access, and operational recovery policies
  apply? These choices must be fixed before handling real user traffic.

These choices narrow a reviewed baseline; they must not weaken mandatory
destination binding, credential isolation, replay state, or session isolation.
