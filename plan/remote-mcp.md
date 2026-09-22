# Remote MCP mediation

Status: W7 target contract; enrollment, private protocol state, and initial
HTTPS engine paths are implemented. Complete control/cleanup integration and
actual daemon acceptance fixtures remain pending. See
[implementation evidence](../docs/proof-of-concept.md#remote-mcp-message-boundary).
This complements the
[local MCP tools](mcp.md); it does not replace their seven-tool interface or
introduce an authentication protocol. Names remain provisional.

## First supported profile

Pin upstream MCP independently to `2025-11-25`, using Streamable HTTP over
verified HTTPS. The daemon is the upstream client. Start with one exact endpoint
per resource and one explicitly enrolled account, using a store-held API key or
preprovisioned bearer credential. This proves credential custody and protocol
mediation, not OAuth discovery, refresh, or general MCP authorization support.
An authentication challenge cannot select a new credential, account, or URL.

The transport baseline sends individual messages by POST, accepts both JSON
and SSE responses, and expects empty HTTP 202 responses to accepted
notifications. Initialization can establish an upstream `MCP-Session-Id`;
subsequent requests carry it and the negotiated `MCP-Protocol-Version`.
Session invalidation requires fresh initialization. These wire requirements
come from the pinned [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
The narrower behavior below is project policy, not a claim that every conforming
MCP server supports this profile.

The initial profile excludes background GET streams, SSE resumption, automatic
reconnection, redirects, transport fallback, dynamic tool enrollment, tasks,
sampling, elicitation, roots, resources, prompts, and arbitrary server requests.
A server that requires any excluded feature is incompatible. In particular,
servers that close a POST stream expecting GET resumption are not supported;
the daemon reports incomplete delivery instead of following a reconnect hint.
Broader compatibility needs a separately reviewed profile and tests.

## Enrollment and agent binding

The private resource profile fixes the HTTPS origin and endpoint path, address
policy, credential item, permitted methods, tool names, reviewed argument/result
contracts, approval rules, and limits. Reject query-bearing endpoints for this
first profile. Enrollment must not overlap a generic pass-through route that
could bypass MCP message validation using the same credential.

The first catalog validator also disallows non-MCP profiles at the same
origin/path, regardless of method/query, and sharing an enrolled store/key
reference between MCP and non-MCP bindings. Do not infer secret equality across
different records or adapter aliases; deliberate duplicate enrollment remains
an operator responsibility. Non-secret tool contracts live in `aap-types` so
configuration validation does not import the trusted remote adapter or SDK.

Use the existing `request.execute` operation to carry bounded MCP HTTP requests;
inspected HTTP ingress must reach the same engine path. The local seven-tool
server does not aggregate remote tools or dynamically add tool names. Its
`request.execute` result remains the HTTP response envelope, with a sanitized
JSON or SSE body. Ordinary MCP clients can use admitted HTTP ingress; this is
not a promise that arbitrary clients can use the local JSON operation API.

Bind one current upstream MCP context to each local session/resource/account.
The resource selects its enrolled account; website `auth_context` selection is
invalid here. Two independent remote MCP conversations require distinct local
sessions in the first profile. Concurrent initialization of one binding fails
without replacing its existing context. Restarting an agent-side bridge cannot
reset the context or operation history.

The agent-facing endpoint exposes no upstream session header. Its trusted local
attachment identifies the binding; it does not require an agent-visible copy
of the upstream token. Reject caller-supplied authentication, cookie,
`MCP-Session-Id`, and `Last-Event-ID` headers. Validate any caller version header
against the pin; generate upstream transport headers inside the daemon.
No proxy context identifier is transmitted as upstream identity.

## Lifecycle and private state

Initialization sends the pinned version, empty client capabilities, and fixed
proxy implementation metadata. Do not forward agent-provided capabilities,
names, icons, instructions, or arbitrary metadata upstream. Require a compatible
version and the tools capability. Expose only the supported tools capability
and safe proxy metadata downstream; unused server capabilities do not become
agent authority. The initialized notification completes the handshake before
tool work. This follows [MCP lifecycle negotiation](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

```text
absent -> initializing -> awaiting_initialized -> ready -> closed
             |                   |                 |
             +-------------------+-----------------+-> invalid

closed / invalid -> explicit fresh initialization, if still authorized
```

Record the private upstream session ID, negotiated version, credential version,
configuration generation, lifetime, and in-flight request mapping. A server
that omits the session header still gets a local lifecycle context. The upstream
ID is private authentication-related state even if the server does not treat
it as sufficient authentication. It must never enter agent results, ordinary
logs, observation payloads, catalog files, or content-derived identifiers.

Accept a bounded, syntactically valid session header only from a complete,
validated initialization response. Duplicate or later replacement headers are
protocol failures, not silent session rotation. Capture its value for response
echo suppression before releasing any response bytes. Reject private cookies as
an additional authentication mechanism in this profile; never import a website
cookie jar into an MCP context.

Failed or incomplete initialization invalidates its provisional context.
An initialization response alone never admits tools before the initialized
notification is accepted. Bound the whole handshake, including agent delay;
late responses cannot resurrect a timed-out or revoked generation.

Upstream 404 on a session-bearing request invalidates the context. The next
permitted interaction must explicitly initialize without the stale header;
never automatically reinitialize and replay the failed tool call. Credential
change, store access loss, policy change, expiry, or local session revocation
also prevents further context use. Revalidate custody and policy on every
dispatch, including when an upstream session already exists.

Explicit endpoint DELETE closes local context authority immediately and may
attempt bounded upstream cleanup under current policy. Remote 405, timeout, or
refusal cannot undo local closure or imply that remote work was rolled back.
Do not dispatch cleanup with a revoked credential. Daemon shutdown discards
private context state regardless of whether remote cleanup is possible.

For the first binding, an admitted DELETE has no body and returns local HTTP
204 with `x-aap-remote-cleanup` set to `confirmed`, `not_supported`, `skipped`, or
`unknown`. This local status confirms closure only, never business rollback.
Only a complete empty upstream 200/204 confirms cleanup; a complete empty 405
reports unsupported termination. Other statuses, unsafe headers/trailers,
nonempty bodies, interrupted delivery, and timeouts report uncertainty after
dispatch. Policy/custody/capacity denial before dispatch reports skipped, as
does an absent, already closed, expired, or stateless context with no native
session to terminate. No raw upstream response is returned.

Cleanup gets a separately admitted child operation, not a new human wait or a
background retry. Concurrent fresh initialization is refused while this local
cleanup attempt is owned; completion, cancellation, or its two-second deadline
releases that barrier without reviving the closed generation. The fixed-value
cleanup header is safe local metadata that the credential-free MCP tool binding
may expose; other private proxy headers retain their existing filtering rules.

## Messages, tool policy, and responses

Parse strict UTF-8 JSON with duplicate-member, depth, token, and size checks.
Accept one JSON-RPC message per request, not batches. Validate its envelope and
method-specific fields before store resolution. Distinguish the application
operation ID from the MCP request ID and the private upstream request ID.
Allocate non-reused upstream IDs within each context generation; rewrite only
the corresponding response ID on delivery. Reject concurrent duplicate agent
IDs and responses for unknown, completed, or other-context requests.

| Message | First-profile behavior |
| --- | --- |
| `initialize` | Only on a new context; validate and reconstruct the handshake |
| `notifications/initialized` | Only for the matching provisional context; complete readiness after upstream acceptance |
| `ping` | Bounded correlated request; allowed during negotiation without advancing it |
| `tools/list` | One bounded upstream page; expose only enrolled, session-permitted definitions |
| `tools/call` | Validate exact tool name and arguments against the enrolled contract before approval or credential access |
| `notifications/cancelled` | Map only an owned, live request; apply the cancellation rules below |
| Other agent methods, responses, or notifications | Refuse; do not forward speculative capabilities |

For the first fixture, enroll a text echo tool and a side-effecting counter tool.
Their reviewed contracts use bounded strings/integers and reject extra fields;
no general JSON Schema execution engine is needed. The upstream tool list must
contain compatible definitions for enrolled tools. A schema change or pagination
requirement fails explicitly rather than silently widening or truncating the
list. Use operator-approved descriptions and schemas downstream; unlisted tools
and upstream descriptions do not become instructions or authorization policy.

MCP defines listing, calls, typed content, and tool errors; see the pinned
[tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
Our first result profile accepts bounded text blocks, optional structured JSON,
and `isError`. Strip undeclared metadata and reject binary content, resource
links, embedded resources, or incompatible result shapes. Sanitize both text
and structured representations before delivery. Render upstream JSON-RPC errors
as fixed safe messages without arbitrary error data. Never fetch a URL from a
description, result, schema, or error.

For JSON responses, validate the whole message before release. For SSE, parse
bounded events incrementally, then validate and sanitize the contained JSON
message before releasing it. Do not apply byte replacement that can corrupt
JSON framing. Ignore bounded comments and empty priming events; retain no resume
cursor and expose no raw event IDs or retry hints. Apart from supported ping
requests, allow one matching final response; premature EOF, extra messages, or
malformed framing are incomplete/protocol failures. Buffer this response
through stream termination before declaring it complete; this profile does not
provide tool progress streaming. Emit reconstructed safe SSE when SSE was used.

Server-initiated ping is the only supported server request: answer through an
engine-admitted, observed child operation with reserved control capacity.
Sampling, elicitation, roots requests, progress/list-change notifications, and
other server messages invalidate the context before those messages reach the
agent. Never execute a server request using a second unmediated model client,
filesystem adapter, browser, or tool runner.

## Approval, cancellation, and uncertain outcomes

Freeze the resource, account, tool, arguments, limits, and context generation
for approval. Item/global/session/action policies remain restrictive; a tool's
annotations cannot label it harmless or waive approval. API-key insertion still
counts as authentication on every request. A private MCP session is not an
approval lease. Pending work holds no newly resolved credential, and status or
cancellation must remain serviceable while an approval is outstanding.

Cancellation before dispatch stops local work without an upstream notification.
After dispatch, best-effort cancellation targets only the original mapped
upstream request and context. Never forward an agent-supplied reason string or
interpret an arbitrary MCP ID as an application operation ID. Initialization
does not receive a cancellation notification; abort and invalidate its context
instead. Unknown/completed IDs are ignored. These restrictions preserve the
pinned [MCP cancellation contract](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation).

A cancellation notification or ping response is a separate bounded child
dispatch, subject to current destination, custody, approval, and observation
checks. Reserve capacity, not permission. If item policy requires approval
and none covers that child dispatch, skip it and record a safe reason; local
cancellation must not wait for a new human decision. No background cleanup loop
may retain a password or bypass revocation to finish a cancellation.

Neither disconnect, cancellation acknowledgment, nor context invalidation
proves that a tool did not run. Mark dispatched work without a trustworthy
result as `outcome_unknown`; retain its deduplication record. Ignore late
cancelled results for delivery and private-state mutation. A new bridge, fresh
handshake, changed MCP ID, or request-status poll cannot replay the operation.
An explicit new application operation is separately authorized and does not
promise upstream idempotency.

## Observation and bounds

Correlate sanitized HTTP and parsed JSON-RPC views with the engine operation,
private context generation's independently assigned safe alias, and any child
dispatch. Do not use upstream session IDs or their hashes for correlation.
Record lifecycle changes and filtering/rewriting as safe metadata. Protocol
failure records its class, not rejected raw payloads. Required observation
admission precedes each dispatch and release of sanitized content.

Known-value suppression includes credentials, captured session IDs, and denied
cookie values, across decoded JSON strings and output representations. As with
website authentication, a malicious upstream recipient can deliberately encode
secrets; this is not a universal exfiltration filter. Remote tool-internal egress
is outside observation unless independently mediated.

These proposed ceilings narrow the shared operation limits:

| Resource | Ceiling |
| --- | --- |
| MCP contexts | 16 per local session, 64 per broker, including provisional/terminal tracking |
| Context lifetime / complete handshake | 10 minutes, capped by session/grant / 30 seconds |
| JSON-RPC request / total upstream response | 256 KiB / 1 MiB |
| Decoded JSON depth / structural tokens | 64 / 32,768 |
| SSE line / event / events per response | 256 KiB / 1 MiB / 128, including empty events |
| Session header / JSON-RPC string ID | 1 KiB / 128 UTF-8 bytes |
| Enrolled tools / upstream list entries | 32 / 64, one page |
| Active work / additional control operations | 8 / 2 per local session, shared across MCP contexts |
| Aggregate protocol buffers | 8 MiB per local session, 64 MiB per broker |
| Control cleanup attempt | 2 seconds, also capped by current authority lifetime |

Count encoded and decoded buffers, queued work, mappings, and reconstructed
output together. Apply the tighter shared limits where these overlap; reserved
control capacity cannot increase ordinary work admission. Neither keepalives
nor server messages extend the absolute deadline. Reject before allocating
unbounded state, never truncate a result into apparent success.

## Delivery and acceptance

Keep credential-free local bindings in `aap-mcp`. Introduce a trusted reusable
`aap-mcp-upstream` crate for remote protocol validation, private session state,
ID mapping, and safe message transformations. It has no independent connector,
store lookup, approval authority, or background retry loop. `aap-engine` owns
dispatch/lifecycle orchestration; `aap-auth` supplies shared secret suppression;
`aap-transport` remains the only upstream connection path. No SDK types enter
`AgentService`, and no custody dependency enters `aap-client` or `aap-mcp`.

Implement in reviewable steps: profile/admission validation, pure lifecycle and
message tests, engine custody/dispatch integration, then real daemon fixtures.
Write failing behavior tests before each production step. W7 remains incomplete
until the real HTTPS fixture demonstrates:

- JSON and SSE initialization/list/call paths, a private session header, an
  empty notification response, and explicit local/remote close outcomes.
- Two sessions and accounts cannot share upstream state, IDs, results, or
  cancellation authority; bridge restart does not reset that boundary.
- Undeclared tools/arguments, alternate routes, capabilities, versions, bad
  schemas, server requests, and caller session headers fail without escalation.
- Secret/session echoes, JSON escaping, SSE chunk splits, upstream errors,
  trailers, and rejected payloads do not leak through either agent or observer.
- Approval stays pending without credential resolution; cancellation remains
  responsive; late replies cannot revive cancelled or revoked state.
- A counter increment received upstream followed by disconnect is dispatched
  once and reported uncertain; 404/reinitialization cannot replay it.
- Limits, slow peers, session rotation attempts, store changes, and observation
  overload remain bounded and fail with honest dispatch/completion state.

Publish supported limitations alongside the fixture transcript. Do not describe
this constrained upstream profile as a general-purpose MCP gateway.
