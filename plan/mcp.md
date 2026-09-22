# MCP adapter and agent tool contract

Status: proposed behavior, not implementation evidence. This completes the
local MCP binding of the [common operations](protocol-common.md) and
[password-manager tools](password-manager.md). It introduces no upstream
authentication protocol. Product and crate names remain provisional.

## Boundary and compatibility

Pin the first adapter to MCP `2025-11-25`. Initialize, negotiate that supported
version, and wait for `notifications/initialized` before admitting tool work.
An unsupported requested version receives the supported version through MCP
negotiation; this is not permission to interpret incompatible messages.
Advertise only tools, without dynamic list-change notifications. Do not
advertise tasks, sampling, elicitation, resources, prompts, or logging.
See the pinned [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

`aap-mcp` translates messages to a host-bound `AgentService`. It owns no store,
credential resolution, cookie jar, policy exception, or approval authority.
For a sandboxed agent, `mcp-bridge SESSION_SOCKET` composes this adapter with
`aap-client`; it must neither load private daemon configuration nor open a
store. A trusted embedding supplies an in-process session handle instead.
Both paths use the same engine checks and session-wide budgets.

The bridge has one fixed session attachment for its lifetime. MCP client names,
JSON-RPC IDs, tool arguments, and reconnections cannot select a different
identity. Restarting a bridge does not reset the daemon's session, operation-ID
history, login limits, or authentication contexts.

Use the official Rust SDK's protocol types only inside the adapter. Own the
bounded connection loop so admission precedes task spawning and an SDK payload
logger cannot bypass the host's observation policy. Disable unused features;
add no OAuth client, independent HTTP connector, or additional schema framework
for speculative future use. Resolve and test an exact compatible SDK version
when implementing the adapter; pinning MCP does not itself pin a Cargo package.

## Local tool surface

Tool names are case-sensitive and stable within this profile:

| Tool | Arguments and result | Engine operation |
| --- | --- | --- |
| `vault.search_items` | Authorized catalog search and bounded pagination | Item discovery |
| `vault.get_login` | Item, URI, operation ID; returns fake credentials and context | `auth.prepare` |
| `vault.auth_status` | Context; returns safe account/state metadata | `auth.status` |
| `vault.logout` | Context; returns local revocation and separate remote outcome | `auth.logout` |
| `request.execute` | Explicit bounded HTTPS request; returns safe response or existing operation state | `request.execute` |
| `request.status` | Operation ID; returns state without dispatching | `request.status` |
| `request.cancel` | Operation ID; requests cancellation and returns current state | `request.cancel` |

The four vault schemas remain defined in [password-manager.md](password-manager.md).
The fixed seven-tool list fits one page; no `nextCursor` is returned and an
unexpected nonempty list cursor is invalid. Vault *item* pagination is separate.

Each tool advertises an object input schema with required fields and
`additionalProperties: false`. Reject duplicate JSON members before conversion
to an object can discard them, including nested tool arguments. Standard MCP
envelope fields follow the pinned version; they are not extra application
arguments. MCP annotations are descriptive hints, never authorization rules.

Return the safe application object in `structuredContent` and the same object
serialized in one text content block. Do not return resource links or binary
attachments that cause the client to fetch a second, unmediated URL. If output
schemas are advertised, they must cover every emitted success/error variant.
These envelopes follow the pinned [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools);
the tool names, payloads, and limits here are project-specific.

## `request.execute`

This is the constrained internet-access tool, not a raw socket or arbitrary
HTTP client. Its input matches the shared credential-free request contract:

```json
{
  "request_id": "BASE64URL_16_BYTES",
  "resource": "work-site",
  "auth_context": "BASE64URL_32_BYTES",
  "method": "GET",
  "target": "https://accounts.example/protected",
  "headers": [["accept", "application/json"]],
  "body_base64": ""
}
```

`request_id`, `resource`, `method`, and `target` are required. Omitted/null
`auth_context` means no selected website context; a profile may require one.
Omitted `headers` and `body_base64` mean an empty list and zero bytes.
`resource` is an enrolled alias supplied in non-secret session setup, not an
agent-supplied store reference. Selecting it cannot grant access to its routes.

Encode exact body bytes using canonical padded standard base64, even for UTF-8
forms or JSON; the empty string encodes an empty body. Do not infer encodings,
double-decode forms, or accept both text and binary body members. Headers are
ordered name/value pairs, with route-specific duplicate and allowlist checks.
Caller authentication, cookie, routing, and hop-by-hop headers do not establish
authority. The engine remains responsible for rejecting unsupported headers,
destination checks, structural substitution, and private response handling.

A fully collected, sanitized response produces this application object:

```json
{
  "kind": "response",
  "request_id": "BASE64URL_16_BYTES",
  "status": 200,
  "headers": [["content-type", "application/json"]],
  "body_base64": "eyJvayI6dHJ1ZX0=",
  "complete": true
}
```

`complete:true` describes successful delivery of the bounded response, not
business success. An upstream 401 or 500 can be a complete response. The
authentication profile separately determines whether a login succeeded.
Never present truncated content as a complete result. Only engine-sanitized
headers and body enter this envelope; private cookies and internal daemon
control headers cannot pass through it.

A duplicate operation ID with unchanged input returns existing state, without
reissuing the HTTP request or inventing a cached response:

```json
{
  "kind": "operation",
  "operation": {
    "request_id": "BASE64URL_16_BYTES",
    "state": "pending_approval",
    "status": null
  }
}
```

The adapter derives this distinction from the service's typed/private control
result, never from a resource's body or caller-controlled header. A resource
returning JSON that resembles operation metadata remains an ordinary response.
Changed input under the same ID yields `request_conflict`.

## Status, approval, and cancellation

`request.status` and `request.cancel` both require exactly
`{"request_id":"BASE64URL_16_BYTES"}`. Their application result has exactly
`request_id`, `state`, and `status`, as in the operation object above. `status`
is an HTTP status integer or null, not proof of business success. State values
come from the [common state machine](protocol-common.md#operation-state-machine).
Unknown and other-session IDs do not disclose another session's work.

Keep two ID spaces separate: JSON-RPC IDs correlate messages on this MCP
connection; application `request_id` values identify immutable work in the
daemon session. Reusing a JSON-RPC ID never provides operation deduplication.
Reject concurrent duplicate JSON-RPC IDs rather than ambiguously routing a
response or cancellation.

An original tool call may await approval asynchronously. While it waits,
independent status/cancel calls must still be serviced and no newly resolved
password may be retained. Polling reports `pending_approval`; it cannot grant
approval. This needs neither MCP tasks nor agent-side elicitation. Trusted
approval-provider events and future signed decisions remain separate from MCP.

Translate `notifications/cancelled` through a bounded mapping of the current
connection's in-flight JSON-RPC IDs to their owned application operations.
Ignore unknown or already completed IDs; never translate an arbitrary numeric
or string ID directly into daemon cancellation authority. Cancelling a status
query, or a duplicate submission returning existing state, must not cancel the
original execution. Cancellation of a live execution drops that owned service
invocation and normally suppresses its MCP response. In-process engine guards
handle the drop; a remote client closes only that invocation's transport. Do
not issue blind operation-level cancellation for a possibly duplicate invocation.
The explicit `request.cancel` tool asks the daemon to cancel the identified
operation and remains available across bridge reconnections; inspect status
afterward rather than assuming remote cancellation. See
[MCP cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation).

On local stdio shutdown, cancel service invocations owned by that bridge and
bound cleanup time. If the daemon is unreachable or the process is
killed, cleanup is not guaranteed: engine deadlines remain authoritative.
Closing the bridge does not revoke the host-created session or undo a remote
action. Reconnect to the same attachment to inspect state; never replay work
automatically. This local shutdown policy is not a rule that an upstream MCP
HTTP disconnection cancels its remote request.

## Errors and finite resource limits

Malformed MCP envelopes and unknown methods/tools produce appropriate JSON-RPC
errors with fixed safe messages. For a structurally valid call to a known tool,
invalid application arguments produce an `isError:true` result with
`request_invalid`; engine denials and failures use their common error codes.
These tool results contain `code` and optional `request_id`. No error includes
reflected input,
raw SDK diagnostics, native store details, or an upstream authentication body.
An HTTP error status alone does not turn a complete response into a protocol
error. Neither error class authorizes retries, account changes, or fallback.

Proposed starting adapter ceilings, subordinate to all engine/profile limits:

| Budget | Ceiling |
| --- | --- |
| Incoming encoded MCP message | 2 MiB |
| Outgoing encoded MCP message, including both result representations | 4 MiB |
| JSON container nesting / string JSON-RPC ID | 64 levels / 128 UTF-8 bytes |
| JSON structural tokens before parsing | 32,768 |
| Decoded HTTP request / tool-collected response | 1 MiB each; authentication profile remains 256 KiB |
| Application headers | 64 pairs and 16 KiB total names/values |
| Concurrent work tool calls per bridge | 8 |
| Additional status/cancel calls per bridge | 2 reserved slots |
| Aggregate retained adapter messages/results | 16 MiB per bridge; reject admission before allocation |
| Initialization / partial-input inactivity / stalled output | 10 seconds / 10 seconds / 10 seconds |
| Tool-call lifetime / shutdown cleanup | 10 minutes, capped by engine deadlines / 2 seconds |

Enforce bounds before SDK task spawning or unbounded frame/result allocation.
Budget queued input, output duplication/escaping, and pending handlers together;
adding a semaphore after an unbounded task queue is insufficient. Apply the
JSON nesting and ID-length limits during parsing. Status and cancellation
capacity must remain available while work slots await human decisions.

Stdio carries UTF-8 newline-delimited MCP messages only; reserve stdout entirely
for those messages, and keep stderr diagnostics safe. Enforce framing limits
incrementally, including when a sender never supplies a newline. The pinned
[transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
defines the framing; these ceilings and cleanup rules are local policy.

`request.execute` buffers only the bounded safe result. Model streaming uses
the separately admitted HTTP interface; do not turn an unbounded stream into
one enormous MCP tool result. A result-limit or output failure after dispatch
does not prove non-execution: preserve the daemon's authoritative state and
return a safe error when possible, without redispatch or silent truncation.

## Remote MCP and verification gates

The local password-manager server and remote MCP mediation are different
roles. W5 can complete its local contract without claiming W7 remote coverage.
Remote Streamable HTTP must use engine-admitted connections and credential
injection, with private upstream session state partitioned by local session,
resource, and account. No SDK default connector, reconnect loop, redirect,
server-initiated request, or authentication discovery may bypass that boundary.
Its separate fixture must prove JSON/SSE response handling, explicit version
negotiation, session invalidation, cancellation, and no automatic tool replay.
The [remote MCP contract](remote-mcp.md) now pins that first upstream profile,
its lifecycle and limits, and the separate trusted adapter boundary. Its
proposed behavior must not be mistaken for completed remote transport support.

Before claiming local MCP support, demonstrate:

- Wire-level initialization, tool discovery, schema rejection, duplicate-member
  rejection, safe errors, and all seven tools through actual stdio framing.
- The full fake-credential website flow through a real daemon and bridge,
  repeated for a second isolated session and with an independent observer.
- Approval remains pending while status/cancel work; no password resolution
  before approval, and late approval cannot revive cancelled work.
- MCP/application ID separation, duplicate execution, connection loss after
  upstream reception, bridge restart, and cancellation races preserve state.
- Oversized/partial frames, slow output, saturated work slots, and malicious
  JSON cannot create unbounded buffers, tasks, or secret-bearing diagnostics.
- The same adapter works with a trusted embedded service; an external client
  builds without engine, store, private-cookie, or CA-key dependencies.

Schemas, wire transcripts, limit tests, and dependency inspection are delivery
artifacts. This planning document alone completes none of those gates.
