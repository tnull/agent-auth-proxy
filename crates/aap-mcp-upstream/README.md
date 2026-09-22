# aap-mcp-upstream

Trusted, connector-free validation and transformation for the pinned remote
MCP profile. This crate is not an agent client or a complete remote gateway.
See [the contract](../../plan/remote-mcp.md).

The component supplies reviewed tool contracts, bounded request/response
validation, structural response sanitization, incremental SSE framing, and
private upstream context/handshake state. The caller must bind contexts to local
sessions/resources/accounts and enforce admitted destinations, current
credential/policy versions, approval, quotas, observation, and cancellation.
Validated messages do not authorize a connection or credential use.

The engine now has real HTTPS initialization/list/call and admitted server-ping
child tests; cancellation/cleanup integration and actual daemon remote-MCP
fixtures remain pending. `validate_control_ack` checks a control POST's status
and headers; the host must also require an empty, trailer-free body through EOF.
Do not advertise a complete remote gateway from these component tests alone.
This crate starts no runtime or connector and
does not retrieve credentials or launch background work. SDK types remain
private to its implementation.

`Tool` and `Argument` are re-exports of the credential-free reviewed contract
in `aap-types::mcp`. Enrollment and this adapter use the same finite validation;
policy configuration does not need to import the MCP SDK or this custody crate.

Tool profiles permit required bounded text and integer fields only. Text
limits count Unicode scalar values; encoded request limits apply separately.
Upstream schemas must match the enrolled structure exactly, not merely claim
equivalence. The full profile's definitions must fit within 256 KiB.

SSE framing follows the [event-stream format](https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream):
UTF-8, an optional initial BOM, LF/CRLF/CR lines, multiline data, ignored
comments/unknown fields, and the last event type. This profile rejects invalid
UTF-8, non-message events, and incomplete trailing frames. It discards IDs and
retry hints without scheduling resumption. Decoder output is private raw
upstream data, not safe observation; validate each message before release.

Responses suppress known secret values in decoded strings, object keys, numeric
data, and common encoded forms. Output is bounded and revalidated after
redaction; key collisions or damaged protocol fields fail instead of yielding
malformed success. The caller must supply all applicable private redaction
patterns, including an initialization response's session header before its
body. Arbitrary encoding by a malicious credential recipient remains outside
this defense's guarantee.

Run `cargo test -p aap-mcp-upstream --locked` with a task-specific
`CARGO_TARGET_DIR` under `/tmp`.

## Context and exchange ownership

Create one `Context` per trusted local session/resource/account binding. It
caps lifetime at ten minutes and the handshake at thirty seconds. Each
`begin` reserves one exchange, assigns a non-reused upstream ID, and rejects
concurrent caller-ID collisions. Contexts allow eight work exchanges and two
control exchanges; the engine must additionally impose the shared per-session
and broker quotas. Context admission never creates a socket or resolves a key.

`outgoing` provides private headers/body for final engine admission and injection.
It is preparation, not a send or an idempotency guarantee. `start_response`
validates HTTP status/headers and adds captured session IDs to the private
redaction template before body processing. Notification acknowledgments must
have empty 202 bodies. Unexpected statuses, cookie/session replacement headers,
encoding, malformed JSON/SSE, and framing limits invalidate the context.

Feed bounded chunks through the returned decoder. Server pings are private
one-shot child work; reserve engine-wide control capacity and apply current
approval/custody/observation policy before `ping_reply` and dispatch. A ping
response's HTTP acknowledgement must also be checked by the host; this component
does not send it or mark it remotely accepted. Never return `Outgoing` or raw
ping bodies to an agent or observer.

`finish` produces an opaque `Completion` after protocol EOF. Its sanitized
response may be inspected for observation, but delivery and context writeback
require current host authorization plus `complete` on the same live context
and exchange. Initialization stages the private session header; only its
matching commit permits `notifications/initialized`, whose accepted completion
admits tool work. A protocol initialization error invalidates the context.

Every operation-drop path must call `abandon` on its exchange. Normal abandoned
work loses its mapping without a claim of remote rollback; an abandoned
handshake invalidates the context. Known cancellation maps only owned live work
and returns its local operation ID so the engine can cancel the actual task.
Unknown/completed/initialization MCP cancellation IDs are ignored. Local status
and remote notification delivery remain engine responsibilities.

`invalidate` makes pending decoders/completions unusable. `close(now)` first
checks expiry/failure and removes local authority, optionally returning private
cleanup headers once. Sending DELETE still requires current engine permission;
expired, failed, or already closed contexts provide no cleanup credential.
Fresh initialization requires a new context and never erases the engine's
operation history or authorizes replay.
