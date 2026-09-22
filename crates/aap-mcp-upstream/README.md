# aap-mcp-upstream

Trusted, connector-free validation and transformation for the pinned remote
MCP profile. This crate is not an agent client or a complete remote gateway.
See [the contract](../../plan/remote-mcp.md).

The first slice supplies reviewed tool contracts, bounded request/response
validation, structural response sanitization, and incremental SSE framing.
The caller must enforce session lifecycle, admitted destinations, current
credential/policy versions, approval, quotas, observation, and cancellation.
Validated messages do not authorize a connection or credential use.

The engine integration, private upstream session custody, and actual daemon
remote-MCP fixture remain pending. Do not advertise remote MCP support from
these pure protocol tests alone. This crate starts no runtime or connector and
does not retrieve credentials or launch background work. SDK types remain
private to its implementation.

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
