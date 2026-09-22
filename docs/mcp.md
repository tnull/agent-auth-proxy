# Local MCP bridge

The Linux daemon binary supports:

```text
agent-auth-proxy mcp-bridge /sandbox/proxy.sock
```

A trusted launcher supplies this session socket and confines the bridge with
the agent. The command does not load daemon configuration, read an unlock key,
or open a secret store. It uses `aap-client` to reach the daemon's existing
session-bound API. Merely running the bridge does not prevent access to other
host files or network interfaces; that still requires the sandbox boundary.

Stdin/stdout carry newline-delimited UTF-8 MCP messages, with no startup banner
or readiness JSON. Successful operation emits no stderr messages. Failures
use fixed safe diagnostics. The bridge performs MCP `2025-11-25` initialization
and advertises only the tools capability. Other protocol revisions can be
proposed during negotiation, but only this revision is returned/supported.

## Tools and results

The seven tools are `vault.search_items`, `vault.get_login`,
`vault.auth_status`, `vault.logout`, `request.execute`, `request.status`, and
`request.cancel`. Their arguments and envelopes are specified in
[the local MCP contract](../plan/mcp.md). Tool discovery returns strict input
schemas. Unknown arguments and duplicate JSON members are rejected. The
bridge exposes no administration, secret-reveal, approval-submit, or raw
network-connection tool.

Application results appear in `structuredContent` and as the same JSON in a
text block. `request.execute` returns a safe HTTP response with exact body
bytes in `body_base64`, or a distinct existing-operation envelope. HTTP status
401/500 is not itself a JSON-RPC protocol failure. An engine denial returns an
`isError:true` result with a safe error code. Duplicate operation IDs never
authorize another dispatch, and resource JSON cannot forge operation state.

For an empty DELETE with local HTTP 204, the result preserves the engine's
`x-aap-remote-cleanup` header only when it has exactly one fixed value:
`confirmed`, `not_supported`, `skipped`, or `unknown`. This distinguishes local
closure from remote cleanup; it cannot prove business rollback. Wrong methods,
statuses, nonempty bodies, unknown/duplicate values, and mixed existing-operation
metadata fail safely. Other private `x-aap-*` headers remain filtered.

Status and explicit cancellation address the application's random request ID,
not the JSON-RPC correlation ID. While a tool waits, independent status/cancel
requests remain available. No human-approval capability is delegated to the
agent through MCP. The production daemon still fails closed when approval is
required and no trusted provider is configured.

MCP cancellation notifications cancel only the matching in-flight invocation
on that bridge. Its future/transport is dropped and a late response is
suppressed; a notification cannot blindly cancel a different invocation that
reused the same application operation ID. A completed status query cannot
cancel the operation it queried. Use `request.cancel` for an explicit daemon
cancellation decision, then `request.status` to inspect authoritative state.
Transport loss or bridge shutdown never proves rollback or remote cancellation.
The daemon's deadlines remain a fallback if local cleanup cannot reach it.

## Bounds and lifecycle

Input messages are at most 2 MiB, output messages 4 MiB, and buffered HTTP
bodies 1 MiB. The website profile's smaller 256 KiB limit still applies.
Framing is incremental; missing newlines cannot bypass limits. Parsing admits
at most 64 nested containers and 32,768 structural tokens before constructing
a JSON tree. String JSON-RPC IDs are at most 128 UTF-8 bytes; numeric IDs must
fit the SDK's signed 64-bit integer representation.

The loop admits at most eight work calls and two status/cancel calls, with a
16 MiB encoded-message/result reservation ceiling. Work reserves a worst-case
4 MiB output plus its input, so the initial settings admit at most three
simultaneous work calls; the byte ceiling dominates the count ceiling. Control
capacity is reserved separately. Input parsing and output serialization also
have bounded temporary buffers; these quotas are not a claim of total process
RSS. Cancelled calls retain their reservation until their owned task is reaped.
No unlimited SDK task queue or payload logger sits before admission.

Initialization, partial-frame inactivity, and stalled output each have a
10-second bound. Tool calls are capped at 10 minutes and engine/session/profile
deadlines may expire first. EOF/error aborts and reaps owned handlers with a
two-second cleanup deadline. Blocking OS stdio cleanup is additionally bounded
by the CLI's two-second runtime shutdown timeout. The underlying host-created
session is not revoked by closing a bridge. There is no automatic reconnect,
request replay, upstream redirect, or HTTP connector inside the MCP adapter.

## Verification and remaining scope

Run `cargo test -p aap-mcp` for tool, wire, bounds, overload, cancellation, and
shutdown checks. Run `cargo test -p aap-daemon --test process real_stdio_bridges`
for actual daemon/bridge processes, SQLCipher, controlled HTTPS form/JSON
logins, two isolated sessions using the same enrolled account, duplicate-operation
behavior, logout, and an independent redacted-observation reader. These use
synthetic credentials only. They do not prove sandbox confinement.

The reusable adapter also accepts an in-process `AgentService`; it imports no
engine/store code. Remote MCP Streamable HTTP mediation, local MCP over HTTP,
complete MCP-wire observation, real sandbox enforcement, and external embedding
conformance remain separate delivery gates. The bounded request tool is not
the model streaming endpoint and does not buffer an unlimited model stream.
