# Local session HTTP binding, version 1

This implemented adapter uses one host-provided Unix socket per session. The
host makes only that attachment visible inside the sandbox. `Host: aap.local`
is a fixed routing check, not authentication. A session ID in a header or body
never selects another session. Operator methods are not present on this router.

Every local call is HTTP/1.1 POST with `Content-Type: application/json`, no
query, and an origin-form target. DTOs are in `aap-types::protocol`; strict JSON
decoding rejects unknown and duplicate fields. Request framing is bounded to
2 MiB, 64 headers/64 KiB, and a ten-second header/body read deadline. Each
session listener has at most 32 active connections, at most 28 of them work,
with four reserved for bounded classification and status/cancel. Ordinary
HTTP connections are not kept alive. TCP upgrade has the narrower metadata
limits and distinct phase timers described in [tcp.md](tcp.md).

| Path | JSON request | Result |
| --- | --- | --- |
| `/aap/v1/request/execute` | `ExecuteRequest` | Sanitized upstream status/body stream |
| `/aap/v1/request/status` | `{"request_id":"…"}` | `OperationStatus` |
| `/aap/v1/request/cancel` | `{"request_id":"…"}` | `OperationStatus` |
| `/aap/v1/vault/search_items` | `SearchItems` | `SearchResult` |
| `/aap/v1/vault/get_login` | `GetLogin` | `Login` |
| `/aap/v1/vault/auth_status` | `AuthContext` | `AuthStatus` |
| `/aap/v1/vault/logout` | `AuthContext` | `Logout` |
| `/aap/v1/connect/admit` | `{"authority":"…"}` | JSON null after admission |
| `/aap/v1/stream/open` | `{"request_id":"…","resource":"…"}` plus required Upgrade headers | Existing status or one framed TCP attachment |

Exposure of a method does not imply the engine supports every profile. The
broker implements API-key execution, controlled website profiles, pinned remote
MCP, the four password-manager methods, and separately enrolled TCP streams.
CONNECT admission checks resource grants, DNS
addresses, and required observation, without reading site credentials.
Tunneling requires the host to configure [interception](connect.md); calling
the admission endpoint alone never issues a certificate or opens a tunnel.

Proxy errors carry `x-aap-error: 1` and the fixed `Error` JSON DTO. Upstream
HTTP error statuses remain ordinary upstream responses, not proxy errors.
For repeated identical execution IDs, the engine returns existing status with
`x-aap-operation-state: existing` (202 while pending, 200 when terminal), not
replayed content or another dispatch. Modified reuse conflicts.
Issuance shares the same ID namespace: identical completed issuance returns its
still-valid fake credentials, pending issuance reports `auth_in_progress`, and
revoked/expired or failed issuance cannot create a replacement binding. Its
operation status is available through the same status endpoint.

The existing HTTP client performs no automatic retry or redirect. Its connection deadline is
ten seconds; a call/stream is bounded to 630 seconds and 32 MiB, with 65-second
stream inactivity. A broken connection after sending is conservatively uncertain.
Use explicit status/cancel calls; disconnect alone is not proof of remote rollback.
Server shutdown cancels listener work and drops in-flight execution futures.
The [TCP client](../crates/aap-client/README.md#tcp-streams) uses distinct opening,
approval/preparation, connected, and final-control deadlines. It does not reuse
these ordinary HTTP client timeout assumptions.

The [daemon/operator composition](daemon.md) uses distinct private listeners.
Provider-compatible path mounts remain separate work. Inspected HTTPS CONNECT
is an optional explicitly configured binding on the same session socket, with
the same session grant and engine pipeline; there is no opaque fallback.
