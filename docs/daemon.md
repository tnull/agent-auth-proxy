# Standalone daemon: initial Linux contract

This describes implemented behavior, not the full planned product. The current
daemon brokers explicitly submitted API-key and profiled website requests, with
password-manager discovery/fake credentials/status/logout and a local stdio
MCP bridge and optional [session-bound CONNECT inspection](connect.md).
It is not yet a remote MCP mediator or sandbox launcher.

## Configuration and startup

`agent-auth-proxy validate CONFIG_DIRECTORY` validates `daemon.json` and
`catalog.json` without reading an unlock key or opening the SQLCipher database.
It prints only `valid` and `configuration_revision` on success. Both documents
are strict JSON, each at most 1 MiB, with the same configuration revision.
Validation checks catalog/profile references, TLS roots, address overrides,
observation bounds, and existing private store/runtime directories.

`agent-auth-proxy serve CONFIG_DIRECTORY` consumes exactly 32 raw key bytes and
EOF on stdin from a trusted launcher. This is a generated database encryption
key, not a password or hex/base64 string. An absent/incorrect key, extra bytes,
unsafe file, invalid configuration, or already-running daemon causes refusal.
Never place the key in a shell command, environment variable, or configuration.
The CLI does not yet offer interactive provisioning or an OS unlock service.
The existing store must be provisioned through `aap-store-sqlite` by trusted
code; the process test demonstrates this with synthetic values only.

`agent-auth-proxy mcp-bridge SESSION_SOCKET` runs the credential-free stdio
adapter without loading this configuration or opening a store. Its stdin is
MCP, not the unlock-key channel. See [the bridge contract](mcp.md).

`DaemonConfig` in `aap-daemon` is the authoritative configuration type:

| Field | Meaning |
| --- | --- |
| `schema_version` | Exactly `1` |
| `configuration_revision` | Matches the catalog; increases on reload |
| `store` | SQLCipher `alias` and private existing `directory` |
| `runtime_directory` | Existing private directory for sockets/readiness/lock |
| `upstream_roots_der_base64` | Explicit canonical base64 DER trust roots; no implicit test or system roots |
| `interception` | Optional public CA certificate and private store reference; see [CONNECT](connect.md) |
| `static_hosts` | Optional exact canonical hostname to IP list; all addresses still require profile admission |
| `profiles` | Validated resource profiles and exact permitted routes |
| `require_approval` | Default false; true fails closed because no production approval adapter is configured |
| `observation` | `acceptance: "local_memory"`, finite `max_events`, `max_bytes`, and optional `required` |

Use owner-only directories (`0700`) and files (`0600`), with safe ancestors and
no access-extending ACLs. Store references, account labels, grants, and readiness
metadata are private even though they contain no passwords. The daemon refuses
unsafe access rather than changing an existing file's permissions.

## Authority planes

Successful startup writes private `control.json` in the runtime directory and
prints the same readiness object to stdout. It contains schema version `1`, a
fresh random `daemon_epoch`, and basenames for the control and observation
sockets. All sockets are owner-only and check peer UID. JSON API calls use
HTTP/1.1 POST with `Host: aap.local` and `Content-Type: application/json`;
optionally enabled CONNECT uses its admitted upstream authority instead.

| Socket | Paths | Authority |
| --- | --- | --- |
| Control | `/aap/operator/v1/session/create`, `/session/revoke`, `/status`, `/reload` (same prefix) | Trusted launcher/operator only |
| Observation | `/aap/observe/v1/read`, `/aap/observe/v1/ack` | Read/acknowledge all recorded sessions; no session creation or secret access |
| Per-session ingress | [Local agent API](local-http.md) | One immutable session grant |

Create takes `resources`, `lifetime_seconds` (1–3600), optional `items`, and restrictive
`require_approval`/`require_observation` booleans. It returns `session_id` and
`ingress_socket`. Revoke takes `session_id`; status and reload take `{}`.
When omitted/null, `items` grants the enrolled items of the permitted profiles;
an explicit list further restricts those aliases and an empty list grants none.
Each session receives its own random socket name. Agent-supplied session fields
or headers cannot select another session. Exposing the whole runtime directory
to an agent would invalidate the isolation model: a launcher must expose only
that agent's attachment and enforce filesystem/network confinement separately.
Same-UID checks alone do not isolate mutually untrusted processes.

Observation read takes optional `cursor` and `limit` (1–1024). A page is also
bounded to 1 MiB including JSON framing, without skipping a retained record that
does not fit. Resume from the returned cursor; gaps explicitly report loss or
epoch changes. Ack takes that cursor. Required recording currently means
acceptance into bounded local memory, not collector delivery or durable storage.
It blocks new recorded work when full until acknowledgment; process death loses
unpersisted records. The observer is trusted to acknowledge its actual consumption.

Per-listener admission is 32 connections, with finite parsing/body/stream
deadlines. The broker permits at most 64 sessions and 8 active upstream operations
per session, with separate operation/approval budgets. Expired sessions deny new
work immediately; create/status removes their idle listener entries. These are
finite first-PoC ceilings, not production resource-sizing guarantees.

## Reload, shutdown, and restart

Reload validates the complete candidate config/catalog pair before activation.
Failure leaves the running generation and its sessions unchanged. Success
requires a strictly newer revision and revokes **all** existing sessions,
including unchanged grants. The trusted launcher creates fresh attachments.
Changes to store location/alias, runtime directory, or observation configuration
require restart; there is no partial backend/collector migration during reload.

SIGTERM/SIGINT revoke sessions, stop listeners, lock the store, and remove only
unchanged socket entries owned by that run. A persistent private `daemon.lock`
file provides a nonblocking exclusive process lock. Readiness is discovery, not
proof that a process is still alive; do not reuse attachments after failure.

After abrupt termination the kernel releases the lock, but old socket entries
and readiness metadata can remain. Restart uses fresh epoch-qualified sockets
and overwrites readiness atomically. It does not unlink unknown stale entries
or attempt to restore old sessions/operations. Old client attachments fail;
recovered vault contents remain available under newly authorized sessions.
An operator may remove specifically identified retired socket entries after
confirming they have no live owner; no recursive runtime cleanup is performed.

No automatic retries are implied by disconnect or restart. An upstream action
may have occurred even if its response or operation state was lost.

## Executable evidence

`cargo test -p aap-daemon --test process` provisions fresh private directories
and a synthetic SQLCipher vault, launches the actual binary, connects an
independent Rust client/observation reader, and uses a controlled HTTPS origin.
It verifies key injection/echo suppression, authority separation, revocation,
paired reload, unsafe configuration and unlock refusal, single-daemon exclusion,
SIGTERM cleanup, SIGKILL restart isolation, vault survival, and expiry.
No real provider/account credentials or system-wide service/CA changes are used.

The website process test additionally exercises two independent credential-free
clients, catalog lookup, fake credentials, CSRF virtualization, form submission,
protected resource access with private cookies, context isolation, logout, and
sanitized external observations. The engine suite also tests JSON login,
asynchronous approval, rotation, store lock, attempt limits, and uncertain login.
See [the engine contract](../crates/aap-engine/README.md) for the supported JSON
response profile and finite context limits. A separate real-process test runs
the form and JSON flows through two stdio MCP bridges, including duplicate
execution/status and external observation. Three additional process tests cover
CONNECT with provider and website authentication, authority/context isolation,
CA rotation, and independent upstream trust. Remote MCP and filesystem/network
confinement remain unverified.
The tunneled website test also runs the enrolled 303 variant: no implicit
follow-up is sent, and its separately submitted GET has no credential body.
