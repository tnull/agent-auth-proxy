# aap-daemon

Thin Linux composition root for the reusable broker, encrypted store, and local
adapters. Configuration and catalog are separate private JSON files with one
matching revision. Operator and observation authority use separate sockets from
every agent session. Native macOS custody is not replaced by SQLite on macOS.

The Linux CLI supports `validate CONFIG_DIRECTORY`, `serve CONFIG_DIRECTORY`,
and the credential-free `mcp-bridge SESSION_SOCKET`. Only `serve` opens an
existing SQLCipher store using exactly 32 raw key bytes plus
EOF on standard input from a trusted launcher. It does not accept an unlock key
in arguments, environment variables, or JSON. See the [operator contract](../../docs/daemon.md)
and [process tests](tests/process.rs) for configuration and synthetic execution.

Nineteen ordinary real-process tests exercise brokerage/observation, reload,
startup refusal, crash/restart, expiry, and the controlled website login/password-manager flow
with two isolated clients, including stdio MCP form/JSON login and optional
CONNECT inspection with a store-held CA key, pinned remote MCP, and constrained
TCP. Six opt-in confinement tests exercise these routes in Linux namespaces;
the full adversarial deployment matrix and native macOS custody remain pending.

Reload now retires the entire old broker before publishing a new generation,
including retained handles outside the attachment map. Shutdown cannot be undone
by a prepared candidate. Operator results distinguish commitment from authority
cleanup and explicitly leave resource drain unconfirmed. Five lifecycle tests
exercise rejected/prepared reloads, retained authority, cleanup failure, and
both shutdown orderings. Bounded asynchronous retirement and complete task/native
cleanup accounting remain separate acceptance gates.

No system service, global CA installation, production credential enrollment, or
neighboring-project modification is implied.
