# aap-daemon

Thin Linux composition root for the reusable broker, encrypted store, and local
adapters. Configuration and catalog are separate private JSON files with one
matching revision. Operator and observation authority use separate sockets from
every agent session. Native macOS custody is not replaced by SQLite on macOS.

The Linux CLI supports `validate CONFIG_DIRECTORY` and `serve CONFIG_DIRECTORY`.
The latter opens an existing SQLCipher store using exactly 32 raw key bytes plus
EOF on standard input from a trusted launcher. It does not accept an unlock key
in arguments, environment variables, or JSON. See the [operator contract](../../docs/daemon.md)
and [process tests](tests/process.rs) for configuration and synthetic execution.

Five real-process tests exercise brokerage/observation, reload, startup refusal,
crash/restart, and expiry. This is not yet the complete proxy: website logins,
CONNECT, MCP/TCP, native macOS custody, and sandbox enforcement remain pending.
No system service, global CA installation, production credential enrollment, or
neighboring-project modification is implied.
