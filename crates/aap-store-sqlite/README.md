# aap-store-sqlite

SQLCipher-backed credential custody for trusted hosts. The adapter uses bundled
SQLCipher with the host OpenSSL development libraries, not ordinary SQLite or
a custom cipher. Cargo default convenience/Wasm/cache features are disabled.

Supply a 32-byte cryptographically random database key through a protected host
channel. It is never a CLI argument, agent environment value, or adjacent JSON
setting. Tests use visibly synthetic keys. The caller provides a Tokio runtime
handle; native work is bounded and offloaded from async worker threads.

The database lives in an `aap-config::PrivateDir`. Credentials and private item
references are encrypted; public agent catalog aliases live separately. Native
diagnostics do not become public errors, and there is no plaintext fallback.

Reads resolve coherent item snapshots and validate both item revision and
store-access generation. Creates are exclusive; updates/deletes require a
matching lease. Lock/unlock, restart, or database-key rotation invalidate old
leases. Every operation rechecks the backing file's identity and private access;
permission loss or replacement closes the live handle instead of using a
detached stale database. Missing/empty/plaintext stores are never initialized
implicitly through `OpenMode::Existing`.

Backups use a separately keyed SQLCipher export into a new private directory.
`rotate_key` first makes and synchronizes an encrypted recovery copy, then
changes the live database key. Backup/rotation failures after taking the live
handle leave the instance locked. Retain the old, new, and recovery keys until
the outcome is verified; cancellation of an async future does not cancel a
native operation already running. Never blindly retry an uncertain rotation.
An incomplete new backup file is not advertised as successful and is not
silently overwritten on retry. Schema version 1 is the initial format; foreign
or newer versions are rejected before persistent configuration changes.

Ten backend tests cover actual encrypted database/WAL files, restart, wrong
keys, no plaintext fallback, coherent updates and rollback, locking, deletion,
backup, key rotation/recovery, unsafe file changes, and unknown schema refusal.
Synthetic wrong-key tests produce SQLCipher's native page-decryption diagnostics;
the adapter exposes only fixed error categories, never those diagnostics.

This package is still part of an unfinished proof of concept. Process-crash
fault tests, future schema-upgrade handling, shared cross-backend conformance,
and daemon integration remain required work. macOS uses the separate Keychain
adapter, not this backend.

[SQLCipher keying and verification](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
