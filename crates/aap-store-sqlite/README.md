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

Eleven backend tests cover actual encrypted database/WAL files, restart, wrong
keys, no plaintext fallback, coherent updates and rollback, locking, deletion,
backup, key rotation/recovery, unsafe file changes, unknown schema refusal,
and native worker ownership after caller cancellation.
Synthetic wrong-key tests produce SQLCipher's native page-decryption diagnostics;
the adapter exposes only fixed error categories, never those diagnostics.

The adapter admits at most eight native jobs per store, including jobs queued
behind its connection lock. A dropped async caller does not release that job's
reservation: the worker retains it until completion. At saturation, even a
request to lock the store returns `Unavailable`; it does not report that the
store is already locked or drained. An admitted lock call is native work too
and may finish after its caller stops waiting. Coordinate it only when the
host owns the backend lifecycle, not to shut down one user of a shared store.

A deterministic conformance test pauses a real SQLCipher worker after reading
a synthetic value, abandons its caller and seven queued callers, and verifies
that capacity stays occupied. Releasing the worker disposes of its late result
and restores capacity without changing the credential lease. This verifies
existing worker ownership, not forced interruption, secret-memory erasure, or
a complete broker/daemon drain API. Only tests enable Tokio's timer feature for
bounded fixture waits; no normal dependency or store interface changes.

This package is still part of an unfinished proof of concept. Process-crash
fault tests, future schema-upgrade handling, shared cross-backend conformance,
and daemon integration remain required work. macOS uses the separate Keychain
adapter, not this backend.

[SQLCipher keying and verification](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
