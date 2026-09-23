# Trusted embedded consumer

This independent Cargo workspace demonstrates public engine composition with
the real SQLCipher backend, explicit verified TLS roots and resolver, a
caller-owned runtime, and a bounded observation recorder. It has no daemon
library or binary dependency and installs no listeners or global trust.

The host and its injected components are trusted and must remain outside the
agent sandbox. Only session-scoped services go to the shared application code.
The integration test provisions synthetic credentials in a fresh private store
and runs the same provider/form/JSON scenarios as the external client example,
then revokes its retained session handles. Store creation is explicit trusted
test setup; `Host::open` must not create a replacement or plaintext fallback.

SQLCipher needs a C compiler, `pkg-config`, and OpenSSL development libraries.
Run with a fresh `CARGO_TARGET_DIR` under `/tmp` and, when necessary, a safe
`AAP_TEST_ROOT` for private fixtures. A host already linking an incompatible
SQLite build should use the external daemon instead of weakening encryption.
See [the common commands](../README.md#run-both-consumers).

The tests also reject wrong keys and missing stores without creating a
replacement, and demonstrate that retained session clones reject work after
revocation. This example does not supply a complete host shutdown coordinator;
production hosts still own admission shutdown, revocation of every retained
session, and bounded cleanup of their own listeners and tasks.
