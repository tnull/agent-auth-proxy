# Trusted embedded consumer

This independent Cargo workspace demonstrates public engine composition with
the real SQLCipher backend, explicit verified TLS roots and resolver, a
caller-owned runtime, and a bounded observation recorder. It has no daemon
library or binary dependency and installs no listeners or global trust.

The host and its injected components are trusted and must remain outside the
agent sandbox. Only session-scoped services go to the shared application code.
The integration test provisions synthetic credentials in a fresh private store
and runs the same provider/form/JSON scenarios as the external client example,
then closes the broker and rejects retained handles and new sessions. Store
creation is explicit trusted test setup; `Host::open` must not create a
replacement or plaintext fallback.

SQLCipher needs a C compiler, `pkg-config`, and OpenSSL development libraries.
Run with a fresh `CARGO_TARGET_DIR` under `/tmp` and, when necessary, a safe
`AAP_TEST_ROOT` for private fixtures. A host already linking an incompatible
SQLite build should use the external daemon instead of weakening encryption.
See [the common commands](../README.md#run-both-consumers).

The tests also reject wrong keys and missing stores without creating a
replacement, and demonstrate that retained session clones reject work after
broker closure, including repeated closure calls. `Broker::close()` does not
lock the store or prove that all resources drained. The host retains
`http_drivers` from its concrete HTTPS transport; callers can join these tasks
with an absolute deadline after closing authority. A separate public-API test
keeps a provider response unpolled, closes the broker, joins its upstream driver,
and observes the real TLS peer stop before consuming or dropping the response.
The join handle does not close admission or include caller-held buffers,
connect/handshake futures, or native store work. This example does not
supply a complete host shutdown coordinator: production hosts still stop their
listeners, cancel/drop owned executions and response bodies, and join tasks
within a finite deadline. In-flight native work requires explicit accounting;
an unpolled response must not be mistaken for a stopped connection.
