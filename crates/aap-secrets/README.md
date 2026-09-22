# aap-secrets

Runtime-neutral, object-safe `SecretStore` read/use and separate optional
`SecretStoreAdmin` interfaces. Only trusted hosts/authentication code receive
these capabilities; agent interfaces receive no store handle or native item ID.

Metadata carries a random item revision and random store-access generation.
Adapters must check both on resolve/revalidate; a lock/unlock or access epoch
change must not revive a previously issued lease. Version values are not hashes
of secret contents. The concrete backend owns coherent snapshots and invalidation.

`SecretBytes` permits explicit borrowed byte access and intentionally has no
formatting, serialization, or clone implementation. It bounds individual fields
to 64 KiB and makes no memory-erasure promise. Secret references are deliberately
not printable either. Errors contain fixed categories, never native diagnostics.

This crate does not implement storage, grant checks, native unlock, or human
approval. Backend crates must pass their real-store conformance tests.

Backend-neutral secret custody for trusted hosts, never an agent retrieval API.

Implementation is in progress. See the root README and proof-of-concept tracker.
