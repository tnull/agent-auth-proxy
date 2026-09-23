# aap-test-support

Development-only synthetic fixtures. The controlled HTTPS origin uses a fresh
self-signed test certificate, records bounded test requests, and can stream,
delay, redirect, or disconnect. Never use it with actual credentials, and never
add it as a production dependency or operational secret-store fallback.

The origin also counts accepted TCP connections independently of captured HTTP
requests. Confinement fixtures use this to distinguish a blocked connection
from an attempted connection which fails TLS or never sends an HTTP request.
Querying that counter asserts that the origin listener is still running.
`active_connections()` separately counts accepted server tasks until they are
joined. Lifecycle tests use it to verify peer connection termination without
driving a held client response; an HTTP error alone is not evidence of closure.

This crate has no dependency on the transport or engine under test.
