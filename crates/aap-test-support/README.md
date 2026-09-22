# aap-test-support

Development-only synthetic fixtures. The controlled HTTPS origin uses a fresh
self-signed test certificate, records bounded test requests, and can stream,
delay, redirect, or disconnect. Never use it with actual credentials, and never
add it as a production dependency or operational secret-store fallback.

This crate has no dependency on the transport or engine under test.
