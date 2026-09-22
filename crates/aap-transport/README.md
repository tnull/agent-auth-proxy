# aap-transport

Trusted HTTPS execution against an already admitted socket address, with
independent certificate/hostname verification. DNS resolution and dialing are
separate: callers authorize the complete resolver result before constructing
an endpoint. This crate owns no grants, credential store, redirects, or retries.

Caller-provided trust roots and the existing Tokio runtime are used explicitly;
there is no global TLS provider installation or process configuration change.
Only HTTP/1.1 is advertised initially. Response bytes/headers from this low-level
interface are private upstream data and must pass the engine's authentication
capture and sanitization before reaching an agent or observation consumer.

Execution checks authority/port and framing before opening a socket, connects
once to the supplied address, disables TLS early data, and uses finite request,
response, header, connection, inactivity, and total-duration limits. Dropping
the response or execution future aborts its connection driver. Once request
dispatch starts, transport failure is conservatively `outcome_unknown`; neither
that condition nor a redirect causes a second request. Consumers must poll the
body to its terminal outcome, not mistake received headers for completion.

Nine tests use real local TLS (including untrusted and mismatched certificates),
record upstream reception, and exercise redirection, ambiguous disconnects,
stream cancellation, deadlines, framing, body limits, and separate resolution.
The interception module additionally validates a narrow self-signed root profile
and consumes an explicitly supplied PKCS#8 key to issue a short-lived identity
for an already admitted CONNECT authority. Two tests cover actual scoped-trust,
SNI/ALPN/IP handshakes and invalid, expired, non-CA, or mismatched key material.
It owns neither store lookup nor admission. The constrained TCP relay is pending.
