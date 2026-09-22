# Session-bound CONNECT inspection

The Linux daemon can accept HTTP/1.1 CONNECT on a session's existing private
Unix socket when the operator configures `interception`. This is an inspected
HTTPS adapter, not an opaque TCP tunnel or an unrestricted forward proxy.
The client must support connecting its HTTP proxy transport to that socket.
No public TCP listener or global proxy/CA installation is created.

## Custody and trust

Optional `daemon.json` configuration:

```json
{
  "interception": {
    "certificate_der_base64": "<canonical base64 of the public DER CA certificate>",
    "credential": {"store": "default", "key": "<private CA item reference>"}
  }
}
```

Provision the referenced store item through trusted host code with exactly one
`PrivateKey` field containing its PKCS#8 key. It must use the configured store
alias and must not also appear in the agent-visible credential catalog. The
public certificate belongs in the enrolled client's private trust configuration;
never give that client the private key, database key, or operator socket.

The supported root is currently a valid self-signed CA with `keyCertSign`.
Only basic constraints, key usage, subject-key identifier, and authority-key
identifier extensions are accepted. Other extensions, including name constraints
and EKU, are refused rather than silently ignored by issuer import. DER/key
inputs are bounded to 64 KiB. Configuration validation checks public certificate
validity/profile, references, and catalog separation without resolving secrets.
Missing, unavailable, or mismatched private keys fail the admitted CONNECT;
startup validation is not proof that the private CA item is usable.

Destination admission precedes private-key resolution. The host issues a fresh
leaf for the exact admitted DNS name or IP, with at most ten minutes' validity
capped by root expiry. There is no certificate cache. Eight signing jobs at
most run per configuration generation, including jobs whose callers disconnect.
The private CA key is not retained by the TLS connection. Store-version/access
leases, a conservative nine-minute connection identity deadline, and CA expiry
are checked before use and before forwarding its HTTP request. Rotation denies
an established connection's next request; it cannot recall bytes already sent.

The downstream TLS server requires matching SNI for DNS names, permits absent
SNI for an admitted IP, advertises only HTTP/1.1, and disables resumption and
early data. The upstream connection independently checks its configured roots
and server name and dials an address authorized by the resource profile. The
interception root never becomes an implicit upstream trust root.

## Routing and authentication

CONNECT uses an explicit canonical `host:port` target and a matching Host
header. The engine checks the session's resource grants and every resolved
address before signing admission, then rechecks after issuance. Required
recording must accept each `connect_admission` event before admission succeeds.
Calling the JSON `/aap/v1/connect/admit` endpoint alone never issues a certificate
or establishes a tunnel.

Inside TLS, the request must use an origin-form path and the same authority;
port omission means 443, not the CONNECT port. Absolute-form targets, nested
CONNECT, upgrades, ambiguous headers/framing, caller Authorization/Cookie,
Expect, trailers, and reserved proxy/authority headers are refused. Framing and
connection headers are consumed locally; remaining application headers still
need explicit route permission. No implicit redirect or retry is performed.

The engine selects exactly one granted profile matching method and target.
For a website profile, the client first obtains fake credentials using the
existing vault API or MCP tool. Automatic context selection is allowed only
when there is exactly one granted account and one live prepared context for
that account. Otherwise the request needs `Proxy-Auth-Context: <auth_context>`;
this local selector is stripped before upstream dispatch and does not grant
authority. Multiple matching profiles are denied unless an explicit context
unambiguously selects its granted website profile.

The same engine then performs approval, placeholder substitution, private
cookie/CSRF handling, API-key injection, verified upstream dispatch, and safe
response/observation sanitization used by explicit requests. Neither the HTTP
adapter nor the certificate helper implements a second authentication policy.

Each ordinary proxied request receives a fresh internal operation ID. Repeating
it is a new operation, not an idempotency promise. Use explicit `request.execute`
with a stable ID when application-level duplicate detection/status is needed.
The trusted `AgentService::forward` seam is not a new JSON/MCP tool endpoint.

## Bounds and evidence

Each connection permits one CONNECT and one inspected HTTP request, then
closes; clients reconnect for subsequent requests. Connections stay in the
listener's owned 32-entry task set, including upgrade and TLS work. Shutdown
drops them rather than leaving detached tunnel tasks. Headers are limited to
64/64 KiB, uploads to 1 MiB with a ten-second read deadline, upgrade/TLS handshakes
to ten seconds each, and the whole connection to 610 seconds. Existing narrower
profile/session/engine limits and streamed-response bounds still apply.

Tests exercise real downstream TLS and independently verified upstream TLS,
provider-key injection, complete fake-credential website login, private cookies
and CSRF, context ambiguity, destination/SNI/Host denial, missing trust,
invalid/expired/mismatched CA material, required-observation failure, and CA-item
rotation after handshake. All credentials and certificates are synthetic.

This does not establish universal browser compatibility, arbitrary HTML or
script login, pinned-TLS bypass, HTTP/2/3, WebSockets, complete TLS lifecycle/wire
observations, or sandbox egress confinement. Complete directional views and
correlated connection lifecycle events remain part of the observation milestone.
The process fixtures use DNS authorities and loopback IPv4; IP-SAN issuance is
unit-tested, but literal-IPv6 end-to-end forwarding is not yet established.
