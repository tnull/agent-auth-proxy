# aap-policy

Pure authorization and destination rules without networking or secret access.

Validate a `Catalog` against trusted profiles, store aliases, and the matching
configuration revision before admission. Profiles use exact HTTPS origin,
method, path, and query rules, bounded bodies, and explicit application-header
allowlists. Form profiles additionally bind login/CSRF fields and application
success evidence. Approval requirements compose restrictively.

`Authentication::Mcp` enrolls one query-free POST endpoint, an optional DELETE
on that same path, one catalog credential, and finite reviewed tool contracts.
It rejects streaming/unbounded routes and caller session/resumption headers.
Catalog validation forbids raw-profile overlap at that origin/path and reuse
of the same enrolled native credential reference through a non-MCP profile.
Distinct MCP account bindings remain supported. These are configuration checks,
not evidence that a caller or engine has implemented remote MCP dispatch.

`TcpProfile` separately enrolls one canonical credential-free endpoint with
explicit address policy, inspection class, approval/observation requirements,
and finite byte/time/per-resource limits. `validate_tcp_profiles` rejects
cross-kind alias collisions, duplicate raw endpoints, and raw access to any
inspected HTTP/provider/MCP host and port. Both kinds share a 256-profile ceiling.
The daemon loader and embedded broker invoke this check before creating sessions.
TCP resources cannot own catalog credentials or be used as HTTP profiles.

`TcpProfile::admit_addresses` checks every candidate address and port, rejects
scope/flow overrides and substitution of a literal IP, then chooses one address
without authorizing retries. It performs no DNS or dialing. These enrollment
contracts are composed by the implemented [engine/client TCP path](../../docs/tcp.md);
this policy crate alone does not relay traffic.

`AddressPolicy::permits_all` checks a complete DNS result. The caller must then
dial one of those admitted addresses without re-resolution, retain the approved
TLS name, and enforce session/grant/revocation checks. This crate does not bind
sessions, perform safe configuration-file I/O, or enforce network isolation.

The conservative first target grammar requires ASCII URIs (use an explicitly
enrolled ASCII/punycode host and percent-encoded UTF-8 paths). It rejects dot
normalization, encoded path separators, semicolon path parameters, and repeated
slashes rather than guessing how an upstream application interprets them.

The initial destination classifier conservatively excludes special-purpose,
private, documentation, transition, and multicast address ranges. Exact private
destinations must be explicitly enrolled by a trusted host; this classifier
alone is not a complete egress policy or sandbox.

Sources checked 2026-09-22:
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/).
