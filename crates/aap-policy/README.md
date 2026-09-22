# aap-policy

Pure authorization and destination rules without networking or secret access.

The initial destination classifier conservatively excludes special-purpose,
private, documentation, transition, and multicast address ranges. Exact private
destinations must be explicitly enrolled by a trusted host; this classifier
alone is not a complete egress policy or sandbox.

Sources checked 2026-09-22:
[IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IANA IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/).
