# Confinement probe agent

Development-only Linux executable for the real-daemon sandbox acceptance test.
It uses the public credential-free client and safe OS interfaces; it does not
contain credentials or depend on the engine, a store, or daemon internals.

The trusted harness supplies bounded length-prefixed JSON jobs on stdin and
checks bounded JSON reports on stdout against live host-side receipt counters.
Jobs name only synthetic fixture targets. Reports contain reachability flags,
namespace/limit facts, and the already-sanitized proxy response, never private
file or environment contents. A descendant executes the same probes.

This program is deliberately capable of direct connection attempts. It is a
probe, not a sandbox or a trusted attestation service. The launcher must enforce
isolation externally before running it. See the workspace's
[confinement guide](../../../../docs/confinement.md) for setup, exact coverage,
and remaining acceptance gates.
