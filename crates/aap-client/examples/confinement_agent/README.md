# Confinement probe agent

Development-only Linux executable for the real-daemon sandbox acceptance test.
It uses the public credential-free client and safe OS interfaces; it does not
contain credentials or depend on the engine, a store, or daemon internals.

The trusted harness supplies bounded length-prefixed JSON jobs on stdin and
checks bounded JSON reports on stdout against live host-side receipt counters.
Jobs name only synthetic fixture targets. Reports contain reachability flags,
namespace/limit facts, and the already-sanitized proxy response, never private
file or environment contents. A descendant executes the same probes.

The probe also invokes the public owned TCP client and runs the public MCP
stdio adapter in a real child process. That child repeats the isolation probes
before its MCP initialization and tool call. Website contexts stay in the
daemon across successive tool subprocesses; neither executable links custody
code. Only Linux development dependencies enable these demonstrations.

Each process accepts at most 32 jobs, each framed job/report is at most 64 KiB,
and each MCP/stream action has a five-second deadline. Fixture TCP payloads are
bounded to 16 KiB in each direction. These fixture budgets are not new limits
on the public client API or production transport contracts.

This program is deliberately capable of direct connection attempts. It is a
probe, not a sandbox or a trusted attestation service. The launcher must enforce
isolation externally before running it. See the workspace's
[confinement guide](../../../../docs/confinement.md) for setup, exact coverage,
and remaining acceptance gates.
