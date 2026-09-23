# Linux confinement fixture

The opt-in provider fixture runs a separate credential-free Rust process inside
real Linux namespaces, talking to the real daemon and SQLCipher-backed provider
profile. It is partial deployment evidence, **not a supported production
launcher or a claim of complete communication interception**. The full
[deployment contract](../plan/deployment.md) still has unchecked gates.

## Running the fixture

The host must provide unprivileged user/network/mount/PID/IPC/UTS namespaces,
IPv4 and IPv6 loopback, `/proc`, and these trusted dynamically linked helpers:
`/usr/bin/bwrap` (tested at 0.12.0), `prlimit`, `unshare`, `true`, and `ldd`.
Bubblewrap must support `--disable-userns`, `--assert-userns-disabled`, and sized
tmpfs mounts. Missing facilities fail the explicitly requested test; there is no
less-isolated fallback. The regular portable test suite leaves this test ignored
and therefore does not establish a confinement pass.

From the workspace root, with the pinned Rust toolchain:

```sh
confinement_target=$(mktemp -d /tmp/cargo-target-aap-confinement.XXXXXX)
export CARGO_TARGET_DIR="$confinement_target"
cargo build --locked -p aap-client --example confinement-agent
export AAP_CONFINEMENT_AGENT="$CARGO_TARGET_DIR/debug/examples/confinement-agent"
cargo test --locked -p aap-daemon --test process \
  confinement::confined_agent_uses_only_its_session_attachment \
  -- --ignored --nocapture
```

If the host's temporary directory has unsafe ancestor permissions, set
`AAP_TEST_ROOT` to a trusted existing parent, as for the other private-file
fixtures. Do not change host permissions, namespace policy, or trust stores to
make a gate pass. Build output stays under `/tmp`. Fixtures use only synthetic
credentials and local services and remove their own private directories.

## Exact launch boundary

The harness invokes Bubblewrap with required (not `-try`) user, network, PID,
IPC, and UTS isolation, a private mount view, disabled further user namespaces,
`--new-session`, `--die-with-parent`, and all capabilities dropped. It exposes:

- One read-only projection of one agent session socket at `/session.sock`.
- The probe executable at `/probe`, `unshare` and `true`, and their individual
  loader/shared-library files discovered from trusted executables. No host
  `/usr`, home, repository, configuration, or runtime directory is mounted.
- A private `/proc`, minimal `/dev`, and 16 MiB private `/tmp`. The root mount
  is read-only. Standard input/output carry bounded synthetic test jobs/reports;
  standard error is a declared diagnostic channel, not an observed proxy stream.

The host clears the launch environment before executing helpers. Bubblewrap
then removes the deliberately injected synthetic environment canary; only its
`PWD` entry may remain. `prlimit` supplies hard per-process limits: 10 CPU
seconds, 1 GiB address space, 128 descriptors, 1 MiB file size, and zero core
size, plus the UID-scoped `RLIMIT_NPROC` ceiling of 512. The harness enforces
15-second job and five-second normal-exit deadlines. These are not aggregate
cgroup memory/CPU budgets for a hostile process tree.

Descriptor inheritance is explicit. The trusted harness duplicates synthetic
network, operator, catalog-file, runtime-directory, and network-namespace
handles at known numbers and deliberately makes them inheritable for the
positive control. Before the confined launch it restores close-on-exec on its
owned handles and rejects any other inheritable descriptor above standard I/O.
This is a controlled fixture mechanism, not a general-purpose launcher API for
closing arbitrary foreign descriptors. Bubblewrap preserves inherited
application descriptors; its namespace setup alone is not descriptor cleanup.
[Bubblewrap 0.12.0 source](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c)

Bubblewrap supplies mechanisms; the caller remains responsible for the complete
mount, namespace, descriptor, and privilege policy. No sandbox framework was
added to the daemon, portable libraries, or normal client dependency graph.
[Bubblewrap security model](https://github.com/containers/bubblewrap/blob/main/README.md)

## Checks and limits of the evidence

The same probe first runs unconfined. Every synthetic network/socket/file/process
target must be accessible, every seeded descriptor must be present, and creating
a user namespace must work. Both this process and its descendant run the probes.
The trusted harness counts accepted TCP/Unix connections and UDP datagrams;
confined probes must not increase those counts. A nonexistent or unreachable
positive-control service fails the test instead of counting as isolation.

| Case | Current fixture evidence |
| --- | --- |
| Approved provider request | Real private key arrives only at the TLS fixture; the client gets a redacted SSE response; both observed views close completely with the request ID |
| Direct networking | Live host-loopback IPv4/IPv6 TCP and UDP canaries remain unreachable from both parent and descendant |
| Host sockets | Filesystem/abstract Unix canaries, operator, owner-observer, and another session socket are unreachable by their known names |
| Private files | Actual catalog, daemon configuration, and encrypted vault cannot be opened for read or write; no private file content appears in reports |
| Host processes | PID handles and `/proc` environment/root access for the runner and daemon fail; namespace identities differ from the positive control |
| Inherited authority | All five deliberately inherited handles are absent in the confined process and its descendant |
| Privilege/environment | Empty effective/permitted/bounding/ambient capabilities, `no_new_privs`, helper execution followed by denied user-namespace creation, clean environment, and declared limits |
| Revocation | A working attachment stops dispatch without direct fallback or new fixture receipts |
| Daemon death/restart | A separate live attachment stops working after abrupt daemon death and remains unusable after restart; only a newly projected attachment succeeds |
| Required recording/approval | An overflowing required collector and an absent approval mechanism each prevent provider dispatch without exposing credentials or enabling direct access; removing only the collector requirement restores that session's provider path |

The Rust probe uses the public `aap-client` interface. It has no credential-store
or engine dependency. Its booleans are test diagnostics, not an agent attestation
accepted by the daemon. The trusted test runner owns the launch policy, live
canaries, positive-control requirements, response checks, and evidence result.

Still unverified by this fixture:

- DNS/HTTPS/QUIC protocol-specific bypass attempts, non-loopback local/link-local
  and metadata destinations, raw/packet/alternate socket families, and complete
  privileged-helper/syscall coverage. Generic TCP/UDP denial is not reported as
  those separate protocol gates passing; no syscall filter is installed here.
- Host memory/ptrace and namespace-joining attacks beyond the process/path and
  inherited-handle checks above; native-store descriptors and actual CA-key
  files; adversarial process-tree teardown and aggregate resource exhaustion.
- Website/CONNECT, local or remote MCP/tool, and TCP-client operations within
  this sandbox, including their required-observation and approval failure cases.
  The recording/approval checks above cover only the provider path.
  Their existing ordinary process/library tests are separate evidence.
- Malicious attachment substitution through request fields and the remaining
  deployment matrix. Knowing another session's pathname is covered, but is not
  the whole substitution suite.
- Other kernels, architectures, launchers, UID arrangements, or macOS isolation.

The initial acceptance test was run against ordinary, unconfined child execution
and failed at the expected direct TCP reachability assertion before the isolated
launcher was added. The extended lifecycle checks are conformance evidence, not
additional regression discoveries. On 2026-09-23 this fixture passed on Linux
`6.12.107+deb13-amd64`, Bubblewrap `0.12.0`, and util-linux `2.41.5`. The probe
retained UID/GID 1000; its nested UID and GID maps each reported `1000 0 1`.
This environment is itself containerized, so the host in this evidence means
the trusted test environment outside the nested agent sandbox, not proof about
an untested physical-host deployment.
