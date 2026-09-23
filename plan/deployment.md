# Sandbox deployment and confinement contract

Status: deployment requirements; partial implementation evidence is recorded
separately in the [Linux fixture guide](../docs/confinement.md). The complete
acceptance suite below has not passed.
This document makes the [architecture's](architecture.md) external enforcement
assumption testable. Keep the current project/package names. It adds neither
a sandbox framework dependency nor a new upstream authentication protocol.

## Product boundary and claims

The daemon mediates admitted traffic; a trusted launcher or embedding host
confines the agent. Starting the daemon, setting proxy environment variables,
or trusting its public CA does not by itself confine a process. Clients that
ignore proxy settings must lose access, not acquire an alternative route.

Distinguish these deployment claims in documentation and test reports:

| Claim | Required evidence |
| --- | --- |
| Credential brokerage | The declared operations keep managed credentials outside the agent and enforce their grants |
| Confined external communication | The actual sandbox exposes no external communication path except its admitted attachment; the bypass suite passes |
| Inspected protocol coverage | Each advertised protocol passes its parsing, TLS, authentication, and observation suite; confinement alone does not establish plaintext visibility |

"All communication" means communication crossing the declared sandbox boundary,
not every interaction between processes inside it. List exceptions explicitly:
operator-visible console output, task input/output files, and any other approved
host channel. Those channels must not invoke privileged host actions implicitly.
Do not advertise observation of them unless a corresponding adapter exists.
Likewise, a remote MCP server's or provider-hosted tool's further egress is not
made observable merely by mediating the request that invokes it.

## Responsibility split

| Component | Owns | Must not infer |
| --- | --- | --- |
| Trusted launcher / embedding host | OS isolation, permitted mounts and descriptors, process tree, narrow session attachment, teardown | That an HTTP proxy setting is an enforced network boundary |
| Daemon and engine | Session admission, destination/action policy, credentials, approvals, supported transport mediation, observation | That successful attachment proves the caller's entire sandbox is confined |
| Credential-free adapter inside sandbox | Translate supported client traffic into the one attached session | Permission to read host configuration, select other sessions, or connect directly on failure |
| Operator / deployment tests | Review isolation configuration and record evidence for the exact deployment | That a unit test or agent self-report attests confinement |

Use the existing crate split: the engine owns authority, HTTP/MCP adapters own
ingress, and the daemon owns listeners. A deployment test fixture can compose
an external launcher. Do not turn portable libraries into container managers,
add launcher dependencies to the client, or modify Loupe/Goose to satisfy this
contract. Selecting and supporting a production launcher is a separate packaging
decision; its security properties must meet this contract.

## First Linux deployment profile

Use an isolated agent network namespace with no external interface or route.
Loopback may support credential-free adapters and tools inside that same
sandbox; it must not be the host's loopback. The daemon resolves and dials
approved upstreams outside the sandbox. The agent does not need a general DNS
service: it submits an enrolled hostname to the proxy.

Network namespaces separate IP networking and Linux abstract Unix sockets;
filesystem-named Unix sockets still need filesystem confinement. Therefore
network isolation is only one part of this profile.
[Linux network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
[Unix-domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html)

Expose only one session's Unix-domain ingress through a narrow filesystem
projection, or a separately supported session-bound channel. Do not mount the
daemon's runtime parent directory. The operator, owner observation, other
sessions, store, configuration, and CA-key paths remain inaccessible. Preserve
the listener's peer checks and owner-only modes; a different-UID deployment
needs an explicit supported attachment design, not a world-writable socket.

The launcher MUST also establish these properties before any untrusted code
runs, including repository hooks, shell startup files, and MCP subprocesses:

- A restricted filesystem view with only declared project/input/output paths;
  no host home, credential files, catalog, cloud metadata service, container
  control socket, SSH agent, desktop service bus, or host namespace handles.
- Process isolation that prevents inspecting or controlling the daemon,
  launcher, observers, approvers, and other sessions. Host process memory,
  environment, file descriptors, and filesystem roots must not be reachable
  through process interfaces. A same-UID deployment needs explicit enforcement
  and tests; `0700`/`0600` alone do not separate those processes.
- An explicit inherited-descriptor allowlist. Close existing network, native
  store, control, observation, namespace, and unrelated directory descriptors.
  Do not pass through the daemon's unlock-key input or its readiness output.
- A minimal reviewed environment, with no provider credentials, store unlock
  keys, host credential-helper configuration, or unrestricted proxy settings.
  Treat loader/runtime startup settings as part of the launch configuration.
- No capabilities or reachable privileged helpers that can undo confinement.
  Prevent joining host namespaces, changing protected mounts, acquiring host
  process access, or obtaining new descriptors from privileged services.
- Descendants inherit the same boundary. Apply finite process, memory, file,
  and execution budgets, and retain control of the complete process tree.

Same-UID process inspection is a separate concern from private file modes;
its actual restrictions depend on the host configuration. Verify the chosen
process boundary rather than assuming a particular global ptrace setting.
[Linux Yama documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html)

Set and verify `no_new_privs` as part of the launch policy, but do not treat it
as a complete sandbox: it restricts privilege acquisition through execution,
not existing privileges or every way to receive additional authority. The
launcher must account for interactions with its chosen security policy.
[Linux no-new-privileges documentation](https://docs.kernel.org/userspace-api/no_new_privs.html)

Do not enable UDP/QUIC, packet/raw sockets, host networking, or alternate socket
families as compatibility fallbacks. Any supported extra transport must have
an explicit policy and acceptance suite. A plaintext TCP fixture proves byte
observation only; it does not prove that arbitrary application payloads cannot
contain encrypted or encoded data.

## Attachment and failure lifecycle

1. The trusted operator starts the daemon with private configuration/store
   access and checks readiness. Store unlock and future human-approval channels
   stay outside the agent launch environment.
2. The launcher creates a bounded session with the exact resource/item grants
   through the control plane. It retains its revocation authority privately.
3. The launcher constructs the sandbox and exposes only that attachment and,
   where needed, the public interception certificate. It verifies the required
   isolation features before starting the untrusted process tree.
4. Adapters use only that attachment. Their HTTP/MCP identifiers do not select
   an identity or grant authority. Local bridge compromise is treated as agent
   compromise, not as loss of the daemon's credential boundary.
5. Session expiry/revocation stops new dispatch and closes applicable streams.
   On job termination the launcher revokes the session and reaps descendants;
   daemon-enforced expiry remains the backstop if the launcher disappears.
6. A daemon crash, failed attachment, or failed TLS inspection never enables
   direct networking or real credentials in the sandbox. Restart requires a
   fresh trusted session attachment; no automatic resurrection of old grants,
   placeholders, private cookies, or pending approvals.

On setup failure, revoke any allocated session and remove only that launch's
owned resources. Do not start the agent with partially established isolation.
Offline local work may continue after daemon loss if the deployment permits it;
external access must remain denied. No statement here promises rollback of an
operation that already reached an upstream resource.

## Confinement acceptance suite

Run probes from the actual sandbox with the same mounts, identity, descriptors,
environment, and descendant rules used for agent execution. Use only synthetic
secrets and controlled fixture services. Ensure each target exists and is
reachable from an appropriate trusted positive-control process before relying
on its non-reachability from the sandbox. A nonexistent service is not evidence
of confinement. Check receipt counters as well as probe results.

| Probe | Required outcome |
| --- | --- |
| Approved provider/site operation through the attached session | Succeeds with private credentials at the fixture only and correlated safe observation |
| Direct IPv4 and IPv6 to controlled external-to-sandbox listeners | No connection or application bytes arrive, including with proxy variables removed |
| DNS over UDP/TCP and direct HTTPS/QUIC attempts | No unmediated packets reach fixture listeners; undeclared resolver routes through the proxy are denied |
| Host loopback, local-service, link-local, and metadata destinations | Direct access fails; proxy requests fail unless that exact fixture service is separately enrolled |
| Filesystem and abstract host sockets; other session, operator, and observer attachments | No connection or privilege acquisition, even when the probe knows the exact address |
| Private catalog, store, CA key, environment, and process paths | No read or mutation; errors and test reports do not disclose their contents |
| Seeded inherited network/control/directory descriptors | Unapproved descriptors are unavailable after launch; they cannot restore access through an otherwise valid sandbox |
| Process inspection, namespace joining, privileged helpers, and descendant probes | Cannot escape the boundary or access another session's authority |
| Local MCP server and tool subprocess attempting direct egress | Same denial as the agent; credential-free translation is the only admitted external path |
| Daemon death, revocation, restart, and attachment substitution | No fallback egress; old attachments fail and another session's handle cannot be selected through request fields |
| Required-observation or approval mechanism unavailable | Protected dispatch fails closed without relaxing confinement or exposing credentials |

Host-access tests must use harmless fixture resources and known addresses,
not destructive calls against real control services. Filesystem/process probes
should assert denial without printing synthetic private content. Descriptor
tests must exercise deliberate launch inputs, not merely inspect a conveniently
empty descriptor table.

Record the kernel/launcher versions, identity mapping, isolation configuration,
enabled transport profiles, and each case's result: passed, failed, or
unverified. The trusted test runner owns this report; it is not an attestation
accepted from the agent. If namespaces, IPv6, process probes, or other required
facilities are unavailable, mark the affected gate unverified. A skip does not
become a pass and must not silently select a less isolated deployment.

## Delivery gates

During W4, demonstrate confinement with the first provider path and complete
the network/filesystem/process/descriptor probes. During W5-W7, rerun the same
suite with the password-manager, CONNECT, local/remote MCP, and TCP adapters as
they are introduced. W8 records the exact tested deployment and remaining
coverage limits in the handoff. Do not defer the first confinement proof until
after advertising complete interception.

The macOS Keychain backend is an independent credential-custody milestone;
passing its tests does not establish a macOS sandbox. A future macOS deployment
needs platform-specific enforcement and equivalent acceptance evidence without
weakening this contract or introducing an encrypted-SQLite credential fallback.
