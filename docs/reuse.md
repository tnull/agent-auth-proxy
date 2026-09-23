# Independent client and trusted-host reuse

The [example consumers](../examples/reuse/README.md) exercise public APIs outside
the root Cargo workspace, with explicit dependencies and separate lockfiles.
They need no package publication or neighboring repository. These are Linux
synthetic acceptance programs, not a production launcher or a Goose integration.

`reuse-client` builds an actual credential-free executable. A separate trusted
test provisions SQLCipher, starts the real daemon, creates two sessions, and
passes only their attachments and a synthetic origin to that executable.
`reuse-embedded` opens a provisioned SQLCipher store and composes the broker,
verified HTTPS transport, resolver, and recorder in the host's runtime. It has
no daemon dependency and does not install listeners, a runtime, or global trust.

`reuse-adapters` now demonstrates host-supplied custody and asynchronous
approval through public traits, plus bounded observation handoff through an
authorized subscription. Its synthetic store is integration-test-only; normal
and test dependency graphs exclude SQLCipher and Apple bindings. See its
[handoff contract and commands](../examples/reuse/adapters/README.md).

## Current shared scenarios

Both consumers run the same driver with form and JSON login profiles. Each run
has eight completed operations and two uncertain operations, exactly ten origin
requests, and a distinct private authentication cookie for each session.

| Plan case | Evidence in this delivery |
| --- | --- |
| R1 | Provider key injection and sanitized streamed output through real HTTPS |
| R2 | Completed-ID reuse without dispatch, changed-input conflict, and stable completed status after cancellation |
| R3 | Ungranted resource and unenrolled origin denial with no additional receipt |
| R4 | Item discovery, repeatable fake-field issuance, private CSRF, form/JSON submission, and protected cookie access |
| R5 | Both sessions authenticate; foreign context use fails; actual authentication cookies remain distinct |
| R6 | Logout invalidates one context without disrupting the other; retained embedded clones and daemon attachments reject work after revocation |
| R7 | Cancellation after response headers and an origin-recorded disconnect end uncertainly; duplicate execution/status does not dispatch again |
| R8 | Full public response headers/bodies, login metadata, typed errors, and decoded observation content exclude seeded managed secrets; each operation has one appropriate ending per view |

The trusted harness independently examines origin receipts and observed records.
The driver report includes public placeholder values so the harness can inspect
the actual returned metadata; it is not a production observation format and is
bounded to 64 KiB for the executable. Cancelled-body evidence includes any bytes
received before the error. Response headers are the cancellation synchronization
point: the fixture records receipt before sending them, then deliberately holds
back the body. Tests do not sleep and infer that dispatch must have occurred.

The embedded tests additionally reject a wrong unlock key, reopen with the
correct key afterward, and refuse an absent store without creating files.
They use public APIs only. No production export or dependency was added to
support these examples.

## Commands, dependencies, and limits

Follow the [runnable commands](../examples/reuse/README.md#run-both-consumers),
including separate normal builds before test-enabled builds. The client normal
graph must exclude trusted broker/authentication/store/configuration components;
its integration-test graph deliberately includes trusted provisioning tools.
The embedded normal graph selects SQLCipher explicitly and excludes the daemon
and test-support crate. Root workspace tests alone do not establish these facts.

The `reuse` CI job describes the independent build, test, dependency, formatting,
lint, and documentation gates. Actual local results are recorded in the
[delivery tracker](proof-of-concept.md). CI configuration is not a remote CI
result, and passing on Linux does not validate Keychain or macOS compatibility.

The provider/website tests do not count secret resolution directly, enforce an
OS sandbox, or establish cross-account isolation using two different accounts. The existing
[confinement fixtures](confinement.md) and remaining
[reuse matrix](../plan/reuse.md#shared-behavioral-suite) are separate gates.
The custom-adapter tests do count secret resolution and exercise denial,
pending approval, store lock/outage/rotation/deletion, cancellation, and actual
recording failure. Observer receipts cannot approve operations, and late
receipts cannot advance a timed-out cursor. These are in-process adapter
checks, not shared daemon/embedded failure-matrix evidence.
Shared failure/rotation scenarios, cookie-backed approval, remote MCP/TCP,
cross-adapter limits, and full shutdown conformance remain required.
The engine currently exposes per-session revocation, not a complete broker-wide
shutdown operation; this example does not claim to close that lifecycle gap.
