# Host-supplied adapter consumer

An independent, unpublished example using only public engine, store, approval,
and observation interfaces. The host is trusted and remains outside the agent
sandbox. The in-memory synthetic secret store exists only in integration-test
code; it is not an operational backend or fallback. Neither normal nor test
builds select SQLCipher or Apple framework dependencies.

The library illustrates bounded asynchronous handoffs to a trusted approver and
observation consumer. It installs no runtime, listener, task, or global state.
The caller drives its futures. This is not a signed approval protocol or human
UI. The test exercises real verified HTTPS using synthetic credentials.

Run from the repository root with an isolated target directory:

```sh
adapter_target=$(mktemp -d /tmp/cargo-target-aap-adapters.XXXXXX)
export CARGO_TARGET_DIR="$adapter_target"
cargo build --manifest-path examples/reuse/adapters/Cargo.toml --locked --lib
cargo test --manifest-path examples/reuse/adapters/Cargo.toml --locked
```

No vault provisioning, unlock key, daemon executable, or private filesystem
fixture is needed. This is API composition evidence, not OS confinement.

## Handoff semantics

`ApprovalInbox` transfers the engine's immutable request to a trusted receiver.
Its queue has an explicit capacity of 1–16 requests; a full or closed queue
fails closed. Receiving a request is not approval. `PendingApproval::decide`
consumes that one decision handle, and reports a closed receiver after engine
cancellation, expiry, or loss of the owning operation. A successfully queued
decision is not proof of dispatch: the engine still revalidates policy and the
credential lease. No real credential is resolved during the wait.

The example does not authenticate a human or verify a signature. A future UI
must display the actual request binding and authenticate its approver before
calling `decide`. The host, UI, and injected store are trusted components, not
isolated plugins. They cannot broaden the agent's grants through this interface.
Native store unlock/user presence remains independent of operation approval.

`ObservationForwarder` owns an already authorized subscription. Each caller-driven
forward transfers at most 32 records / 16 KiB to a channel of at most 16 pages,
then waits at most ten seconds for the consumer's receipt. It acknowledges the
subscription only after that receipt and before advancing its cursor. Expiry
wins if a receipt and deadline are both ready. The acknowledgment method only
queues a receipt; the forward result confirms whether it was accepted.

Full/closed queues, dropped pages, timeout, and abandoned forwards retain the
old cursor. A later call can repeat delivery IDs, so consumers must tolerate
duplicates. Retention overflow can still produce an explicit gap. This is not
durable or exactly-once delivery, and acknowledging a page does not prove an
IDS evaluated it or authorize an operation. Dropping the forwarder closes its
subscription and releases its claims; the host still owns other recorder claims.

The configured acceptance boundary is the bounded local recorder. A disconnected
downstream consumer does not itself make recording unavailable while that
recorder has capacity. The tests separately fail the actual recording boundary
and prove no secret resolution or dispatch follows in required mode.

## Verified scenarios and limits

The test-only store provides coherent leases, counted metadata/resolution, and
controlled lock, outage, interaction-required, rotation, and deletion changes.
Real HTTPS requests prove both initial and freshly approved rotated credentials
work; stale pending approval cannot release them. Other scenarios cover denied
destinations/resources, full/closed approval queues, cancellation, revocation,
dropped execution/approver, late approval, observation replay after loss, queue
overflow, deadlines, and the separation of observer acknowledgment from consent.

This example does not supply the daemon with dynamically loaded plugins. It
does not complete store-backend conformance, cookie-backed approval, the shared
daemon/embedded failure matrix, remote MCP/TCP parity, or broker-wide shutdown.
Those remain requirements in [the reuse plan](../../../plan/reuse.md).
