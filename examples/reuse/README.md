# Independent public-API consumers

These development-only examples use synthetic credentials and controlled HTTPS
origins. `client` and `embedded` are separate Cargo workspaces with explicit
dependencies and their own lockfiles. Neither inherits root workspace features
or consumer dependency settings. The independent [adapters](adapters/README.md)
consumer additionally demonstrates a host-supplied test store, async approval,
and bounded observation handoff without linking a native secret backend.
Local path dependencies use this Git checkout;
there is no package publication or dependency on Goose/Loupe.

`support/scenarios.rs` is shared credential-free application code. Both paths
must execute the same provider and website scenarios. `support/fixture.rs` is
trusted test-only orchestration and never enters the client binary. The latter
owns SQLCipher provisioning, real synthetic credential expectations, upstream
receipt counters, and observation checks.

The examples demonstrate public API reuse, not OS confinement or production
packaging. The wider [reuse acceptance matrix](../../plan/reuse.md) remains a
separate gate, including shared approval/store failures, remote MCP/TCP, and shared
quota/shutdown races. See each consumer's README for its trust boundary.

## Run both consumers

From the repository root on Linux, with the pinned toolchain and SQLCipher's
C compiler, `pkg-config`, and OpenSSL development prerequisites installed:

```sh
reuse_target=$(mktemp -d /tmp/cargo-target-aap-reuse.XXXXXX)
CARGO_TARGET_DIR="$reuse_target/daemon" cargo build -p aap-daemon --bin agent-auth-proxy --locked
export AAP_DAEMON="$reuse_target/daemon/debug/agent-auth-proxy"

# Normal builds are separate from test-enabled builds and from each other.
CARGO_TARGET_DIR="$reuse_target/client" cargo build --manifest-path examples/reuse/client/Cargo.toml --locked --bin reuse-client
CARGO_TARGET_DIR="$reuse_target/embedded" cargo build --manifest-path examples/reuse/embedded/Cargo.toml --locked --lib
CARGO_TARGET_DIR="$reuse_target/client" cargo test --manifest-path examples/reuse/client/Cargo.toml --locked
CARGO_TARGET_DIR="$reuse_target/embedded" cargo test --manifest-path examples/reuse/embedded/Cargo.toml --locked
```

Private fixtures default to `/tmp`. If that directory has unsafe permissions
on the host, set `AAP_TEST_ROOT` to an existing trusted parent directory; do not
change global permissions or relax the private-file checks. Keep build output
under `/tmp` regardless. Each run creates and removes only its own synthetic
fixture directories. Wrong-key tests may emit fixed SQLCipher decryption
diagnostics, not credentials or the key.

Repeat the commands with `RUSTUP_TOOLCHAIN=1.88.0` and a fresh build directory
for the declared MSRV; the client must test a daemon built by that compiler too.
These workspaces are not members of the root workspace: root-only Cargo commands
do not build or test them. Their lockfiles pin the registry graph; path packages
come from this exact checkout, not a released API or a moving Git dependency.

Formatting and dependency review are also explicit:

```sh
rustfmt --edition 2024 --check examples/reuse/support/scenarios.rs examples/reuse/support/fixture.rs
for consumer in client embedded adapters; do
  manifest="examples/reuse/$consumer/Cargo.toml"
  cargo fmt --manifest-path "$manifest" --all -- --check
  cargo locate-project --manifest-path "$manifest" --workspace --message-format plain
  cargo tree --manifest-path "$manifest" --locked --edges normal,build --prefix none
  CARGO_TARGET_DIR="$reuse_target/$consumer" cargo clippy --manifest-path "$manifest" --all-targets --locked -- -D warnings
  CARGO_TARGET_DIR="$reuse_target/$consumer" RUSTDOCFLAGS=-Dwarnings cargo doc --manifest-path "$manifest" --no-deps --locked
done
```

The `reuse` CI job checks both compilers, workspace roots, normal dependency
closures, and real-process tests. Its presence is not evidence that remote CI
has run. See [current integration evidence](../../docs/reuse.md) for scope.

The [custom-adapter consumer](adapters/README.md) has its own build/test commands.
It does not need `AAP_DAEMON` or a SQLCipher vault; its fixture store is test-only,
not an operational alternative to the encrypted/native backends.
