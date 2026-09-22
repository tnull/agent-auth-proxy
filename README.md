# Agent authentication proxy

A Rust proof of concept in development: a trusted daemon mediates sandboxed
agent traffic, keeps upstream credentials in a pluggable secret store, and
exports sanitized communication streams. It is not yet ready for use.

See [the design](plan/README.md) and the
[implementation and verification tracker](docs/proof-of-concept.md).

Libraries are separated by responsibility and can be reused by trusted hosts.
The agent-facing client must never acquire a dependency on credential custody.
macOS uses Keychain directly through `security-framework`; other platforms use
encrypted SQLite. The store interface remains backend-neutral.

## Development

Use the pinned toolchain. Keep build artifacts outside the repository:

```sh
build_target=$(mktemp -d /tmp/cargo-target-agent-auth-proxy-poc.XXXXXX)
export CARGO_TARGET_DIR="$build_target"
cargo fmt --all
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Packages are unpublished while their interfaces stabilize. A distribution
license has not yet been selected; no publishing or release is implied.
