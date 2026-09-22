# Agent authentication proxy

A Rust proof of concept in development: a trusted daemon mediates sandboxed
agent traffic, keeps upstream credentials in a pluggable secret store, and
exports sanitized communication streams. It is not yet ready for use.

See [the design](plan/README.md) and the
[implementation and verification tracker](docs/proof-of-concept.md).

Libraries are separated by responsibility and can be reused by trusted hosts.
The agent-facing client must never acquire a dependency on credential custody.
The planned daemon defaults are native Keychain on macOS and encrypted SQLite
elsewhere. SQLCipher custody is implemented; the macOS adapter is still pending.
The store interface remains backend-neutral.

The first provider slice now runs through a standalone Linux daemon, from
session admission through SQLCipher key retrieval and verified HTTPS to
sanitized streamed output. Exercise it without personal credentials or live
provider requests with `cargo test -p aap-daemon --test process` or the broader
library suite with `cargo test -p aap-engine`. See the [daemon contract](docs/daemon.md).
The controlled form/JSON website flow now works through the engine, with a real
daemon form-login test using fake credentials and private cookies. The
[credential-free MCP bridge](docs/mcp.md) now exposes the vault and bounded
request tools, with real-process form/JSON website tests. Optional
[CONNECT/TLS inspection](docs/connect.md) also brokers provider and website
requests through the session socket. [HTTP observation](docs/observation.md)
now correlates sanitized agent/upstream views, ordered content, and logical
request endings. Collectors have operator-enrolled private session/content
subscriptions with isolated cursors and acknowledgments. Remote MCP, TCP,
complete connection coverage, and confinement demonstrations remain pending.

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

The SQLite backend builds bundled SQLCipher and needs a C compiler, `pkg-config`,
and OpenSSL development libraries. Filesystem fixtures normally use root-owned
sticky `/tmp`; if that parent is unsafe on the test host, set `AAP_TEST_ROOT`
to a trusted existing parent for fresh automatically removed test directories.
Keep `CARGO_TARGET_DIR` under `/tmp` regardless. Do not relax filesystem checks
or change global permissions to make tests pass.

Packages are unpublished while their interfaces stabilize. A distribution
license has not yet been selected; no publishing or release is implied.
