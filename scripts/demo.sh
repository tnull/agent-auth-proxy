#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
    echo "Usage: $0 [serve|smoke|check] [STATE_DIRECTORY]"
    echo 'Linux synthetic demo. Default: serve, state in $HOME/.aap-demo.'
    echo "serve: start and keep running; smoke: verify and stop; check: use a running demo."
    exit 0
fi
demo_mode=${1:-serve}
case "$demo_mode" in serve|smoke|check) ;; *) echo "Unknown demo command; use --help." >&2; exit 2 ;; esac
if (( $# > 2 )); then echo "Too many arguments; use --help." >&2; exit 2; fi
if [[ $(uname -s) != Linux ]]; then echo "This demo currently requires Linux." >&2; exit 2; fi

demo_repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
demo_state=${2:-${HOME:?HOME is needed for the default demo state}/.aap-demo}
if [[ $demo_state != /* ]]; then demo_state="$PWD/$demo_state"; fi
if [[ -z ${CARGO_TARGET_DIR:-} ]]; then
    CARGO_TARGET_DIR=$(mktemp -d /tmp/cargo-target-aap-demo.XXXXXX)
fi
case "$CARGO_TARGET_DIR" in /tmp/*) ;; *) echo "Set CARGO_TARGET_DIR to a build directory under /tmp." >&2; exit 2 ;; esac
export CARGO_TARGET_DIR
echo "Demo build directory: $CARGO_TARGET_DIR" >&2
cd -- "$demo_repo"
cargo build --locked -p aap-daemon --bin agent-auth-proxy --example demo

if [[ $demo_mode == check ]]; then
    exec "$CARGO_TARGET_DIR/debug/examples/demo" check "$demo_state"
fi
exec "$CARGO_TARGET_DIR/debug/examples/demo" "$demo_mode" "$demo_state" "$CARGO_TARGET_DIR/debug/agent-auth-proxy"
