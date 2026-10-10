#!/bin/sh
# Compatibility entrypoint; orchestration and assertions live in Rust xtask.
exec cargo run --manifest-path "$(dirname "$0")/../../xtask/Cargo.toml" -- integration container-lifecycle "$@"
