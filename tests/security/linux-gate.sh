#!/usr/bin/env bash
# Authoritative privileged Linux gate. The caller supplies a passwordless sudo.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
export RAUHA_ADDR='http://[::1]:9876'
TEST_IMAGE=${TEST_IMAGE:-alpine:latest}
TEST_SECONDARY_IMAGE=${TEST_SECONDARY_IMAGE:-busybox:latest}

[ "$(uname -s)" = Linux ] || { echo "Linux is required" >&2; exit 2; }
test -r /sys/kernel/btf/vmlinux || { echo "kernel BTF is required" >&2; exit 2; }
grep -qw bpf /sys/kernel/security/lsm || { echo "BPF LSM is required" >&2; exit 2; }
for command in cargo bpf-linker crun findmnt ip jq nft pgrep protoc python3 rustup sudo timeout; do
    command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }
done

cargo fmt --all -- --check
cargo clippy --quiet --workspace --all-targets --locked -- -D warnings
cargo test --quiet --workspace --locked
cargo build --quiet --workspace --locked
cargo xtask build-ebpf --release

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/rauha-security.XXXXXX")
DAEMON_LOG="$ROOT/.gate/rauhad.log"
DAEMON_PID_FILE="$RUN_ROOT/rauhad.pid"
HOSTNAME_BEFORE=$(hostname)
mkdir -p "$ROOT/.gate"
DAEMON_PID=""
DAEMON_LAUNCH_PID=""

start_daemon() {
    sudo env RAUHA_ROOT="$RUN_ROOT" RAUHA_PID_FILE="$DAEMON_PID_FILE" \
        sh -c 'printf "%s\n" "$$" >"$RAUHA_PID_FILE"; exec "$1"' \
        sh "$ROOT/target/debug/rauhad" >>"$DAEMON_LOG" 2>&1 &
    DAEMON_LAUNCH_PID=$!

    for _ in $(seq 1 30); do
        [ -s "$DAEMON_PID_FILE" ] && break
        sleep 0.1
    done
    DAEMON_PID=$(cat "$DAEMON_PID_FILE" 2>/dev/null || true)
    [ -n "$DAEMON_PID" ] || { echo "rauhad did not publish its PID" >&2; return 1; }

    for _ in $(seq 1 30); do
        if ! sudo kill -0 "$DAEMON_PID" 2>/dev/null; then
            wait "$DAEMON_LAUNCH_PID" 2>/dev/null || true
            tail -100 "$DAEMON_LOG" >&2
            echo "rauhad exited before becoming ready" >&2
            return 1
        fi
        if "$ROOT/target/debug/rauha" zone list >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    tail -100 "$DAEMON_LOG" >&2
    return 1
}

crash_daemon() {
    sudo kill -KILL "$DAEMON_PID"
    wait "$DAEMON_LAUNCH_PID" 2>/dev/null || true
    DAEMON_PID=""
    DAEMON_LAUNCH_PID=""
    rm -f "$DAEMON_PID_FILE"
}

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        sudo kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_LAUNCH_PID" 2>/dev/null || true
    fi
    while read -r shim_pid; do
        sudo kill "$shim_pid" 2>/dev/null || true
    done < <(pgrep -f -- "--rootfs-root $RUN_ROOT/" || true)
    while read -r mountpoint; do
        sudo umount "$mountpoint" 2>/dev/null || true
    done < <(findmnt -rn -o TARGET | awk -v root="$RUN_ROOT/" 'index($0, root) == 1' | sort -r)
    if [ "$(hostname)" != "$HOSTNAME_BEFORE" ]; then
        sudo hostname "$HOSTNAME_BEFORE"
    fi
    case "$RUN_ROOT" in
        "${TMPDIR:-/tmp}"/rauha-security.*) sudo rm -rf -- "$RUN_ROOT" ;;
        *) echo "refusing to remove unexpected run root: $RUN_ROOT" >&2 ;;
    esac
}
trap cleanup EXIT

if "$ROOT/target/debug/rauha" zone list >/dev/null 2>&1; then
    echo "refusing to test against an endpoint that was already active at $RAUHA_ADDR" >&2
    exit 2
fi

: >"$DAEMON_LOG"
start_daemon

FAILURES=0
TEST_TIMEOUT=${RAUHA_TEST_TIMEOUT_SECONDS:-120}
for test_script in tests/integration/*.sh; do
    if ! sudo env RAUHA_ADDR="$RAUHA_ADDR" RAUHA_BIN="$ROOT/target/debug/rauha" RAUHA_ROOT="$RUN_ROOT" TEST_IMAGE="$TEST_IMAGE" \
        timeout --foreground --kill-after=5s "$TEST_TIMEOUT" bash "$test_script"; then
        echo "FAILED: $test_script" >&2
        FAILURES=$((FAILURES + 1))
    fi
done

# Prove crash recovery against live kernel state, not only serialized metadata.
RECOVERY_STATE="$RUN_ROOT/recovery-probe.state"
sudo env RAUHA_ADDR="$RAUHA_ADDR" RAUHA_BIN="$ROOT/target/debug/rauha" RAUHA_ROOT="$RUN_ROOT" TEST_IMAGE="$TEST_IMAGE" \
    bash "$ROOT/tests/security/recovery-probe.sh" prepare "$RECOVERY_STATE"
crash_daemon
start_daemon
sudo env RAUHA_ADDR="$RAUHA_ADDR" RAUHA_BIN="$ROOT/target/debug/rauha" RAUHA_ROOT="$RUN_ROOT" TEST_IMAGE="$TEST_IMAGE" \
    bash "$ROOT/tests/security/recovery-probe.sh" verify "$RECOVERY_STATE"

# Prove the production two-phase OCI handoff against a Rauha-prepared rootfs.
sudo env RAUHA_ADDR="$RAUHA_ADDR" RAUHA_BIN="$ROOT/target/debug/rauha" RAUHA_ROOT="$RUN_ROOT" TEST_IMAGE="$TEST_IMAGE" \
    bash "$ROOT/tests/security/oci-executor-probe.sh"

if ! timeout --foreground --kill-after=5s "$TEST_TIMEOUT" env RAUHA_GRPC_ENDPOINT=http://[::1]:9876 \
    TEST_IMAGE="$TEST_IMAGE" TEST_SECONDARY_IMAGE="$TEST_SECONDARY_IMAGE" \
    cargo test --quiet --manifest-path eval/oracle/Cargo.toml --locked; then
    echo "FAILED: eval/oracle" >&2
    FAILURES=$((FAILURES + 1))
fi

[ "$FAILURES" -eq 0 ] || { echo "$FAILURES security gate(s) failed" >&2; exit 1; }
