#!/usr/bin/env bash
# Integration test: cgroup_lock eBPF enforcement
#
# Verifies:
#   1. Same-zone cgroup move succeeds (container creation requires shim enrollment)
#   2. Cross-zone cgroup move is denied by eBPF cgroup_attach_task hook
#
# Requires: Linux, root, rauhad running with eBPF loaded, alpine image pulled.
# The cross-zone denial test only works when eBPF enforcement is active.
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ZONE_A="test-cglock-a-$$"
ZONE_B="test-cglock-b-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"
FIFO="/tmp/rauha-test-cglock-$$"
RESULT_FILE="/tmp/rauha-test-cglock-result-$$"
ERR_FILE="/tmp/rauha-test-cglock-error-$$"
HELPER_PID=""

cleanup() {
    if [ -n "${HELPER_PID:-}" ]; then
        kill "$HELPER_PID" 2>/dev/null || true
        wait "$HELPER_PID" 2>/dev/null || true
    fi
    rm -f "$FIFO" "$RESULT_FILE" "$ERR_FILE"
    $RAUHA zone delete --name "$ZONE_A" --force 2>/dev/null || true
    $RAUHA zone delete --name "$ZONE_B" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== cgroup_lock enforcement test ==="

# Pull image (idempotent).
$RAUHA image pull "$IMAGE" 2>/dev/null || true

# Create two zones.
$RAUHA zone create --name "$ZONE_A"
$RAUHA zone create --name "$ZONE_B"

CGROUP_A="/sys/fs/cgroup/rauha.slice/zone-${ZONE_A}"
CGROUP_B="/sys/fs/cgroup/rauha.slice/zone-${ZONE_B}"

# Verify cgroup directories exist.
if [ ! -d "$CGROUP_A" ] || [ ! -d "$CGROUP_B" ]; then
    echo "SKIP: zone cgroup directories not found (cgroups may not be available)"
    exit 0
fi

# --- Test 1: Same-zone cgroup move succeeds ---
# Container creation requires the shim to write the child's PID into the
# zone's cgroup.procs. If cgroup_lock incorrectly denies same-zone moves,
# this fails.
echo "Test 1: same-zone cgroup move (container creation)..."
CONTAINER_ID=$($RAUHA run --zone "$ZONE_A" "$IMAGE" /bin/sleep 30 2>/dev/null)
if [ -z "$CONTAINER_ID" ]; then
    echo "FAIL: container creation failed — cgroup_lock may be blocking same-zone moves"
    exit 1
fi
echo "  PASS: container created in zone A (same-zone cgroup move succeeded)"

sleep 1

# Verify a process is in zone A's cgroup.
PROCS_A=$(cat "${CGROUP_A}/cgroup.procs" 2>/dev/null | wc -l)
if [ "$PROCS_A" -eq 0 ]; then
    echo "  WARN: no processes found in zone A cgroup (shim may manage differently)"
fi

# --- Test 2: Cross-zone cgroup move is denied ---
# We enroll a helper process in zone A's cgroup (from unzoned context, which
# is allowed because the caller is not in any zone). Then the helper — now
# inside zone A — tries to move itself to zone B's cgroup. The eBPF
# cgroup_attach_task hook should deny this with EPERM.
echo "Test 2: cross-zone cgroup move (should be denied by eBPF)..."

mkfifo "$FIFO"

# Start helper process that waits for enrollment, then attempts cross-zone move.
(
    # Wait until we've been enrolled in zone A.
    cat "$FIFO" > /dev/null

    # Try to move this helper process to zone B's cgroup. Use BASHPID so the
    # helper writes its own PID, not the parent script's PID.
    set +e
    echo "$BASHPID" > "${CGROUP_B}/cgroup.procs" 2>"$ERR_FILE"
    rc=$?
    printf '%s\n' "$rc" > "$RESULT_FILE"

    # Stay alive long enough for the parent to observe cgroup membership if the
    # write unexpectedly succeeds. Without this, a successful move can be hidden
    # by process exit before cgroup.procs is checked.
    sleep 10
) &
HELPER_PID=$!

# Give the helper time to start and block on the FIFO.
sleep 0.2

# Enroll the helper's shell process into zone A's cgroup.
# This write comes from the test script (unzoned), so cgroup_lock allows it.
if ! echo "$HELPER_PID" > "${CGROUP_A}/cgroup.procs" 2>/dev/null; then
    echo "  SKIP: could not enroll helper in zone A cgroup (may need root)"
    echo "go" > "$FIFO"
    wait "$HELPER_PID" 2>/dev/null || true
    exit 0
fi

# Signal helper to proceed with the cross-zone move attempt.
echo "go" > "$FIFO"

# Capture the helper's cgroup.procs write result.
for _ in $(seq 1 50); do
    if [ -s "$RESULT_FILE" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -s "$RESULT_FILE" ]; then
    echo "  FAIL: helper did not report cross-zone cgroup move result"
    exit 1
fi

RESULT=$(cat "$RESULT_FILE")
if [ "$RESULT" -eq 0 ]; then
    echo "  FAIL: cross-zone cgroup move write succeeded"
    echo "  This means cgroup_lock eBPF enforcement is not active."
    exit 1
fi

# Also check: is the helper still in zone A's cgroup (not zone B's)?
HELPER_IN_B=$(grep -c "^${HELPER_PID}$" "${CGROUP_B}/cgroup.procs" 2>/dev/null || echo "0")

if [ "$HELPER_IN_B" -gt 0 ]; then
    echo "  FAIL: helper process found in zone B's cgroup — cross-zone move was allowed"
    echo "  This means cgroup_lock eBPF enforcement is not active."
    exit 1
fi

echo "  PASS: cross-zone cgroup move correctly denied"

# Cleanup the container.
$RAUHA stop "$CONTAINER_ID" 2>/dev/null || true

echo "=== All cgroup_lock tests passed ==="
