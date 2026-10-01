#!/usr/bin/env bash
# Integration test: seccomp-notify FD broker (the Capsicum-shaped primitive)
# Requires: Linux, root, rauhad running, alpine image pulled
#
# With policies/broker.toml every openat/openat2 in the zone suspends in the
# kernel and is judged by the zone shim: read-only opens are granted by fd
# injection, everything else is answered with an honest errno. This test
# proves the three faces end to end through the sandbox task contract
# (which waits for the task and mirrors its exit code): a grant (cat a
# file), a policy denial (a write open), and the decision record
# (broker.log).
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BROKER_POLICY=${RAUHA_TEST_BROKER_POLICY:-$ROOT/policies/broker.toml}
RUN_DIR="${RAUHA_RUN_DIR:-/run/rauha}"
ZONE_NAME="test-broker-$$"
IMAGE="${TEST_IMAGE:-alpine:latest}"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete "$ZONE_NAME" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: seccomp-notify FD broker ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Creating zone with brokered-opens policy..."
$RAUHA zone create --name "$ZONE_NAME" --policy "$BROKER_POLICY"

echo "3. A read-only open is granted: cat reads /etc/hostname through the broker..."
OUT=$($RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 -- /bin/cat /etc/hostname)
if [ -n "$OUT" ]; then
    echo "   granted open (OK): $OUT"
else
    echo "   FAIL: cat produced no output — the brokered read open did not resolve"
    exit 1
fi

echo "4. A relative open resolves beneath the workload's own cwd..."
OUT=$($RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
    -- /bin/sh -c 'cd /etc && cat hostname')
if [ -n "$OUT" ]; then
    echo "   relative granted open (OK): $OUT"
else
    echo "   FAIL: relative open through the broker did not resolve"
    exit 1
fi

echo "5. Directory opens are granted (O_DIRECTORY must not trip O_TMPFILE)..."
if $RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
    -- /bin/ls /usr >/dev/null 2>&1; then
    echo "   directory open granted (OK)"
else
    echo "   FAIL: ls /usr failed — O_DIRECTORY opens must be grantable"
    exit 1
fi

echo "6. A write open is denied with an honest errno (task exit code is mirrored)..."
set +e
$RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
    -- /bin/sh -c 'echo brokered > /tmp/broker-write-test' >/dev/null 2>&1
CODE=$?
set -e
if [ "$CODE" -ne 0 ]; then
    echo "   write open denied, task exit $CODE (OK)"
else
    echo "   FAIL: a write open succeeded under a broker that only grants read-only"
    exit 1
fi

echo "7. Decisions were recorded in the container's broker.log..."
LOGS=$(ls -t "$RUN_DIR"/containers/*/broker.log 2>/dev/null | head -3 || true)
if [ -z "$LOGS" ]; then
    echo "   FAIL: no broker.log under $RUN_DIR/containers/"
    exit 1
fi
GRANTED=$(grep -h '"decision":"granted"' $LOGS | wc -l | tr -d ' ')
DENIED=$(grep -h '"decision":"denied"' $LOGS | wc -l | tr -d ' ')
if [ "$GRANTED" -ge 1 ] && [ "$DENIED" -ge 1 ]; then
    echo "   broker.log: $GRANTED granted, $DENIED denied (OK)"
    grep -h '"syscall":"openat"' $LOGS | head -2 | sed 's/^/     /'
else
    echo "   FAIL: expected grants and denials in broker.log, got $GRANTED/$DENIED"
    exit 1
fi

echo "8. Broker decisions surface in the sandbox result as enforcement events..."
JSON=$($RAUHA --json sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
    -- /bin/cat /etc/hostname)
if echo "$JSON" | grep -q '"hook":"seccomp_notify"' \
    && echo "$JSON" | grep -q '"action":"zone.syscall.brokered.granted"'; then
    echo "   enforcement event in result (OK)"
else
    echo "   FAIL: sandbox result did not carry broker decisions as enforcement events"
    echo "$JSON" | head -5
    exit 1
fi

echo "9. Broker decisions stream live on rauha events..."
EVENTS_OUT=$(mktemp /tmp/rauha-events-XXXXXX.jsonl)
(timeout 12 $RAUHA events --json >"$EVENTS_OUT" 2>/dev/null || true) &
EVENTS_PID=$!
sleep 1
$RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
    -- /bin/cat /etc/hostname >/dev/null 2>&1 || true
wait "$EVENTS_PID" 2>/dev/null || true
if ! grep -q 'zone.syscall.brokered' "$EVENTS_OUT"; then
    # Subscription timing can lose the first task under load: one retry
    # before declaring failure.
    sleep 3
    $RAUHA sandbox --name "$ZONE_NAME" --image "$IMAGE" --timeout 30 \
        -- /bin/cat /etc/hostname >/dev/null 2>&1 || true
    sleep 2
fi
if grep -q 'zone.syscall.brokered' "$EVENTS_OUT"; then
    echo "   live event seen (OK)"
    grep -m 1 -o '"event":"zone.syscall.brokered[^"]*"' "$EVENTS_OUT" | sed 's/^/     /'
else
    echo "   FAIL: no zone.syscall.brokered event on the events stream"
    exit 1
fi
rm -f "$EVENTS_OUT"

echo "10. run-created containers stream broker decisions too..."
EVENTS_OUT=$(mktemp /tmp/rauha-events-XXXXXX.jsonl)
(timeout 12 $RAUHA events --json >"$EVENTS_OUT" 2>/dev/null || true) &
EVENTS_PID=$!
sleep 1
$RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/cat /etc/hostname >/dev/null 2>&1 || true
wait "$EVENTS_PID" 2>/dev/null || true
if ! grep -q 'zone.syscall.brokered' "$EVENTS_OUT"; then
    # Same subscription race as step 9: one retry.
    sleep 3
    $RAUHA run --zone "$ZONE_NAME" "$IMAGE" /bin/cat /etc/hostname >/dev/null 2>&1 || true
    sleep 2
fi
if grep -q 'zone.syscall.brokered' "$EVENTS_OUT"; then
    echo "   live event from run container (OK)"
else
    echo "   FAIL: no brokered event for a run-created container"
    exit 1
fi
rm -f "$EVENTS_OUT"

echo "=== PASS: seccomp-notify FD broker ==="
