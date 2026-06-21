#!/usr/bin/env bash
# Integration test: agent sandbox task execution (SandboxService.RunSandbox)
# Requires: Linux, root, rauhad running, alpine image pulled
#
# Exercises the end-to-end agent-sandbox contract: run one command in its own
# zone, capture stdout/stderr/exit-code, and mirror the task's exit code. The
# no-name form allocates and tears down a temporary zone automatically.
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
IMAGE="${TEST_IMAGE:-alpine:latest}"
NAMED_ZONE="test-sandbox-$$"

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete --name "$NAMED_ZONE" --force 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Test: agent sandbox task execution ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Running a task in a temporary zone, capturing stdout..."
OUT=$($RAUHA sandbox --image "$IMAGE" -- /bin/echo hello-from-sandbox)
if echo "$OUT" | grep -q "hello-from-sandbox"; then
    echo "   stdout captured (OK)"
else
    echo "   FAIL: task stdout did not contain 'hello-from-sandbox': $OUT"
    exit 1
fi

echo "3. A succeeding task exits 0..."
if $RAUHA sandbox --image "$IMAGE" -- /bin/true >/dev/null 2>&1; then
    echo "   exit 0 on success (OK)"
else
    echo "   FAIL: succeeding task did not exit 0"
    exit 1
fi

echo "4. The CLI mirrors a failing task's exit code..."
set +e
$RAUHA sandbox --image "$IMAGE" -- /bin/sh -c "exit 3" >/dev/null 2>&1
CODE=$?
set -e
if [ "$CODE" -eq 3 ]; then
    echo "   exit code mirrored ($CODE) (OK)"
else
    echo "   FAIL: expected exit code 3, got $CODE"
    exit 1
fi

echo "5. JSON output reports a succeeded status..."
JSON=$($RAUHA --json sandbox --image "$IMAGE" -- /bin/echo hi)
if echo "$JSON" | grep -q '"status":"succeeded"' && echo "$JSON" | grep -q '"exit_code":0'; then
    echo "   JSON contract intact (OK)"
else
    echo "   FAIL: unexpected JSON result: $JSON"
    exit 1
fi

echo "6. A named, pre-existing zone is reused and left intact..."
$RAUHA zone create --name "$NAMED_ZONE"
$RAUHA sandbox --image "$IMAGE" --name "$NAMED_ZONE" -- /bin/echo in-named-zone >/dev/null
if $RAUHA zone list 2>/dev/null | grep -q "$NAMED_ZONE"; then
    echo "   named zone survived the task (OK)"
else
    echo "   FAIL: named zone was deleted (only temporary zones should be)"
    exit 1
fi

echo "=== PASS: agent sandbox task execution ==="
