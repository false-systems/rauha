#!/usr/bin/env bash
# Integration test: agent sandbox task execution (SandboxService.RunSandbox)
# Requires: Linux, root, rauhad running, alpine image pulled
#
# Exercises the end-to-end agent-sandbox contract: run one command in its own
# zone, capture stdout/stderr/exit-code, and mirror the task's exit code. The
# no-name form allocates and tears down a temporary zone automatically.
set -euo pipefail

RAUHA="${RAUHA_BIN:-cargo run --bin rauha --}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
AUDIT_POLICY=${RAUHA_TEST_AUDIT_POLICY:-$ROOT/policies/audit.toml}
IMAGE="${TEST_IMAGE:-alpine:latest}"
NAMED_ZONE="test-sandbox-$$"
RECEIPT_FILE=$(mktemp /tmp/rauha-receipt-XXXXXX.json)

cleanup() {
    echo "Cleaning up..."
    $RAUHA zone delete "$NAMED_ZONE" --force 2>/dev/null || true
    rm -f "$RECEIPT_FILE"
}
trap cleanup EXIT

echo "=== Test: agent sandbox task execution ==="

echo "1. Pulling image (if not present)..."
$RAUHA image pull "$IMAGE" 2>/dev/null || true

echo "2. Running a task in a temporary zone, capturing stdout..."
OUT=$($RAUHA sandbox --audit --image "$IMAGE" -- /bin/echo hello-from-sandbox)
if echo "$OUT" | grep -q "hello-from-sandbox"; then
    echo "   stdout captured (OK)"
else
    echo "   FAIL: task stdout did not contain 'hello-from-sandbox': $OUT"
    exit 1
fi

echo "3. A succeeding task exits 0..."
if $RAUHA sandbox --audit --image "$IMAGE" -- /bin/true >/dev/null 2>&1; then
    echo "   exit 0 on success (OK)"
else
    echo "   FAIL: succeeding task did not exit 0"
    exit 1
fi

echo "4. The CLI mirrors a failing task's exit code..."
set +e
$RAUHA sandbox --audit --image "$IMAGE" -- /bin/sh -c "exit 3" >/dev/null 2>&1
CODE=$?
set -e
if [ "$CODE" -eq 3 ]; then
    echo "   exit code mirrored ($CODE) (OK)"
else
    echo "   FAIL: expected exit code 3, got $CODE"
    exit 1
fi

echo "5. JSON output reports a succeeded status..."
JSON=$($RAUHA --json sandbox --audit --image "$IMAGE" -- /bin/echo hi)
if echo "$JSON" | grep -q '"status":"succeeded"' \
    && echo "$JSON" | grep -q '"exit_code":0' \
    && echo "$JSON" | grep -q '"admission":"audit"' \
    && echo "$JSON" | grep -q '"schema":"rauha.execution-receipt.v1"' \
    && echo "$JSON" | grep -q '"digest_verified":false'; then
    echo "   JSON contract intact; tag pull is not claimed as digest-verified (OK)"
else
    echo "   FAIL: unexpected JSON result: $JSON"
    exit 1
fi

echo "6. A digest-pinned image is receipted as digest-verified..."
DIGEST=$($RAUHA --json image inspect "$IMAGE" | jq -r .digest)
PINNED="${IMAGE%%:*}@$DIGEST"
$RAUHA image pull "$PINNED" >/dev/null
JSON=$($RAUHA --json sandbox --audit --image "$PINNED" -- /bin/true)
if echo "$JSON" | grep -q '"status":"succeeded"' \
    && echo "$JSON" | grep -q "\"manifest_digest\":\"$DIGEST\"" \
    && echo "$JSON" | grep -q '"digest_verified":true'; then
    echo "   pinned digest verified and receipted (OK)"
else
    echo "   FAIL: pinned image receipt: $JSON"
    exit 1
fi

echo "6. The execution receipt verifies independently..."
printf '%s\n' "$JSON" >"$RECEIPT_FILE"
$RAUHA receipt "$RECEIPT_FILE" --public-key "${RAUHA_ROOT:?}/metadata/receipt.ed25519.pub" >/dev/null
echo "   signed receipt verified (OK)"

echo "6b. The DSSE in-toto envelope verifies and carries the manifest as subject..."
DSSE_FILE=$(mktemp /tmp/rauha-receipt-dsse-XXXXXX.json)
echo "$JSON" | jq .receipt_dsse >"$DSSE_FILE"
if echo "$JSON" | jq -e '.receipt_dsse.payloadType == "application/vnd.in-toto+json"' >/dev/null \
    && echo "$JSON" | jq -e '.receipt_dsse.payload | @base64d | fromjson | .predicateType == "https://rauha.dev/execution/v0"' >/dev/null \
    && echo "$JSON" | jq -e --arg d "$DIGEST" '.receipt_dsse.payload | @base64d | fromjson | .subject[0].digest.sha256 == $d[7:]' >/dev/null; then
    echo "   in-toto statement intact, subject = manifest digest (OK)"
else
    echo "   FAIL: DSSE envelope shape: $JSON"
    exit 1
fi
if $RAUHA receipt "$DSSE_FILE" --public-key "${RAUHA_ROOT:?}/metadata/receipt.ed25519.pub" >/dev/null; then
    echo "   DSSE signature verified offline (OK)"
else
    echo "   FAIL: DSSE verification"
    exit 1
fi

echo "7. A named, pre-existing zone is reused and left intact..."
$RAUHA zone create --name "$NAMED_ZONE" --policy "$AUDIT_POLICY"
$RAUHA sandbox --image "$IMAGE" --name "$NAMED_ZONE" -- /bin/echo in-named-zone >/dev/null
if $RAUHA zone list 2>/dev/null | grep -q "$NAMED_ZONE"; then
    echo "   named zone survived the task (OK)"
else
    echo "   FAIL: named zone was deleted (only temporary zones should be)"
    exit 1
fi

echo "=== PASS: agent sandbox task execution ==="
