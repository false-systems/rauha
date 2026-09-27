#!/usr/bin/env bash
# Run Rauha's privileged security gate on the local Linux host or one Lima VM.
set -euo pipefail

[ "$#" -eq 0 ] || { echo "usage: tests/security/run.sh" >&2; exit 2; }

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

running_lima() {
    limactl list --format '{{.Name}} {{.Status}}' | awk '$2 == "Running" { print $1 }'
}

select_lima() {
    local selected=${RAUHA_LIMA_INSTANCE:-}
    if [ -z "$selected" ]; then
        local running count
        running=$(running_lima)
        count=$(printf '%s\n' "$running" | sed '/^$/d' | wc -l | tr -d ' ')
        if [ "$count" -ne 1 ]; then
            echo "expected one running Lima instance, found $count; set RAUHA_LIMA_INSTANCE" >&2
            exit 2
        fi
        selected=$running
    fi
    if [ "$(limactl list --format '{{.Status}}' "$selected")" != Running ]; then
        echo "Lima instance $selected is not running" >&2
        exit 2
    fi
    printf '%s\n' "$selected"
}

GATE="$ROOT/tests/security/linux-gate.sh"
IMAGES=(TEST_IMAGE="${TEST_IMAGE:-alpine:latest}" TEST_SECONDARY_IMAGE="${TEST_SECONDARY_IMAGE:-busybox:latest}")

if [ "$(uname -s)" = Linux ]; then
    exec env "${IMAGES[@]}" bash "$GATE"
fi

instance=$(select_lima)
exec limactl shell "$instance" -- env "${IMAGES[@]}" bash "$GATE"
