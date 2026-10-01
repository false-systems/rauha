# Rauha Sandbox Runtime

Rauha's primary product shape is an agent sandbox runtime.

The target command is:

```bash
rauha sandbox --image python:3.12 --repo-path . --env RUST_LOG=debug -- pytest tests/
```

## Current State

API/CLI contract and runtime execution are implemented.

What exists today:

- `proto/sandbox.proto` — `rauha.sandbox.v1.SandboxService` with `RunSandbox`,
  `GetSandboxResult`, and `DeleteSandboxResult`.
- `rauha-cli`'s `rauha sandbox` subcommand parses task arguments and calls
  `SandboxService.RunSandbox`.
- `rauhad`'s `SandboxServiceImpl` allocates or resolves a zone, creates and
  starts one container, waits for completion, captures stdout/stderr and
  lifecycle/enforcement event summaries, then tears down temporary resources
  unless `keep_zone` is set.
- `rauha-common::sandbox` exposes the portable result types
  (`SandboxExecResult`, `SandboxStatus`, `SandboxEventSummary`,
  `EnforcementEventSummary`).

Temporary task containers and zones have cancellation cleanup guards. If a
client disconnects while the request future is running, the daemon schedules
forced deletion for resources it owns.

## Result Contract

`rauha-common/src/sandbox.rs` defines the portable result shape for future
sandbox execution:

```json
{
  "task_id": "task_123",
  "zone_id": "zone_456",
  "command": ["pytest", "tests/"],
  "status": "succeeded",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "duration_ms": 1842,
  "started_at": null,
  "finished_at": null,
  "admission": "strict",
  "unavailable_controls": [],
  "capture_issues": [],
  "events": [],
  "enforcement_events": []
}
```

`enforcement_events` is best-effort and may be empty. That is the expected
portable baseline on backends without Linux kernel enforcement. On Linux, the
daemon drains a task-scoped subscription from a daemon-wide broadcast; broadcast
lag can still drop events, so consumers must not treat the field as an
audit-complete log.

`admission` is the effective zone policy, not merely the requested CLI flag.
Strict tasks are rejected when live isolation verification fails. `--audit`
permits a temporary zone to run with those failures and records their check
names in `unavailable_controls` and structured completion evidence.

`timeout_seconds == 0` means wait indefinitely. Callers that need bounded task
execution should set an explicit timeout.

## Output and retained results

The shim drains stdout/stderr through bounded collectors, keeping at most
`evidence.container_log_max_bytes` bytes per stream (default 1 MiB). Broker
records share that per-file limit and are kept only as whole records. Excess
output is drained and discarded; it cannot grow the log file or block the
workload on a full collector. Storage is root-only. An incomplete marker remains
on overflow, I/O failure, or interrupted capture. Container deletion removes
its raw logs; keeping a zone does not keep its completed task containers.

`evidence.sandbox_log_max_bytes` limits each returned text preview (default and
maximum 1 MiB), after UTF-8 replacement. The complete protobuf, including both
receipts, is limited to 4 MiB. Additional event or text reduction is explicit in
`capture_issues`; both receipts sign these issues and hash the delivered text
preview. They do not claim to hash discarded raw output. Log streaming also
limits its initial window to the last 1 MiB and splits lines into bounded chunks.
Enforcement totals count captured decisions; storage-loss flags do not claim an
exact count of discarded broker records.

The CLI prints `task-<UUID>` before sending the execution request. An optional
`--task-id` supplies that identifier explicitly. The daemon reserves capacity
in its existing redb store before execution and saves the signed result before
replying. `rauha sandbox-result <task-id>` returns the same result and exit code,
including after a daemon restart. Reusing a retained ID is refused; it never
silently runs the task twice.

`evidence.results_max_bytes` defaults to 64 MiB of payload capacity. Each task
reserves 4 MiB before executing; completed results occupy their actual encoded
size, while interrupted reservations keep the full budget. Database bookkeeping
is additional. Capacity exhaustion refuses
new tasks before execution; results are not silently evicted. Explicitly release
capacity with `rauha sandbox-result <task-id> --delete`. Active tasks cannot be
deleted, including after restart while their container still requires cleanup.
Requests refused before execution release their reservation. A reservation
without a completed result means running or interrupted,
not “nothing happened”; this is result retention, not task resume or replay.

Per-container caps bound workload output, not the total number of containers
an authorized host client can create. Old orphan logs from earlier versions
are not deleted automatically.

Live regression (Linux, isolated daemon with Alpine pulled, default budgets):
`RAUHA_TEST_RUN_DIR=/run/rauha cargo test -p rauhad --test runtime_output hostile_output -- --ignored --nocapture`.
Run the test executable as a user able to inspect the daemon's root-only logs.
The Linux gate also runs `recovered_shim_cleanup` after its live crash-recovery
probe, checking that deleting the recovered zone shuts down its surviving shim.

## Runtime Flow

1. Create or select a zone for the task (temporary by default, named if
   `--name`/`name` is set).
2. Create and start a container inside the zone, with the configured image,
   command, environment, and workdir.
3. Wait for the container's primary process to exit (respecting
   `timeout_seconds`).
4. Capture stdout, stderr, exit code, and wall-clock duration.
5. Collect zone-level audit events and (where available) Linux kernel
   enforcement events.
6. Clean up the zone unless `keep_zone` is set.
7. Build a `SandboxResult` and return it. CLI then renders human or JSON
   output via the existing `OutputMode` plumbing and mirrors the task exit
   code.
