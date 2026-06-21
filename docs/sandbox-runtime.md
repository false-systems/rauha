# Rauha Sandbox Runtime

Rauha's primary product shape is an agent sandbox runtime.

The target command is:

```bash
rauha sandbox --image python:3.12 --repo-path . --env RUST_LOG=debug -- pytest tests/
```

## Current State

API/CLI contract and runtime execution are implemented.

What exists today:

- `proto/sandbox.proto` — `rauha.sandbox.v1.SandboxService` with one RPC,
  `RunSandbox(RunSandboxRequest) returns (SandboxResult)`.
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
  "events": [],
  "enforcement_events": []
}
```

`enforcement_events` is best-effort and may be empty. That is the expected
portable baseline on backends without Linux kernel enforcement. On Linux, the
daemon drains a task-scoped subscription from a daemon-wide broadcast; broadcast
lag can still drop events, so consumers must not treat the field as an
audit-complete log.

`timeout_seconds == 0` means wait indefinitely. Callers that need bounded task
execution should set an explicit timeout.

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
