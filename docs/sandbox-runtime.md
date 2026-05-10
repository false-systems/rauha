# Rauha Sandbox Runtime

Rauha's primary product shape is an agent sandbox runtime.

The target command is:

```bash
rauha sandbox --image python:3.12 --repo . -- pytest tests/
```

## Current State

API/CLI contract landed. Runtime execution still planned.

What exists today:

- `proto/sandbox.proto` — `rauha.sandbox.v1.SandboxService` with one RPC,
  `RunSandbox(RunSandboxRequest) returns (SandboxResult)`.
- `rauha-cli`'s `rauha sandbox` subcommand parses task arguments and calls
  `SandboxService.RunSandbox`.
- `rauhad`'s `SandboxServiceImpl` returns `Status::unimplemented` with the
  message *"sandbox execution is not implemented yet; use zone/run/exec
  commands or see docs/sandbox-runtime.md"*.
- `rauha-common::sandbox` exposes the portable result types
  (`SandboxExecResult`, `SandboxStatus`, `SandboxEventSummary`,
  `EnforcementEventSummary`).

What does **not** exist yet:

- allocation of a temporary task zone
- container creation and start inside that zone
- waiting for command completion
- stdout/stderr capture into a single result
- exit code capture
- duration tracking
- task-scoped enforcement event collection
- cleanup of the temporary zone by default

The daemon's RunSandbox method intentionally returns `Unimplemented` so callers
can already write code against the contract while the runtime path is being
built.

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

`enforcement_events` may be empty. That is the expected portable baseline.
When Syvä integration is added, Linux kernel events can populate that field
without changing the user-facing result contract.

## Minimal Implementation Plan

The next PR replaces the `Unimplemented` body in `SandboxServiceImpl` with
real execution. Step list:

1. Create or select a zone for the task (temporary by default, named if
   `--name`/`name` is set).
2. Create and start a container inside the zone, with the configured image,
   command, env, and workdir.
3. Wait for the container's primary process to exit (respecting
   `timeout_seconds`).
4. Capture stdout, stderr, exit code, and wall-clock duration.
5. Collect zone-level audit events and (where available) Linux kernel
   enforcement events.
6. Clean up the zone unless `keep_zone` is set.
7. Build a `SandboxResult` and return it. CLI then renders human or JSON
   output via the existing `OutputMode` plumbing.

The first implementation should wrap existing zone/container primitives
rather than bypassing them with an ordinary host `std::process::Command`.
