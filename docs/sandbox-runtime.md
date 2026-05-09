# Rauha Sandbox Runtime

Rauha's primary product shape is an agent sandbox runtime.

The target command is:

```bash
rauha sandbox --image python:3.12 --repo . -- pytest tests/
```

This is not implemented yet. The current repository can create zones and start
containers, but `rauha run` is asynchronous container lifecycle:

1. create a container in an existing zone
2. start it
3. return the container ID

It does not currently:

- allocate a temporary task zone
- wait for command completion
- capture stdout and stderr into a single result
- record duration
- return exit code from the initial process
- collect task-scoped enforcement events
- clean up the temporary zone by default

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
When Syva integration is added, Linux kernel events can populate that field
without changing the user-facing result contract.

## Minimal Implementation Plan

1. Add a daemon RPC for task-level sandbox execution.
2. Create or select a zone for the task.
3. Create/start a container or process inside the zone.
4. Wait for completion.
5. Capture stdout, stderr, exit code, and duration.
6. Collect audit and enforcement event summaries.
7. Clean up by default, with an explicit keep/debug option.
8. Add `rauha sandbox` CLI with `--json`.

The first implementation should wrap existing zone/container primitives rather
than bypassing them with an ordinary host `std::process::Command`.
