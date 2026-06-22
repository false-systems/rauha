# Rauha Observability Audit

This audit captures the state before the first evidence-grade observability
pass. It is an inventory, not a claim that every item is fixed.

## Current Event/Log Locations

- `rauhad/src/main.rs` emits daemon startup, backend initialization, gRPC ready,
  shutdown, and network cleanup logs.
- `rauhad/src/zone/registry.rs` owns zone lifecycle, policy hot reload,
  container lifecycle, rootfs preparation, lazy container reaping, stats, and
  shim request paths.
- `rauhad/src/server.rs` owns gRPC request handling, watch events, sandbox task
  execution, sandbox result construction, enforcement-event capture, exec,
  attach, image service, and policy parsing at the API boundary.
- `rauhad/src/backend/linux/*` emits cgroup, namespace, veth, nftables, eBPF,
  BPF map, enforcement event reader, and Linux shim lifecycle logs.
- `rauhad/src/backend/macos/*` emits VM, APFS, pf, vsock, and macOS container
  lifecycle logs. `vm.rs` still has `eprintln!` debug-style lines.
- `rauha-evidence` already normalizes Linux enforcement events and owns sinks,
  but daemon lifecycle and sandbox runtime paths were not using a central
  `event.name` contract.
- `rauha-cli` uses `println!`/`eprintln!` for user-facing output. That is
  acceptable; CLI output is not daemon evidence.
- `rauha-shim` and `rauha-guest-agent` emit child/container lifecycle logs.
  Some exec logs include `?command`, which can carry sensitive argv.
- `rauha-enforce` is legacy and has monitor/status output plus eBPF logs. It
  should not be extended as the primary Rauha evidence path.

## Missing Correlation Fields

- Most daemon logs lacked `event.name`, `event.version`, `event.kind`, and
  `event.outcome`.
- Sandbox execution had `task_id` in result data but not consistently on daemon
  runtime logs.
- Zone/container logs often included only zone name or container id, not both.
- Enforcement capture had good zone-id matching logic but did not explicitly log
  whether capture was best-effort, incomplete, or unavailable for each task.
- Backend and enforcement mode were not consistently present on lifecycle logs.
- Request/correlation IDs were not propagated across CLI request -> daemon ->
  zone allocation -> container start -> command exit -> cleanup -> result.

## Unsafe Or Noisy Logs

- `rauha-shim/src/main.rs` and `rauha-guest-agent/src/main.rs` log `?command`
  for exec operations. These should become command hashes plus redacted
  user-visible argv only when safe.
- `rauhad/src/backend/macos/vm.rs` contains direct `eprintln!` diagnostics. They
  should become structured backend events or be downgraded behind explicit
  local debugging.
- Several backend warnings are prose-only and need stable `error.code` /
  `error.kind` fields.
- CLI `logs` intentionally prints container stdout/stderr. That must stay a
  user-facing stream and must not be mirrored into daemon operational logs.

## Structured Events Added In This Pass

- Daemon/backend:
  - `rauha.daemon.start`
  - `rauha.backend.selected`
  - `rauha.daemon.ready`
  - `rauha.daemon.shutdown`
- Zone/policy:
  - `rauha.zone.create.started`
  - `rauha.zone.create.succeeded`
  - `rauha.zone.create.failed`
  - `rauha.zone.delete.started`
  - `rauha.zone.delete.succeeded`
  - `rauha.zone.delete.failed`
  - `rauha.policy.apply.started`
  - `rauha.policy.apply.succeeded`
  - `rauha.policy.apply.failed`
- Sandbox:
  - `rauha.sandbox.run.started`
  - `rauha.sandbox.zone.allocated`
  - `rauha.sandbox.container.started`
  - `rauha.sandbox.command.started`
  - `rauha.sandbox.command.exited`
  - `rauha.sandbox.command.timed_out`
  - `rauha.sandbox.stdout.captured`
  - `rauha.sandbox.stderr.captured`
  - `rauha.sandbox.result.built`
  - `rauha.sandbox.cleanup.succeeded`
  - `rauha.sandbox.cleanup.partial`
  - `rauha.sandbox.run.succeeded`
  - `rauha.sandbox.run.failed`
- Enforcement capture:
  - `rauha.enforcement.capture.best_effort`
  - `rauha.enforcement.capture.incomplete`
  - `rauha.enforcer.unavailable`

## Remaining Places To Convert

- Linux backend cgroup/namespace/network/eBPF map operations should emit the
  resource, network, filesystem, and enforcement event names defined in
  `rauha-evidence::event_name`.
- macOS VM/pf/APFS paths should replace direct `eprintln!` diagnostics with
  structured backend events.
- `rauha-shim` and `rauha-guest-agent` should stop logging full command argv.
- containerd shim should emit `rauha.containerd.*` and `rauha.k8s.*` names when
  Kubernetes identity is present or missing.
- Policy parse/load paths should include policy hashes and machine-readable
  validation codes before and after `parse_policy`.
- Resource sampling/pressure/OOM detection names are defined but not fully
  wired.

## Stdout/Stderr Leakage Risk

- Daemon sandbox capture reads stdout/stderr into the sandbox result only.
  Structured capture events record byte counts, not payload.
- CLI log streaming prints payload by design, outside daemon operational logs.
- Shim/guest-agent exec command logging remains a follow-up risk because argv
  can encode secrets even when stdout/stderr are not logged.

## Best-Effort Behavior

- Enforcement capture is best-effort because it drains a daemon-wide broadcast
  scoped by compact kernel zone id. Broadcast lag can drop events.
- If there is no event broadcast, capture is `unavailable`.
- If a broadcast exists but no kernel zone id is available, capture is
  `partial` / incomplete and events are not attributed.
- Empty enforcement events in a sandbox result must not be interpreted as an
  audit-complete statement.
