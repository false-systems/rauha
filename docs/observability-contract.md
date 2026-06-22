# Rauha Observability Contract

Rauha observability is evidence, not decoration. Operational logs must describe
runtime facts in structured fields that can reconstruct a task boundary without
reading prose.

## Event Naming

- Event names are stable dotted strings in `rauha_evidence::event_name`.
- New runtime events use the `rauha.<domain>.<object>.<transition>` shape.
- Enforcement normalizations from lower layers may keep legacy names such as
  `zone.file.denied`, but runtime lifecycle events must use the `rauha.*`
  namespace.
- Event names are append-only once released. Changing semantics requires a new
  event name or `event.version`.

## Required Fields

Every structured runtime event must include:

- `event.name`
- `event.version`
- `event.kind`
- `event.outcome`
- `timestamp`
- `level`

When applicable, events must also include:

- `task_id`
- `zone_id`
- `zone_name`
- `container_id`
- `sandbox_id`
- `command_hash`
- `command_argv_safe`
- `image_ref`
- `repo_path_safe` or `repo_hash`
- `policy_name`
- `policy_hash`
- `backend.name`
- `backend.platform`
- `backend.enforcement_mode`
- `enforcer.backend`
- `enforcer.capabilities`
- `request_id`
- `trace_id`
- `correlation_id`
- `parent_span_id`
- `span_id`
- `duration_ms`
- `error.code`
- `error.kind`
- `error.message`
- `degraded_reason`
- `trust_level`

## Event Kinds

Allowed `event.kind` values:

- `lifecycle`
- `policy`
- `execution`
- `filesystem`
- `network`
- `resource`
- `enforcement`
- `audit`
- `cleanup`
- `backend`
- `error`

## Event Outcomes

Allowed `event.outcome` values:

- `started`
- `succeeded`
- `failed`
- `denied`
- `allowed`
- `skipped`
- `degraded`
- `timed_out`
- `cancelled`

## Trust Model

Allowed `trust_level` values:

- `complete`: the event describes a completed local runtime fact.
- `partial`: the event is true, but related evidence may be missing.
- `best_effort`: the capture path is inherently lossy or attribution is scoped
  from a broader stream.
- `unavailable`: the capability or backend needed to observe the fact is absent.

Best-effort capture must never look complete. When a field is best-effort or
partial, set `trust_level` and `degraded_reason`.

## Enforcement Modes

Allowed `backend.enforcement_mode` values:

- `enforcing`: the backend enforces the boundary before or during action.
- `audit_only`: Rauha can observe but not deny through that path.
- `noop`: a test/no-op enforcer accepted policy operations without kernel
  enforcement.
- `unavailable`: enforcement data or backend capture is not available.

Do not use `enforcing` for a path that is only observed after the fact.

## Enforcement Vs Audit

- Enforcement events are deny-before-action decisions or direct enforcement
  state changes.
- Audit events are observations after an action, or observations from a backend
  that cannot deny that action.
- A denied event must say whether it was enforced or audit-only through
  `backend.enforcement_mode` and `event.kind`.
- If attribution to a task is uncertain, mark the event `partial` and do not
  attach it to the task result as if it were exact.

## Correlation Model

- `correlation_id` is the join key for one user-visible operation.
- For sandbox runs, `correlation_id` currently equals `task_id`.
- A sandbox run should be followable across request receipt, zone allocation,
  policy apply, container start, command exit, capture, cleanup, and result
  return.
- Kernel enforcement events may carry compact backend IDs. They must be
  projected to user-facing zone/task IDs only when the mapping is known.

## Error Model

Every failure event should include:

- `error.code`: stable machine-readable code, for example
  `zone_not_found`, `policy_apply_failed`, `container_cleanup_failed`.
- `error.kind`: coarse class such as `invalid_input`, `not_found`, `backend`,
  `cleanup`, `runtime`, or `permission`.
- `error.message`: bounded, redacted human-readable message.

Human prose belongs in `error.message`, CLI output, and documentation. The
fields above are what automation should use.

## Forbidden Fields And Payloads

Never put these in daemon operational events:

- secrets, tokens, passwords, API keys, credentials
- full environment maps
- private repo contents
- stdout/stderr payload
- arbitrary command output
- SQL-like blobs or unbounded serialized data
- full command argv unless it is already user-visible and redacted

Use `command_hash` instead of raw command where possible. Capture stdout/stderr
in sandbox results, not daemon logs. Daemon capture events may record byte
counts and truncation state.

## Good Event

```json
{
  "timestamp": "2026-06-22T00:00:00.000Z",
  "level": "INFO",
  "event.name": "rauha.sandbox.run.started",
  "event.version": 1,
  "event.kind": "execution",
  "event.outcome": "started",
  "task_id": "task_123",
  "zone_id": "zone_456",
  "zone_name": "task-zone-abc",
  "image_ref": "python:3.12",
  "policy_hash": "sha256:...",
  "backend.name": "linux-ebpf",
  "backend.platform": "linux",
  "backend.enforcement_mode": "enforcing",
  "correlation_id": "task_123",
  "trust_level": "best_effort",
  "degraded_reason": "enforcement_capture_status_reported_separately"
}
```

## Degraded Event

```json
{
  "event.name": "rauha.enforcement.capture.best_effort",
  "event.kind": "enforcement",
  "event.outcome": "degraded",
  "task_id": "task_123",
  "zone_id": "zone_456",
  "backend.enforcement_mode": "enforcing",
  "trust_level": "best_effort",
  "degraded_reason": "daemon_wide_broadcast_scoped_by_kernel_zone_id"
}
```

## Bad Events

Bad because it cannot be joined:

```text
container started
```

Bad because it leaks payload:

```text
task stdout: <full command output here>
```

Bad because it hides best-effort capture:

```json
{"event.name":"sandbox.done","enforcement_events":[]}
```

That event does not say whether there were no enforcement events, capture was
unavailable, broadcast lag dropped events, or attribution was uncertain.
