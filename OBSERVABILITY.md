# Rauha Evidence Surface

Ownership reading for this PR: Syva is the eBPF LSM enforcer. `rauha-evidence`
is Rauha's evidence/observability surface. It consumes raw Syva/backend records
plus Rauha lifecycle events and owns schema, projections, and sinks. It does not
enforce policy and does not add sandbox execution.

## Data Path

Linux:

1. eBPF LSM hooks emit fixed `EnforcementEvent` records into
   `ENFORCEMENT_EVENTS`.
2. `ENFORCEMENT_EVENTS` is declared as Aya eBPF `ring_buf::RingBuf`, which maps
   to `BPF_MAP_TYPE_RINGBUF` rather than perfbuf.
3. `rauhad` drains the Aya userspace `RingBuf` and normalizes each raw record
   immediately into `rauha_evidence::FalseEvent`.
4. The existing gRPC `WatchEvents` API projects the same canonical event into
   the existing `ZoneEvent` message without changing the proto contract.

macOS:

The macOS backend has no ring buffer. Guest-agent/vsock events must normalize
into the same `FalseEvent` schema at the adapter edge before reaching sinks.
That adapter is intentionally not implemented in this observe-only pass.

## Event Taxonomy

All event names are constants in `rauha_evidence::event_name`. The message
position is stable; variance belongs in event fields.

Reserved sandbox names are present in the schema:

- `task.started`
- `task.succeeded`
- `task.failed`

They are not emitted until the separate sandbox runtime PR.

## Projections

One `FalseEvent` supports three renderings:

- machine JSON: `FalseEvent::machine_json()`
- compact human: `FalseEvent::compact_human()`
- expanded human: `FalseEvent::expanded_human()`

The daemon emits normalized events through `tracing` with constant message
`rauha.evidence` and structured fields. The existing gRPC watch surface carries
machine JSON in `ZoneEvent.message` and the constant canonical name in
`ZoneEvent.event_type`.

## Cardinality

`rauha_evidence::validate_metric_labels` rejects high-cardinality labels:

- `zone.id`
- `container.id`
- `actor.id`
- `inode`
- `pid`
- `connection.id`
- `trace_id`

These identifiers are event fields only. Aggregate metrics should use
`event` and bounded zone buckets, never raw IDs.

## Overflow And Shedding

Current behavior:

- BPF ring buffer records use Aya `RingBuf::output`.
- Userspace subscriber lag in the existing watch API is converted into a
  `pipeline.shed` event and traced.
- Undersized ring-buffer records are converted into `pipeline.shed`.

Known gap:

- Kernel-side `RingBuf::output` failure is currently not counted as
  `ringbuf.drop`; the eBPF program still discards the return value. Evidence is
  therefore shaped and non-silent once it reaches userspace, but a full kernel
  ring buffer still needs a dedicated BPF-side counter map to satisfy the
  `ringbuf.drop` acceptance criterion completely.

Denial records are evidence. Telemetry may be sampled in future work; denials
must not be sampled away.

## Overhead Measurement

The hot path still emits a fixed-size struct and performs no rendering or string
interpolation in kernel space. Reproducible overhead measurement requires a
privileged Linux CI job with:

```sh
sysctl kernel.bpf_stats_enabled=1
bpftool prog show
```

Record `run_cnt` and `run_time_ns` per Rauha LSM program and publish
`run_time_ns / run_cnt` per event class.
