# Rauha Observability

Rauha is the telemetry source. It emits structured daemon logs and normalized
evidence events; downstream agents or collectors own cloud tags, pod or
namespace enrichment, Fluent Bit sidecars, S3 archival, and retention policy.

## Config

Rauha reads TOML only. Set `RAUHA_CONFIG` to a TOML file with an optional
`[observability]` table:

```toml
[observability]
format = "auto"        # auto, json, text
level = "info"         # overridden by RUST_LOG
environment = "unknown"

[observability.sampling.keep_ratio]
"pipeline.shed" = 0.25

[observability.sampling.rate_limit_per_second]
"ringbuf.drop" = 1
"pipeline.shed" = 1

[observability.drop]
events = ["shim.__ping__"]

# NOTE: sampling, rate limits, and event drops are parsed but NOT yet wired.
# Configuring any of them logs a startup warning.

# NOTE: sink routing is parsed but NOT yet wired — logs always go to stdout
# regardless of these settings. Setting stdout=false or rotating_file logs a
# startup warning. (Tracked for a follow-up slice.)
[observability.sinks]
stdout = true

[observability.sinks.rotating_file]
path = "/var/log/rauha/rauhad.jsonl"
max_size_bytes = 104857600
max_age_seconds = 604800

[observability.otlp]
endpoint = "http://127.0.0.1:4317"
protocol = "grpc"
timeout_ms = 10000

[observability.otlp.headers]
authorization = "Bearer token"
```

OTLP settings are also parsed but not yet wired; configuring an endpoint logs a
startup warning.

Environment fallbacks:

- `RUST_LOG` controls the tracing filter.
- `RAUHA_LOG_LEVEL` sets the default level when `RUST_LOG` is unset.
- `RAUHA_ENVIRONMENT` overrides `observability.environment`.
- `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`, and
  `OTEL_EXPORTER_OTLP_TIMEOUT` override the matching OTLP fields.

## Standard Keys

Daemon log lines use JSON by default unless `format = "text"` is configured or
`format = "auto"` detects an interactive stdout. `timestamp` is RFC3339 UTC with
millisecond precision. Operational records include:

- `timestamp`
- `log.level`
- `message`
- `service.name`
- `service.version`
- `environment`
- `host.id`
- `host.name`
- `pid`
- `request_id`
- `correlation_id`
- `trace.id`
- `span.id`

Evidence events reuse `rauha-evidence` names and add stable event keys such as
`event.name`, `event.kind`, `event.outcome`, `backend.name`, `trust_level`,
`degraded_reason`, `duration_ms`, `error.code`, and `error.kind`.

## Levels

- `DEBUG`: verbose implementation detail.
- `INFO`: normal lifecycle and request progress.
- `WARN`: recoverable or explicitly admitted degraded behavior. There is no
  rootless/no-enforcement Linux daemon mode.
- `ERROR`: needs operator attention.
- Fatal process exits should be reserved for unrecoverable startup or
  enforcement faults.

## OTLP

The `otlp` cargo feature reserves the intended vendor-neutral export path.
Export is not implemented yet; stdout JSON remains the source of truth.

## Cost Controls

Sampling, rate-limit, and event-drop settings are reserved for noisy records
such as `ringbuf.drop`, `pipeline.shed`, and `shim.__ping__`; they are not yet
applied. Userspace subscriber lag is converted into `pipeline.shed`.
Kernel-side full-ring-buffer drops still require a BPF-side counter before
Rauha can report every `ringbuf.drop` loss without inference.
