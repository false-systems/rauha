//! Daemon logging setup.
//!
//! Rauha is the telemetry source: it emits one structured JSON object per log
//! line to stdout, with standardized resource keys (`service.name`, `host.id`,
//! …) present on EVERY line as top-level fields — independent of which tokio
//! task produced the event. A `tracing` span guard cannot do this (it does not
//! cross task boundaries and nests its fields under `span`), so we format events
//! ourselves in a small `Layer` and inject the constant resource fields plus any
//! active span scope (request/correlation/trace/span ids) flat into the object.

use std::io::Write;

use rauha_common::observability::{LogFormat, ObservabilityConfig};
use serde_json::{json, Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber from observability config.
pub fn init(config: &ObservabilityConfig) -> anyhow::Result<()> {
    // RUST_LOG wins; otherwise default to the configured level for rauhad AND
    // the evidence target (evidence events are emitted on the `rauha_evidence`
    // target — without this they would be filtered out by default).
    let lvl = &config.level;
    let default_directives = format!("rauhad={lvl},rauha_evidence={lvl},rauha_shim={lvl}");
    let filter =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(&default_directives))?;

    let format = match config.format {
        LogFormat::Json => LogFormat::Json,
        LogFormat::Text => LogFormat::Text,
        LogFormat::Auto if stdout_is_tty() => LogFormat::Text,
        LogFormat::Auto => LogFormat::Json,
    };

    match format {
        LogFormat::Text => {
            // Human dev output — unchanged from the original fmt subscriber.
            tracing_subscriber::fmt()
                .with_timer(ChronoUtc::rfc_3339())
                .with_env_filter(filter)
                .with_writer(std::io::stdout)
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(JsonLogLayer::new(resource_fields(config)))
                .init();
        }
    }
    Ok(())
}

/// Constant resource attributes attached to every log line as top-level keys.
fn resource_fields(config: &ObservabilityConfig) -> Vec<(&'static str, Value)> {
    vec![
        ("service.name", json!("rauhad")),
        ("service.version", json!(env!("CARGO_PKG_VERSION"))),
        ("environment", json!(config.environment)),
        ("host.id", json!(host_id())),
        ("host.name", json!(host_name())),
        ("pid", json!(std::process::id())),
    ]
}

/// A `tracing` layer that writes one flat JSON object per event to stdout.
struct JsonLogLayer {
    resource: Vec<(&'static str, Value)>,
}

impl JsonLogLayer {
    fn new(resource: Vec<(&'static str, Value)>) -> Self {
        Self { resource }
    }
}

/// Structured span fields, captured at span creation and merged into every
/// event emitted within that span's scope.
struct SpanFields(Map<String, Value>);

impl<S> Layer<S> for JsonLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::Id,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut fields = Map::new();
            attrs.record(&mut JsonVisitor::new(&mut fields));
            span.extensions_mut().insert(SpanFields(fields));
        }
    }

    fn on_record(&self, id: &tracing::Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(SpanFields(fields)) = ext.get_mut::<SpanFields>() {
                values.record(&mut JsonVisitor::new(fields));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut map = Map::new();

        let meta = event.metadata();
        map.insert("timestamp".into(), json!(now_rfc3339()));
        map.insert("level".into(), json!(meta.level().as_str()));
        map.insert("target".into(), json!(meta.target()));

        // Constant resource attributes (top-level, every line).
        for (key, value) in &self.resource {
            map.insert((*key).to_string(), value.clone());
        }

        // Active span scope (root → current): request/correlation/trace/span ids.
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(SpanFields(fields)) = span.extensions().get::<SpanFields>() {
                    for (key, value) in fields {
                        map.insert(key.clone(), value.clone());
                    }
                }
            }
        }

        // Event's own fields. An empty-string field does not override a
        // non-empty resource/span value already present — this lets evidence
        // events (which emit empty `correlation_id`/`trace.id` when unset)
        // inherit the active request's ids from span scope.
        event.record(&mut JsonVisitor::with_skip_empty(&mut map));

        if let Ok(line) = serde_json::to_string(&Value::Object(map)) {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
        }
    }
}

struct JsonVisitor<'a> {
    map: &'a mut Map<String, Value>,
    skip_empty: bool,
}

impl<'a> JsonVisitor<'a> {
    fn new(map: &'a mut Map<String, Value>) -> Self {
        Self {
            map,
            skip_empty: false,
        }
    }

    fn with_skip_empty(map: &'a mut Map<String, Value>) -> Self {
        Self {
            map,
            skip_empty: true,
        }
    }

    fn put(&mut self, key: &str, value: Value) {
        if self.skip_empty {
            if let Value::String(s) = &value {
                if s.is_empty() && self.map.contains_key(key) {
                    return;
                }
            }
        }
        self.map.insert(key.to_string(), value);
    }
}

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field.name(), Value::String(value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field.name(), Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field.name(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field.name(), Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        // The message format string is recorded here under the "message" field;
        // Debug of fmt::Arguments / DisplayValue yields the plain string.
        self.put(field.name(), Value::String(format!("{value:?}")));
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn host_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(host_name)
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_event_field_does_not_override_existing() {
        let mut map = Map::new();
        map.insert("correlation_id".into(), json!("abc"));
        let mut v = JsonVisitor::with_skip_empty(&mut map);
        v.put("correlation_id", json!(""));
        assert_eq!(map.get("correlation_id"), Some(&json!("abc")));
    }

    #[test]
    fn non_empty_event_field_overrides() {
        let mut map = Map::new();
        map.insert("correlation_id".into(), json!("abc"));
        let mut v = JsonVisitor::with_skip_empty(&mut map);
        v.put("correlation_id", json!("xyz"));
        assert_eq!(map.get("correlation_id"), Some(&json!("xyz")));
    }
}
