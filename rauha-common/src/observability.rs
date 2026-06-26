use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ObservabilityConfig {
    #[serde(default = "default_format")]
    pub format: LogFormat,
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_environment")]
    pub environment: String,
    #[serde(default)]
    pub sampling: SamplingConfig,
    #[serde(default)]
    pub drop: DropConfig,
    #[serde(default)]
    pub sinks: SinksConfig,
    #[serde(default)]
    pub otlp: OtlpConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
            level: default_level(),
            environment: default_environment(),
            sampling: SamplingConfig::default(),
            drop: DropConfig::default(),
            sinks: SinksConfig::default(),
            otlp: OtlpConfig::default(),
        }
    }
}

impl ObservabilityConfig {
    pub fn from_env_or_default() -> Result<Self, ObservabilityConfigError> {
        let Some(path) = std::env::var_os("RAUHA_CONFIG") else {
            return Ok(Self::from_env_overrides(Self::default()));
        };
        let path = PathBuf::from(path);
        let text =
            std::fs::read_to_string(&path).map_err(|source| ObservabilityConfigError::Read {
                path: path.clone(),
                source,
            })?;
        let file: RauhaConfigFile =
            toml::from_str(&text).map_err(|source| ObservabilityConfigError::Parse {
                path: path.clone(),
                source,
            })?;
        Ok(Self::from_env_overrides(
            file.observability.unwrap_or_default(),
        ))
    }

    fn from_env_overrides(mut config: Self) -> Self {
        if let Ok(environment) = std::env::var("RAUHA_ENVIRONMENT") {
            config.environment = environment;
        }
        if let Ok(level) = std::env::var("RAUHA_LOG_LEVEL") {
            config.level = level;
        }
        if let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") {
            config.otlp.endpoint = Some(endpoint);
        }
        if let Ok(protocol) = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL") {
            config.otlp.protocol = protocol;
        }
        if let Ok(timeout) = std::env::var("OTEL_EXPORTER_OTLP_TIMEOUT") {
            if let Ok(ms) = timeout.parse::<u64>() {
                config.otlp.timeout_ms = ms;
            }
        }
        config
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Text,
    Auto,
}

fn default_format() -> LogFormat {
    LogFormat::Auto
}

fn default_level() -> String {
    "info".into()
}

fn default_environment() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct SamplingConfig {
    #[serde(default)]
    pub keep_ratio: BTreeMap<String, f64>,
    #[serde(default)]
    pub rate_limit_per_second: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct DropConfig {
    #[serde(default = "default_drop_events")]
    pub events: Vec<String>,
}

impl Default for DropConfig {
    fn default() -> Self {
        Self {
            events: default_drop_events(),
        }
    }
}

fn default_drop_events() -> Vec<String> {
    vec!["shim.__ping__".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct SinksConfig {
    #[serde(default = "default_true")]
    pub stdout: bool,
    pub rotating_file: Option<RotatingFileSinkConfig>,
}

impl Default for SinksConfig {
    fn default() -> Self {
        Self {
            stdout: true,
            rotating_file: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct RotatingFileSinkConfig {
    pub path: PathBuf,
    pub max_size_bytes: u64,
    pub max_age_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct OtlpConfig {
    pub endpoint: Option<String>,
    #[serde(default = "default_otlp_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_otlp_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            protocol: default_otlp_protocol(),
            headers: BTreeMap::new(),
            timeout_ms: default_otlp_timeout_ms(),
        }
    }
}

impl OtlpConfig {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

fn default_true() -> bool {
    true
}

fn default_otlp_protocol() -> String {
    "grpc".into()
}

fn default_otlp_timeout_ms() -> u64 {
    10_000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RauhaConfigFile {
    pub observability: Option<ObservabilityConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum ObservabilityConfigError {
    #[error("failed to read Rauha config at {path}: {source}; hint: set RAUHA_CONFIG to a readable TOML file or unset it to use defaults")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse Rauha config at {path}: {source}; hint: use TOML with an [observability] table")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_observability_is_json_auto_low_noise() {
        let config = ObservabilityConfig::default();
        assert_eq!(config.format, LogFormat::Auto);
        assert_eq!(config.environment, "unknown");
        assert_eq!(config.drop.events, vec!["shim.__ping__"]);
    }

    #[test]
    fn parses_observability_table() {
        let file: RauhaConfigFile = toml::from_str(
            r#"
            [observability]
            format = "text"
            level = "debug"
            environment = "dev"

            [observability.sampling.keep_ratio]
            "pipeline.shed" = 0.25

            [observability.otlp]
            endpoint = "http://127.0.0.1:4317"
            timeout_ms = 500
            "#,
        )
        .unwrap();
        let config = file.observability.unwrap();
        assert_eq!(config.format, LogFormat::Text);
        assert_eq!(config.level, "debug");
        assert_eq!(config.environment, "dev");
        assert_eq!(config.otlp.timeout(), Duration::from_millis(500));
    }
}
