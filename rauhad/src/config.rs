//! Daemon configuration (`rauha.toml`).
//!
//! Never hardcode: every value that could differ between hosts — paths,
//! addresses, subnets, DNS, binary locations, capacities — is config with a
//! default, from this one schema. Exactly two kinds of constants are exempt:
//! security invariants (enrollment order, fail-closed behavior) and named
//! physical constants (see CLAUDE.md).
//!
//! Resolution order: `RAUHA_CONFIG` env var, then `{root}/rauha.toml`, then
//! defaults. A missing file is not an error. `RAUHA_ROOT` stays an env var —
//! the config file is discovered *via* the root, so it cannot define it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rauha_common::error::{RauhaError, Result};

/// Daemon configuration schema. Defaults are the documented behavior; the
/// file exists to override them.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub executor: ExecutorConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    #[serde(default)]
    pub evidence: EvidenceConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub broker: BrokerConfig,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// gRPC listen address.
    #[serde(default = "default_server_addr")]
    pub addr: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: default_server_addr(),
        }
    }
}

fn default_server_addr() -> String {
    "[::1]:9876".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Zone bridge subnet, IPv4 CIDR. Zone IPs and the gateway (offset 1)
    /// are allocated from it.
    #[serde(default = "default_subnet")]
    pub subnet: String,
    /// Bridge interface name the zones attach to.
    #[serde(default = "default_bridge")]
    pub bridge: String,
    /// Last-resort nameservers when the host resolv.conf yields nothing
    /// usable (all localhost stubs). The default derives from the host
    /// first; these are only a fallback.
    #[serde(default = "default_dns_fallback")]
    pub dns_fallback: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            subnet: default_subnet(),
            bridge: default_bridge(),
            dns_fallback: default_dns_fallback(),
        }
    }
}

fn default_subnet() -> String {
    "10.89.0.0/16".into()
}

fn default_bridge() -> String {
    "rauha0".into()
}

fn default_dns_fallback() -> Vec<String> {
    vec!["1.1.1.1".into(), "8.8.8.8".into()]
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorConfig {
    /// crun binary: "auto" searches PATH and known locations, or an
    /// absolute path.
    #[serde(default = "default_crun")]
    pub crun: String,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            crun: default_crun(),
        }
    }
}

fn default_crun() -> String {
    "auto".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsConfig {
    /// Runtime dir for sockets and container logs (the shim receives it
    /// via `RAUHA_RUN_DIR`).
    #[serde(default = "default_run_dir")]
    pub run_dir: String,
    /// Named network namespaces live here (`ip netns` convention).
    #[serde(default = "default_netns_dir")]
    pub netns_dir: String,
    /// eBPF map/program pin directory.
    #[serde(default = "default_bpf_pin_dir")]
    pub bpf_pin_dir: String,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            run_dir: default_run_dir(),
            netns_dir: default_netns_dir(),
            bpf_pin_dir: default_bpf_pin_dir(),
        }
    }
}

fn default_run_dir() -> String {
    "/run/rauha".into()
}

fn default_netns_dir() -> String {
    "/var/run/netns".into()
}

fn default_bpf_pin_dir() -> String {
    "/sys/fs/bpf/rauha".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    /// Per-stream cap for captured sandbox stdout/stderr.
    #[serde(default = "default_sandbox_log_max_bytes")]
    pub sandbox_log_max_bytes: usize,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            sandbox_log_max_bytes: default_sandbox_log_max_bytes(),
        }
    }
}

fn default_sandbox_log_max_bytes() -> usize {
    1024 * 1024
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum accepted policy TOML size (guards parse-time memory).
    #[serde(default = "default_policy_max_bytes")]
    pub policy_max_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            policy_max_bytes: default_policy_max_bytes(),
        }
    }
}

fn default_policy_max_bytes() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Writable paths that are always considered safe (virtual/ephemeral
    /// filesystems). Overriding this widens what `filesystem.writable_paths`
    /// admits without Landlock backing — strict admission still reports it
    /// in `zone verify` degradations.
    #[serde(default = "default_safe_writable_roots")]
    pub safe_writable_roots: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            safe_writable_roots: default_safe_writable_roots(),
        }
    }
}

fn default_safe_writable_roots() -> Vec<String> {
    ["/proc", "/sys", "/dev", "/run"]
        .into_iter()
        .map(Into::into)
        .collect()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    /// Task-pin cache capacity for the shim's seccomp broker, passed to
    /// the shim as `RAUHA_BROKER_CACHE_MAX`. One entry per workload thread
    /// that makes brokered calls; `0` disables caching (every judgment
    /// takes the cold path). The bound keeps a zone from growing the
    /// broker's memory by spawning threads; the shim additionally clamps
    /// it to the fd budget (three fds per pin).
    #[serde(default = "default_broker_cache_max_tasks")]
    pub cache_max_tasks: usize,
    /// Judge threads in the shim's seccomp broker, passed as
    /// `RAUHA_BROKER_JUDGE_THREADS`. The kernel hands each pending
    /// notification to exactly one concurrent RECV, so this is the
    /// broker's judgment parallelism; `1` is the serial loop.
    #[serde(default = "default_broker_judge_threads")]
    pub judge_threads: usize,
    /// How long the broker waits for the runtime's seccomp fd hand-off
    /// before failing cleanly, in milliseconds, passed as
    /// `RAUHA_BROKER_HANDOFF_TIMEOUT_MS`.
    #[serde(default = "default_broker_handoff_timeout_ms")]
    pub handoff_timeout_ms: u64,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            cache_max_tasks: default_broker_cache_max_tasks(),
            judge_threads: default_broker_judge_threads(),
            handoff_timeout_ms: default_broker_handoff_timeout_ms(),
        }
    }
}

fn default_broker_cache_max_tasks() -> usize {
    512
}

fn default_broker_judge_threads() -> usize {
    4
}

fn default_broker_handoff_timeout_ms() -> u64 {
    30_000
}

impl DaemonConfig {
    /// Load configuration. Resolution order: `RAUHA_CONFIG`, then
    /// `{root}/rauha.toml`, then defaults. A missing file is not an error;
    /// an unreadable or malformed one is.
    pub fn load(root: &str) -> Result<Self> {
        let path = Self::config_path(root);
        match (&path, std::fs::read_to_string(&path)) {
            (_, Ok(content)) => {
                let config: DaemonConfig = toml::from_str(&content).map_err(|e| {
                    RauhaError::InvalidInput(format!("invalid config file {}: {e}", path.display()))
                })?;
                tracing::info!(path = %path.display(), "loaded daemon config");
                config.validate()?;
                Ok(config)
            }
            (p, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::env::var("RAUHA_CONFIG").is_ok() {
                    // An explicit RAUHA_CONFIG that does not exist is an error:
                    // silently falling back to defaults would hide a typo.
                    return Err(RauhaError::InvalidInput(format!(
                        "RAUHA_CONFIG points to {}, which does not exist",
                        p.display()
                    )));
                }
                Ok(Self::default())
            }
            (p, Err(e)) => Err(RauhaError::InvalidInput(format!(
                "cannot read config file {}: {e}",
                p.display()
            ))),
        }
    }

    fn config_path(root: &str) -> PathBuf {
        if let Ok(explicit) = std::env::var("RAUHA_CONFIG") {
            return PathBuf::from(explicit);
        }
        Path::new(root).join("rauha.toml")
    }

    /// Reject values that cannot work before anything depends on them.
    fn validate(&self) -> Result<()> {
        let _: SocketAddr = self.server.addr.parse().map_err(|_| {
            RauhaError::InvalidInput(format!(
                "server.addr {:?} is not a valid socket address",
                self.server.addr
            ))
        })?;
        let _ = self.subnet_octets()?;
        for ns in &self.network.dns_fallback {
            ns.parse::<std::net::IpAddr>().map_err(|_| {
                RauhaError::InvalidInput(format!(
                    "network.dns_fallback entry {ns:?} is not an IP address"
                ))
            })?;
        }
        if self.network.bridge.is_empty() {
            return Err(RauhaError::InvalidInput("network.bridge is empty".into()));
        }
        if self.executor.crun != "auto" && !Path::new(&self.executor.crun).is_absolute() {
            return Err(RauhaError::InvalidInput(format!(
                "executor.crun must be \"auto\" or an absolute path, got {:?}",
                self.executor.crun
            )));
        }
        if self.evidence.sandbox_log_max_bytes == 0 || self.limits.policy_max_bytes == 0 {
            return Err(RauhaError::InvalidInput(
                "evidence.sandbox_log_max_bytes and limits.policy_max_bytes must be > 0".into(),
            ));
        }
        if self.broker.cache_max_tasks > (1 << 20) {
            return Err(RauhaError::InvalidInput(format!(
                "broker.cache_max_tasks {} is unreasonable — one cache entry is held per \
                 workload thread making brokered calls (max {})",
                self.broker.cache_max_tasks,
                1 << 20
            )));
        }
        if self.broker.judge_threads == 0 || self.broker.judge_threads > 64 {
            return Err(RauhaError::InvalidInput(format!(
                "broker.judge_threads must be between 1 (serial) and 64, got {}",
                self.broker.judge_threads
            )));
        }
        if !(1_000..=300_000).contains(&self.broker.handoff_timeout_ms) {
            return Err(RauhaError::InvalidInput(format!(
                "broker.handoff_timeout_ms must be between 1000 and 300000, got {}",
                self.broker.handoff_timeout_ms
            )));
        }
        Ok(())
    }

    /// Parse `network.subnet` into `(octets, prefix_len)`.
    pub fn subnet_octets(&self) -> Result<([u8; 4], u8)> {
        parse_cidr(&self.network.subnet)
    }
}

/// Parse an IPv4 CIDR like `10.89.0.0/16`.
pub fn parse_cidr(cidr: &str) -> Result<([u8; 4], u8)> {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return Err(RauhaError::InvalidInput(format!(
            "subnet {cidr:?} is not a CIDR (expected e.g. \"10.89.0.0/16\")"
        )));
    };
    let octets: [u8; 4] = addr
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| RauhaError::InvalidInput(format!("subnet address {addr:?} is not IPv4")))?
        .octets();
    let prefix: u8 = prefix.parse().map_err(|_| {
        RauhaError::InvalidInput(format!("subnet prefix {prefix:?} is not a number"))
    })?;
    if prefix > 32 {
        return Err(RauhaError::InvalidInput(format!(
            "subnet prefix /{prefix} is invalid (max /32)"
        )));
    }
    if prefix < 16 {
        return Err(RauhaError::InvalidInput(format!(
            "subnet /{prefix} is larger than /16 — refusing: a zone network that big \
             exhausts the address space Rauha is allowed to manage"
        )));
    }
    // The allocator reserves offset 0 (network address) and offset 1
    // (gateway); /31 and /32 leave zero (or negative) room for zones and the
    // gateway would fall outside the subnet. Reject at config time, not at
    // the first zone create.
    if prefix > 30 {
        return Err(RauhaError::InvalidInput(format!(
            "subnet /{prefix} is too small — /30 is the minimum that fits a gateway \
             plus at least one zone (got {cidr})"
        )));
    }
    // Host bits must be zero (network address, not a host address).
    let bits = u32::from_be_bytes(octets);
    let host_mask = if prefix == 32 { 0 } else { u32::MAX >> prefix };
    if bits & host_mask != 0 {
        return Err(RauhaError::InvalidInput(format!(
            "subnet {cidr} has host bits set (expected a network address like 10.89.0.0/16)"
        )));
    }
    Ok((octets, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_parse_and_validate() {
        let c = DaemonConfig::default();
        c.validate().unwrap();
        assert_eq!(c.server.addr, "[::1]:9876");
        assert_eq!(c.network.subnet, "10.89.0.0/16");
        assert_eq!(c.network.bridge, "rauha0");
        assert_eq!(c.executor.crun, "auto");
        assert_eq!(c.paths.run_dir, "/run/rauha");
        assert_eq!(
            c.policy.safe_writable_roots,
            ["/proc", "/sys", "/dev", "/run"]
        );
        assert_eq!(c.evidence.sandbox_log_max_bytes, 1024 * 1024);
        assert_eq!(c.limits.policy_max_bytes, 64 * 1024);
        assert_eq!(c.broker.cache_max_tasks, 512);
        assert_eq!(c.broker.judge_threads, 4);
        assert_eq!(c.broker.handoff_timeout_ms, 30_000);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let _guard = crate::testutil::EnvGuard::unset("RAUHA_CONFIG");
        let c = DaemonConfig::load("/nonexistent-rauha-root").unwrap();
        assert_eq!(c.network.subnet, "10.89.0.0/16");
    }

    #[test]
    fn explicit_missing_config_is_an_error() {
        let guard = crate::testutil::EnvGuard::set("RAUHA_CONFIG", "/nonexistent/rauha.toml");
        let err = DaemonConfig::load("/nonexistent-rauha-root").unwrap_err();
        assert!(err.to_string().contains("RAUHA_CONFIG"));
        drop(guard);
    }

    #[test]
    fn file_overrides_defaults() {
        let _guard = crate::testutil::EnvGuard::unset("RAUHA_CONFIG");
        let dir = std::env::temp_dir().join(format!("rauha-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rauha.toml"),
            "[network]\nsubnet = \"172.30.0.0/24\"\n",
        )
        .unwrap();
        let c = DaemonConfig::load(dir.to_str().unwrap()).unwrap();
        assert_eq!(c.network.subnet, "172.30.0.0/24");
        assert_eq!(c.server.addr, "[::1]:9876"); // untouched section keeps default
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = toml::from_str::<DaemonConfig>("[netwrk]\nsubnet = \"1.2.3.0/24\"\n");
        assert!(err.is_err());
    }

    #[test]
    fn cidr_parsing() {
        assert_eq!(parse_cidr("10.89.0.0/16").unwrap(), ([10, 89, 0, 0], 16));
        assert!(parse_cidr("10.89.0.1/16").is_err()); // host bits set
        assert!(parse_cidr("10.89.0.0").is_err()); // no prefix
        assert!(parse_cidr("10.89.0.0/8").is_err()); // larger than /16
        assert!(parse_cidr("10.89.0.0/40").is_err()); // impossible prefix
        assert!(parse_cidr("10.89.0.0/31").is_err()); // no room for gateway + zones
        assert!(parse_cidr("10.89.0.0/32").is_err());
        assert!(parse_cidr("not-an-ip/16").is_err());
    }

    #[test]
    fn validation_rejects_bad_values() {
        let mut c = DaemonConfig::default();
        c.server.addr = "not-an-addr".into();
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.executor.crun = "crun".into(); // relative
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.limits.policy_max_bytes = 0;
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.network.dns_fallback = vec!["not-an-ip".into()];
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.broker.cache_max_tasks = 2 << 21;
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.broker.judge_threads = 0;
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.broker.judge_threads = 65;
        assert!(c.validate().is_err());

        let mut c = DaemonConfig::default();
        c.broker.handoff_timeout_ms = 10;
        assert!(c.validate().is_err());
    }
}
