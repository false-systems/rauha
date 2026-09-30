use rauha_common::error::Result;
use rauha_common::zone::{PolicyAdmission, PolicyFile, ZonePolicy, ZoneType};

/// Parse a TOML policy string into a ZonePolicy and ZoneType.
pub fn parse_policy(toml_str: &str, base_root: &str) -> Result<(ZoneType, ZonePolicy)> {
    let policy_file: PolicyFile = toml::from_str(toml_str)
        .map_err(|e| rauha_common::error::RauhaError::InvalidPolicy(e.to_string()))?;

    let zone_type = match policy_file.zone.zone_type.as_str() {
        "non-global" => ZoneType::NonGlobal,
        "privileged" => ZoneType::Privileged,
        "global" => ZoneType::Global,
        other => {
            return Err(rauha_common::error::RauhaError::InvalidPolicy(format!(
                "unknown zone type: {other}"
            )))
        }
    };

    let zone_policy = policy_file.to_zone_policy(base_root)?;
    Ok((zone_type, zone_policy))
}

/// Serialize a ZonePolicy back to TOML format for display.
pub fn policy_to_toml(name: &str, zone_type: ZoneType, policy: &ZonePolicy) -> String {
    let type_str = match zone_type {
        ZoneType::Global => "global",
        ZoneType::NonGlobal => "non-global",
        ZoneType::Privileged => "privileged",
    };

    let net_mode = match policy.network.mode {
        rauha_common::zone::NetworkMode::Isolated => "isolated",
        rauha_common::zone::NetworkMode::Bridged => "bridged",
        rauha_common::zone::NetworkMode::Host => "host",
    };

    let admission_mode = match policy.admission {
        PolicyAdmission::Strict => "strict",
        PolicyAdmission::Audit => "audit",
    };

    let caps = policy
        .capabilities
        .allowed
        .iter()
        .map(|c| format!("    \"{c}\""))
        .collect::<Vec<_>>()
        .join(",\n");

    let writable = policy
        .filesystem
        .writable_paths
        .iter()
        .map(|p| format!("\"{p}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let devices = policy
        .devices
        .allowed
        .iter()
        .map(|d| format!("\"{d}\""))
        .collect::<Vec<_>>()
        .join(", ");

    let deny_syscalls = policy
        .syscalls
        .deny
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"[zone]
name = "{name}"
type = "{type_str}"

[admission]
mode = "{admission_mode}"

[capabilities]
allowed = [
{caps}
]

[resources]
cpu_shares = {cpu}
memory_limit = "{mem}"
io_weight = {io}
pids_max = {pids}

[network]
mode = "{net_mode}"
allowed_zones = [{allowed_zones}]
allowed_egress = [{allowed_egress}]
allowed_ingress = [{allowed_ingress}]

[filesystem]
root = "{root}"
shared_layers = {shared}
writable_paths = [{writable}]

[devices]
allowed = [{devices}]

[syscalls]
deny = [{deny_syscalls}]
"#,
        cpu = policy.resources.cpu_shares,
        mem = format_memory_size(policy.resources.memory_limit),
        io = policy.resources.io_weight,
        pids = policy.resources.pids_max,
        allowed_zones = policy
            .network
            .allowed_zones
            .iter()
            .map(|z| format!("\"{z}\""))
            .collect::<Vec<_>>()
            .join(", "),
        allowed_egress = policy
            .network
            .allowed_egress
            .iter()
            .map(|e| format!("\"{e}\""))
            .collect::<Vec<_>>()
            .join(", "),
        allowed_ingress = policy
            .network
            .allowed_ingress
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", "),
        root = policy.filesystem.root,
        shared = policy.filesystem.shared_layers,
    )
}

fn format_memory_size(bytes: u64) -> String {
    if bytes.is_multiple_of(1024 * 1024 * 1024) {
        format!("{}Gi", bytes / (1024 * 1024 * 1024))
    } else if bytes.is_multiple_of(1024 * 1024) {
        format!("{}Mi", bytes / (1024 * 1024))
    } else {
        bytes.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_policy() {
        let toml = r#"
[zone]
name = "production"
type = "non-global"

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = "4Gi"
io_weight = 100
pids_max = 512

[network]
mode = "isolated"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
root = "/var/lib/rauha/zones/production"
shared_layers = true
writable_paths = ["/data", "/tmp"]

[devices]
allowed = ["/dev/null", "/dev/zero", "/dev/urandom"]

[syscalls]
deny = ["mount", "umount2"]
broker = ["openat"]
"#;

        let (zone_type, policy) = parse_policy(toml, "/var/lib/rauha").unwrap();
        assert_eq!(zone_type, ZoneType::NonGlobal);
        assert_eq!(policy.capabilities.allowed.len(), 2);
        assert_eq!(policy.resources.memory_limit, 4 * 1024 * 1024 * 1024);
        assert_eq!(policy.network.allowed_zones, vec!["frontend"]);
        assert_eq!(policy.syscalls.deny, vec!["mount", "umount2"]);
        assert_eq!(policy.syscalls.broker, vec!["openat"]);
    }

    #[test]
    fn missing_capabilities_section_means_allow_none() {
        // Capability policy is an allow-list. Omitted and explicitly empty
        // both mean the workload receives no capabilities.
        let toml = r#"
[zone]
name = "minimal"
type = "non-global"
"#;

        let (_zone_type, policy) = parse_policy(toml, "/var/lib/rauha").unwrap();
        assert!(policy.capabilities.allowed.is_empty());
    }

    #[test]
    fn admission_defaults_to_strict_and_accepts_explicit_audit() {
        let strict = r#"
[zone]
name = "strict"
type = "non-global"
"#;
        let audit = r#"
[zone]
name = "audit"
type = "non-global"

[admission]
mode = "audit"
"#;

        assert_eq!(
            parse_policy(strict, "/var/lib/rauha").unwrap().1.admission,
            PolicyAdmission::Strict
        );
        assert_eq!(
            parse_policy(audit, "/var/lib/rauha").unwrap().1.admission,
            PolicyAdmission::Audit
        );
    }

    #[test]
    fn unknown_top_level_policy_key_is_rejected() {
        let toml = r#"
[zone]
name = "strict"
type = "non-global"

[surprise]
enabled = true
"#;

        assert!(parse_policy(toml, "/var/lib/rauha").is_err());
    }

    #[test]
    fn unknown_nested_policy_key_is_rejected() {
        let toml = r#"
[zone]
name = "strict"
type = "non-global"
extra = "nope"
"#;

        assert!(parse_policy(toml, "/var/lib/rauha").is_err());
    }

    #[test]
    fn unknown_capability_is_rejected() {
        let toml = r#"
[zone]
name = "strict"
type = "non-global"

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_NOT_REAL"]
"#;

        assert!(parse_policy(toml, "/var/lib/rauha").is_err());
    }

    #[test]
    fn capability_short_form_is_accepted() {
        let toml = r#"
[zone]
name = "strict"
type = "non-global"

[capabilities]
allowed = ["net_bind_service"]
"#;

        let (_zone_type, policy) = parse_policy(toml, "/var/lib/rauha").unwrap();
        assert_eq!(policy.capabilities.allowed, vec!["net_bind_service"]);
    }
}
