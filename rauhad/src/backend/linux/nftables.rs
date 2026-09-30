//! nftables rule management for zone networking.
//!
//! Handles two concerns:
//! 1. NAT masquerade — zones can reach the internet via the host
//! 2. Inet filtering — controls routed egress and blocks zone-to-host traffic
//! 3. Bridge filtering — controls same-subnet cross-zone traffic at layer 2
//!
//! nftables is the primary network enforcement layer. eBPF stays focused on
//! syscall policy (file_open, ptrace, etc). This separation keeps each
//! subsystem doing what it does best.

use std::io::Write;
use std::process::{Command, Stdio};

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{NetworkEndpoint, NetworkMode, NetworkPolicy};

const TABLE_NAME: &str = "rauha";
const TABLE_FAMILY: &str = "inet";
const BRIDGE_FAMILY: &str = "bridge";

/// Ensure the rauha nftables table and NAT masquerade chain exist.
/// Called once during LinuxBackend::new(). The bridge name comes from
/// daemon config (default `rauha0`).
pub fn ensure_nat(subnet_cidr: &str, bridge: &str) -> Result<()> {
    // The inet table (NAT + L3 forward filtering) is required: without it
    // zones have no masqueraded connectivity at all — fail closed, with a
    // message that names what the kernel is missing. nft -f applies it as
    // one kernel transaction, so a failure leaves the previous table
    // intact.
    run_nft_script(&inet_ruleset(
        subnet_cidr,
        bridge,
        table_exists(TABLE_FAMILY)?,
    ))
    .map_err(|error| {
        RauhaError::BackendError(format!(
            "cannot create the inet nftables table (NAT + forward filtering): {error} — \
             the kernel needs nf_tables and nf_nat; this is a hard requirement"
        ))
    })?;

    // The bridge table is the cross-zone L2 boundary. It runs in its own
    // transaction: a kernel without nf_tables_bridge degrades explicitly
    // instead of refusing the daemon — the existing per-zone admission
    // model governs (strict zones refuse network policy without bridge
    // filtering; audit zones record a network:nftables degradation, and
    // `zone verify` reports it).
    // A failed table_exists query must not kill the optional path: assume
    // the table is absent and let the script attempt speak for itself.
    let bridge_exists = table_exists(BRIDGE_FAMILY).unwrap_or(false);
    if let Err(error) = run_nft_script(&bridge_ruleset(bridge_exists)) {
        tracing::warn!(
            %error,
            "bridge nftables table unavailable (kernel without nf_tables_bridge?) — \
             cross-zone L2 filtering degrades: strict zones will refuse network \
             admission, audit zones record network:nftables"
        );
    }

    tracing::info!(
        subnet = subnet_cidr,
        "nftables NAT + forward chains created"
    );
    Ok(())
}

/// The inet half of the base ruleset: NAT masquerade plus the L3 forward
/// filter (default drop) and the host-input drop. Applied as one kernel
/// transaction. Required — see `ensure_nat`.
fn inet_ruleset(subnet_cidr: &str, bridge: &str, replace: bool) -> String {
    format!(
        "{delete_inet}add table inet rauha\n\
         add chain inet rauha postrouting {{ type nat hook postrouting priority srcnat; }}\n\
         add rule inet rauha postrouting ip saddr {subnet_cidr} oifname != \"{bridge}\" masquerade\n\
         add chain inet rauha forward {{ type filter hook forward priority filter; policy drop; }}\n\
         add rule inet rauha forward ct state established,related accept\n\
         add rule inet rauha forward iifname \"{bridge}\" accept\n\
         add rule inet rauha forward oifname \"{bridge}\" accept\n\
         add chain inet rauha input {{ type filter hook input priority filter; policy accept; }}\n\
         add rule inet rauha input ct state established,related accept\n\
         add rule inet rauha input iifname \"{bridge}\" drop\n",
        delete_inet = if replace { "delete table inet rauha\n" } else { "" },
    )
}

/// The bridge half: every base chain is `policy drop`, so a zone only has
/// connectivity through the per-zone jump rules installed by
/// `apply_zone_rules` — a zone whose rules failed to apply, or whose rules
/// are mid-replacement, is cut off rather than left open. The inet forward
/// `iifname "rauha0"` accept is only reachable for frames that already
/// passed a bridge input chain. Optional — a kernel without
/// nf_tables_bridge degrades (see `ensure_nat`).
fn bridge_ruleset(replace: bool) -> String {
    format!(
        "{delete_bridge}add table bridge rauha\n\
         add chain bridge rauha forward {{ type filter hook forward priority filter; policy drop; }}\n\
         add chain bridge rauha input {{ type filter hook input priority filter; policy drop; }}\n\
         add chain bridge rauha output {{ type filter hook output priority filter; policy drop; }}\n",
        delete_bridge = if replace { "delete table bridge rauha\n" } else { "" },
    )
}

/// Remove the entire rauha nftables table.
/// Called during daemon shutdown.
pub fn cleanup_nat() -> Result<()> {
    if table_exists(TABLE_FAMILY)? {
        run_nft(&["delete", "table", TABLE_FAMILY, TABLE_NAME])?;
    }
    if table_exists(BRIDGE_FAMILY)? {
        run_nft(&["delete", "table", BRIDGE_FAMILY, TABLE_NAME])?;
    }
    tracing::info!("nftables tables removed");
    Ok(())
}

/// Apply nftables forward rules for a zone based on its NetworkPolicy.
///
/// Zone names are validated by `validate_zone_name` (alphanumeric + hyphen,
/// max 128 chars) which produces safe nftables chain identifiers.
pub fn apply_zone_rules(zone_name: &str, veth_name: &str, policy: &NetworkPolicy) -> Result<()> {
    let bridge_rules = bridge_zone_chain_rules(veth_name, policy);
    let bridge_input_rules = bridge_input_chain_rules(policy)?;
    let bridge_output_rules = bridge_output_chain_rules(policy)?;

    // Removal is fail-closed: the base chains deny traffic until the complete
    // replacement is accepted as one nft transaction.
    let _ = remove_zone_rules(zone_name);

    if policy.mode != NetworkMode::Host {
        let chain_name = zone_chain_name(zone_name);
        let input_chain_name = zone_input_chain_name(zone_name);
        let output_chain_name = zone_output_chain_name(zone_name);
        let mut script = format!(
            "add chain bridge rauha {chain_name}\n\
             add chain bridge rauha {input_chain_name}\n\
             add chain bridge rauha {output_chain_name}\n"
        );
        for rule in bridge_rules {
            script.push_str(&format!("add rule bridge rauha {chain_name} {rule}\n"));
        }
        for rule in bridge_input_rules {
            script.push_str(&format!(
                "add rule bridge rauha {input_chain_name} {rule}\n"
            ));
        }
        for rule in bridge_output_rules {
            script.push_str(&format!(
                "add rule bridge rauha {output_chain_name} {rule}\n"
            ));
        }
        script.push_str(&format!(
            "add rule bridge rauha forward iifname \"{veth_name}\" jump {chain_name}\n\
             add rule bridge rauha forward oifname \"{veth_name}\" jump {chain_name}\n\
             add rule bridge rauha input iifname \"{veth_name}\" jump {input_chain_name}\n\
             add rule bridge rauha output oifname \"{veth_name}\" jump {output_chain_name}\n"
        ));
        run_nft_script(&script)?;
    }

    tracing::info!(zone = zone_name, mode = ?policy.mode, "nftables rules applied");
    Ok(())
}

/// Remove all nftables rules for a zone.
pub fn remove_zone_rules(zone_name: &str) -> Result<()> {
    let chain_name = zone_chain_name(zone_name);
    let input_chain_name = zone_input_chain_name(zone_name);
    let output_chain_name = zone_output_chain_name(zone_name);

    let _ = remove_chain_jumps(BRIDGE_FAMILY, "forward", &chain_name);
    let _ = remove_chain_jumps(BRIDGE_FAMILY, "input", &input_chain_name);
    let _ = remove_chain_jumps(BRIDGE_FAMILY, "output", &output_chain_name);
    for (family, chain) in [
        (BRIDGE_FAMILY, chain_name.as_str()),
        (BRIDGE_FAMILY, input_chain_name.as_str()),
        (BRIDGE_FAMILY, output_chain_name.as_str()),
    ] {
        let _ = run_nft(&["flush", "chain", family, TABLE_NAME, chain]);
        let _ = run_nft(&["delete", "chain", family, TABLE_NAME, chain]);
    }

    Ok(())
}

pub fn zone_rules_exist(zone_name: &str, veth_name: &str, policy: &NetworkPolicy) -> bool {
    if policy.mode == NetworkMode::Host {
        return true;
    }
    let chain_name = zone_chain_name(zone_name);
    let input_chain_name = zone_input_chain_name(zone_name);
    let output_chain_name = zone_output_chain_name(zone_name);
    let bridge_chain = Command::new("nft")
        .args(["list", "chain", BRIDGE_FAMILY, TABLE_NAME, &chain_name])
        .output();
    let bridge_input_chain = Command::new("nft")
        .args([
            "list",
            "chain",
            BRIDGE_FAMILY,
            TABLE_NAME,
            &input_chain_name,
        ])
        .output();
    let bridge_output_chain = Command::new("nft")
        .args([
            "list",
            "chain",
            BRIDGE_FAMILY,
            TABLE_NAME,
            &output_chain_name,
        ])
        .output();
    let bridge_forward = Command::new("nft")
        .args(["list", "chain", BRIDGE_FAMILY, TABLE_NAME, "forward"])
        .output();
    let bridge_input = Command::new("nft")
        .args(["list", "chain", BRIDGE_FAMILY, TABLE_NAME, "input"])
        .output();
    let bridge_output = Command::new("nft")
        .args(["list", "chain", BRIDGE_FAMILY, TABLE_NAME, "output"])
        .output();
    bridge_chain.is_ok_and(|output| {
        output.status.success()
            && nft_chain_rules(&output.stdout, &chain_name)
                == bridge_zone_chain_rules(veth_name, policy)
    }) && bridge_input_chain.is_ok_and(|output| {
        output.status.success()
            && bridge_input_chain_rules(policy)
                .is_ok_and(|rules| nft_chain_rules(&output.stdout, &input_chain_name) == rules)
    }) && bridge_output_chain.is_ok_and(|output| {
        output.status.success()
            && bridge_output_chain_rules(policy)
                .is_ok_and(|rules| nft_chain_rules(&output.stdout, &output_chain_name) == rules)
    }) && bridge_forward.is_ok_and(|output| forward_has_jumps(&output, veth_name, &chain_name))
        && bridge_input
            .is_ok_and(|output| chain_has_jump(&output, "iifname", veth_name, &input_chain_name))
        && bridge_output
            .is_ok_and(|output| chain_has_jump(&output, "oifname", veth_name, &output_chain_name))
}

fn forward_has_jumps(output: &std::process::Output, veth_name: &str, chain_name: &str) -> bool {
    if !output.status.success() {
        return false;
    }
    let rules = String::from_utf8_lossy(&output.stdout);
    rules.contains(&format!("iifname \"{veth_name}\" jump {chain_name}"))
        && rules.contains(&format!("oifname \"{veth_name}\" jump {chain_name}"))
}

fn chain_has_jump(
    output: &std::process::Output,
    interface_match: &str,
    veth_name: &str,
    chain_name: &str,
) -> bool {
    output.status.success()
        && String::from_utf8_lossy(&output.stdout).contains(&format!(
            "{interface_match} \"{veth_name}\" jump {chain_name}"
        ))
}

fn bridge_input_chain_rules(policy: &NetworkPolicy) -> Result<Vec<String>> {
    if policy.mode != NetworkMode::Bridged {
        return Ok(vec!["drop".into()]);
    }

    let mut rules = vec![
        "ether type arp accept".into(),
        "meta l4proto ipv6-icmp accept".into(),
        "ct state established,related accept".into(),
    ];
    rules.extend(endpoint_rules("daddr", &policy.allowed_egress)?);
    rules.push("drop".into());
    Ok(rules)
}

fn bridge_output_chain_rules(policy: &NetworkPolicy) -> Result<Vec<String>> {
    if policy.mode != NetworkMode::Bridged {
        return Ok(vec!["drop".into()]);
    }

    let mut rules = vec![
        "ether type arp accept".into(),
        "meta l4proto ipv6-icmp accept".into(),
        "ct state established,related accept".into(),
    ];
    rules.extend(endpoint_rules("saddr", &policy.allowed_ingress)?);
    rules.push("drop".into());
    Ok(rules)
}

fn bridge_zone_chain_rules(veth_name: &str, policy: &NetworkPolicy) -> Vec<String> {
    if policy.mode != NetworkMode::Bridged {
        return vec!["return".into()];
    }

    let mut rules = Vec::new();
    for zone in &policy.allowed_zones {
        let peer = super::network::veth_host_name_for(zone);
        rules.push(format!(
            "iifname \"{veth_name}\" oifname \"{}\" accept",
            peer
        ));
        rules.push(format!("iifname \"{peer}\" oifname \"{veth_name}\" accept"));
    }
    rules.push("return".into());
    rules
}

fn nft_chain_rules(output: &[u8], chain_name: &str) -> Vec<String> {
    let mut in_chain = false;
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line == format!("chain {chain_name} {{") {
                in_chain = true;
                return None;
            }
            if !in_chain {
                return None;
            }
            if line == "}" {
                in_chain = false;
                return None;
            }
            let rule = line.split("# handle ").next().unwrap_or(line).trim();
            (!rule.is_empty()).then(|| rule.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .collect()
}

/// Remove rules in a base chain that jump to the given zone chain.
/// Uses nft handle-based deletion to avoid leaving stale references.
fn remove_chain_jumps(family: &str, base_chain: &str, chain_name: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", family, TABLE_NAME, base_chain])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to list nftables {family} {base_chain} chain: {e}"),
            hint: "ensure nftables is installed (nft command)".into(),
        })?;

    if !output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains("jump") && line.contains(chain_name) {
            if let Some(idx) = line.find("# handle ") {
                let handle = line[idx + "# handle ".len()..].trim();
                if !handle.is_empty() {
                    let _ = run_nft(&[
                        "delete", "rule", family, TABLE_NAME, base_chain, "handle", handle,
                    ]);
                }
            }
        }
    }

    Ok(())
}

fn zone_chain_name(zone_name: &str) -> String {
    // Zone names are validated by validate_zone_name: no path separators,
    // no NUL, not "." or "..", max 128 chars. This produces safe nftables
    // chain identifiers (max 256 chars).
    format!("zone-{zone_name}")
}

fn zone_input_chain_name(zone_name: &str) -> String {
    format!("input-{zone_name}")
}

fn zone_output_chain_name(zone_name: &str) -> String {
    format!("output-{zone_name}")
}

fn endpoint_rules(address_match: &str, targets: &[String]) -> Result<Vec<String>> {
    targets
        .iter()
        .map(|target| {
            // Zones persisted before ports became mandatory-nonzero used
            // `addr:0` to mean "any port"; keep those zones loadable.
            let target = match target.strip_suffix(":0") {
                Some(network) if network.parse::<NetworkEndpoint>().is_ok() => {
                    tracing::warn!(target, "legacy ':0' network target treated as any port");
                    network
                }
                _ => target.as_str(),
            };
            let endpoint = target.parse::<NetworkEndpoint>().map_err(|error| {
                RauhaError::InvalidPolicy(format!("invalid network target {target:?}: {error}"))
            })?;
            let mut rule = format!(
                "{} {address_match} {}",
                endpoint.nft_family(),
                endpoint.network()
            );
            if let Some(port) = endpoint.port {
                rule.push_str(&format!(" tcp dport {port}"));
            }
            rule.push_str(" accept");
            Ok(rule)
        })
        .collect()
}

fn table_exists(family: &str) -> Result<bool> {
    let output = Command::new("nft")
        .args(["list", "table", family, TABLE_NAME])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check nftables table: {e}"),
            hint: "ensure nftables is installed (nft command)".into(),
        })?;

    Ok(output.status.success())
}

fn run_nft(args: &[&str]) -> Result<()> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to run `nft {}`: {e}", args.join(" ")),
            hint: "ensure nftables is installed and rauhad runs as root".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("nft {} failed: {stderr}", args.join(" ")),
            hint: "run rauhad as root".into(),
        });
    }

    Ok(())
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to start nftables transaction: {e}"),
            hint: "ensure nftables is installed and rauhad runs as root".into(),
        })?;
    let mut stdin = child.stdin.take().ok_or_else(|| RauhaError::NetworkError {
        message: "failed to open nftables transaction input".into(),
        hint: "restart rauhad".into(),
    })?;
    if let Err(e) = stdin.write_all(script.as_bytes()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RauhaError::NetworkError {
            message: format!("failed to write nftables transaction: {e}"),
            hint: "restart rauhad".into(),
        });
    }
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to wait for nftables transaction: {e}"),
            hint: "restart rauhad".into(),
        })?;
    if !output.status.success() {
        return Err(RauhaError::NetworkError {
            message: format!(
                "nftables transaction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
            hint: "check nftables support and run rauhad as root".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_chain_name_format() {
        assert_eq!(zone_chain_name("web"), "zone-web");
        assert_eq!(zone_chain_name("my-app"), "zone-my-app");
        assert_eq!(zone_input_chain_name("web"), "input-web");
        assert_eq!(zone_output_chain_name("web"), "output-web");
    }

    #[test]
    fn empty_egress_adds_no_implicit_dns_exception() {
        assert!(endpoint_rules("daddr", &[]).unwrap().is_empty());
    }

    #[test]
    fn base_rulesets_split_by_family_and_fail_closed() {
        // inet: NAT + forward + host-input drop, one atomic transaction.
        let inet = inet_ruleset("10.89.0.0/16", "rauha0", true);
        assert_eq!(inet.lines().next().unwrap(), "delete table inet rauha");
        assert!(inet.contains("add table inet rauha"));
        assert!(inet.contains("add rule inet rauha input iifname \"rauha0\" drop"));
        assert!(inet.contains("ip saddr 10.89.0.0/16"));
        assert!(
            !inet.contains("bridge"),
            "bridge rules live in their own transaction"
        );
        // bridge: every base chain fails closed, its own transaction.
        let bridge = bridge_ruleset(true);
        assert_eq!(bridge.lines().next().unwrap(), "delete table bridge rauha");
        for chain in ["forward", "input", "output"] {
            assert!(
                bridge.contains(&format!(
                    "add chain bridge rauha {chain} {{ type filter hook {chain} priority filter; policy drop; }}"
                )),
                "bridge {chain} chain must fail closed"
            );
        }
        assert!(
            !bridge.contains("inet"),
            "no inet rules in the bridge transaction"
        );
        // First boot creates without deleting.
        assert!(inet_ruleset("10.0.0.0/16", "rauha0", false).starts_with("add table inet rauha"));
        assert!(bridge_ruleset(false).starts_with("add table bridge rauha"));
    }

    #[test]
    fn bridge_rules_are_bidirectional_and_fall_through_to_default_deny() {
        let policy = NetworkPolicy {
            mode: NetworkMode::Bridged,
            allowed_zones: vec!["peer".into()],
            allowed_egress: vec![],
            allowed_ingress: vec![],
        };
        let rules = bridge_zone_chain_rules("veth-source", &policy);
        let peer_veth = super::super::network::veth_host_name_for("peer");

        assert_eq!(rules.last().unwrap(), "return");
        assert!(rules.contains(&format!(
            "iifname \"veth-source\" oifname \"{peer_veth}\" accept"
        )));
        assert!(rules.contains(&format!(
            "iifname \"{peer_veth}\" oifname \"veth-source\" accept"
        )));
    }

    #[test]
    fn endpoint_rules_support_ipv4_ipv6_and_tcp_ports() {
        let rules =
            endpoint_rules("daddr", &["10.0.0.0/8:443".into(), "2001:db8::/32".into()]).unwrap();
        assert_eq!(
            rules,
            [
                "ip daddr 10.0.0.0/8 tcp dport 443 accept",
                "ip6 daddr 2001:db8::/32 accept",
            ]
        );
    }

    #[test]
    fn endpoint_rules_accept_legacy_port_zero_as_any_port() {
        let rules = endpoint_rules("daddr", &["0.0.0.0/0:0".into()]).unwrap();
        assert_eq!(rules, ["ip daddr 0.0.0.0/0 accept"]);
    }

    #[test]
    fn endpoint_rules_reject_nft_injection() {
        let error = endpoint_rules("daddr", &["0.0.0.0/0 accept".into()]).unwrap_err();
        assert!(error.to_string().contains("invalid network target"));
    }

    #[test]
    fn chain_verification_rejects_extra_accept_rule() {
        let output = b"table inet rauha {\n\tchain zone-test {\n\t\treturn # handle 4\n\t}\n}\n";
        assert_eq!(nft_chain_rules(output, "zone-test"), vec!["return"]);

        let tampered = b"table inet rauha {\n\tchain zone-test {\n\t\taccept # handle 3\n\t\treturn # handle 4\n\t}\n}\n";
        assert_ne!(nft_chain_rules(tampered, "zone-test"), vec!["return"]);
    }
}
