//! Network setup for zone isolation: veth pairs and bridge.
//!
//! Each zone gets a veth pair:
//! - host side: `veth-{zone}` attached to the rauha0 bridge
//! - zone side: `eth0` inside the zone's network namespace
//!
//! TODO(ipv6): Currently the address allocation and route setup are IPv4-only
//! (10.89.0.0/16). IPv6 addresses are not assigned, and IPv4-specific
//! nftables matches (for example NAT and rules using `ip saddr`/`ip daddr`)
//! do not apply to IPv6 traffic.
//! See: https://github.com/yairfalse/rauha/issues/24
//!
//! The rauha0 bridge connects all zone veth host-side interfaces,
//! with eBPF-enforced policy controlling which zones can communicate.

use std::net::Ipv4Addr;
use std::process::Command;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::ZoneNetworkState;
use sha2::{Digest, Sha256};

/// Ensure the zone bridge exists with a gateway IP and IP forwarding enabled.
/// The bridge name comes from daemon config (default `rauha0`).
pub fn ensure_bridge(gateway: Ipv4Addr, prefix_len: u8, bridge: &str) -> Result<()> {
    // Check if bridge already exists.
    let output = Command::new("ip")
        .args(["link", "show", bridge])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check bridge: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        // Create the bridge.
        run_ip(&["link", "add", "name", bridge, "type", "bridge"])?;
        run_ip(&["link", "set", bridge, "up"])?;
        tracing::info!(%bridge, "created network bridge");
    }

    // Assign gateway IP if not already present.
    let cidr = format!("{gateway}/{prefix_len}");
    if !bridge_has_addr(&cidr, bridge)? {
        run_ip(&["addr", "add", &cidr, "dev", bridge])?;
        tracing::info!(%bridge, addr = %cidr, "assigned gateway IP to bridge");
    }

    // Enable IP forwarding.
    enable_ip_forwarding()?;

    Ok(())
}

/// Check if the bridge already has a specific address assigned.
fn bridge_has_addr(cidr: &str, bridge: &str) -> Result<bool> {
    let output = Command::new("ip")
        .args(["addr", "show", "dev", bridge])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check bridge addresses: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(cidr))
}

/// Enable IPv4 forwarding via sysctl.
fn enable_ip_forwarding() -> Result<()> {
    let output = Command::new("sysctl")
        .args(["-w", "net.ipv4.ip_forward=1"])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to enable IP forwarding: {e}"),
            hint: "ensure rauhad runs as root".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("sysctl ip_forward failed: {stderr}"),
            hint: "run rauhad as root".into(),
        });
    }

    Ok(())
}

/// Create a veth pair for a zone and attach to bridge + namespace.
///
/// Creates:
/// - `veth-{zone}` on the host, attached to rauha0 bridge
/// - `eth0` inside the zone's network namespace
///
/// If `net_state` is provided, assigns the zone IP and adds a default route
/// via the gateway.
pub fn create_veth_pair(
    zone_name: &str,
    net_state: Option<&ZoneNetworkState>,
    bridge: &str,
) -> Result<()> {
    let host_if = veth_host_name(zone_name);
    let zone_peer_if = veth_peer_name(zone_name);
    let zone_if = "eth0";
    let ns_name = format!("rauha-{zone_name}");

    // Both ends initially exist in the host namespace, whose own `eth0` is
    // normally already taken. Rename the peer only after moving it.
    run_ip(&[
        "link",
        "add",
        &host_if,
        "type",
        "veth",
        "peer",
        "name",
        &zone_peer_if,
    ])?;

    let configure = (|| {
        run_ip(&["link", "set", &zone_peer_if, "netns", &ns_name])?;
        run_ip_netns(&ns_name, &["link", "set", &zone_peer_if, "name", zone_if])?;
        run_ip(&["link", "set", &host_if, "master", bridge])?;
        run_ip(&["link", "set", &host_if, "up"])?;
        run_ip_netns(&ns_name, &["link", "set", zone_if, "up"])?;
        run_ip_netns(&ns_name, &["link", "set", "lo", "up"])?;

        if let Some(state) = net_state {
            let cidr = state.cidr();
            let gateway = state.gateway().to_string();
            run_ip_netns(&ns_name, &["addr", "add", &cidr, "dev", zone_if])?;
            run_ip_netns(&ns_name, &["route", "add", "default", "via", &gateway])?;
            tracing::info!(zone = zone_name, ip = %state.ip(), "assigned IP to zone veth");
        }
        Ok(())
    })();

    if let Err(error) = configure {
        let _ = run_ip(&["link", "delete", &host_if]);
        return Err(error);
    }

    tracing::info!(zone = zone_name, host_if = host_if, "created veth pair");
    Ok(())
}

/// Get the host-side veth interface name for a zone (public for nftables).
pub fn veth_host_name_for(zone_name: &str) -> String {
    resolve_veth_host_name(zone_name, interface_exists)
}

fn resolve_veth_host_name(zone_name: &str, exists: impl Fn(&str) -> bool) -> String {
    let current = veth_host_name(zone_name);
    if exists(&current) {
        return current;
    }
    let legacy = legacy_veth_host_name(zone_name);
    if exists(&legacy) {
        return legacy;
    }
    current
}

pub fn veth_exists(zone_name: &str) -> bool {
    interface_exists(&veth_host_name(zone_name))
        || interface_exists(&legacy_veth_host_name(zone_name))
}

/// Destroy a zone's veth pair. Deleting the host side automatically
/// removes the zone side too.
pub fn destroy_veth_pair(zone_name: &str) -> Result<()> {
    let host_if = veth_host_name_for(zone_name);

    // Check if interface exists.
    let output = Command::new("ip")
        .args(["link", "show", &host_if])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check veth: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        return Ok(()); // Already gone.
    }

    run_ip(&["link", "delete", &host_if])?;

    tracing::info!(zone = zone_name, "destroyed veth pair");
    Ok(())
}

/// Destroy the zone bridge (called on daemon shutdown).
pub fn destroy_bridge(bridge: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(["link", "show", bridge])
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to check bridge: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        return Ok(()); // Already gone.
    }

    run_ip(&["link", "set", bridge, "down"])?;
    run_ip(&["link", "delete", bridge, "type", "bridge"])?;

    tracing::info!(%bridge, "destroyed network bridge");
    Ok(())
}

fn veth_host_name(zone_name: &str) -> String {
    veth_name("veth", zone_name)
}

fn veth_peer_name(zone_name: &str) -> String {
    veth_name("peer", zone_name)
}

fn veth_name(prefix: &str, zone_name: &str) -> String {
    let digest = Sha256::digest(zone_name.as_bytes());
    format!(
        "{prefix}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4]
    )
}

fn legacy_veth_host_name(zone_name: &str) -> String {
    format!(
        "veth-{}",
        zone_name.get(..zone_name.len().min(10)).unwrap_or_default()
    )
}

fn interface_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| RauhaError::NetworkError {
            message: format!("failed to run `ip {}`: {e}", args.join(" ")),
            hint: "ensure iproute2 is installed and rauhad runs as root".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!("ip {} failed: {stderr}", args.join(" ")),
            hint: "run rauhad as root".into(),
        });
    }

    Ok(())
}

fn run_ip_netns(ns_name: &str, args: &[&str]) -> Result<()> {
    let mut cmd_args = vec!["netns", "exec", ns_name, "ip"];
    cmd_args.extend_from_slice(args);

    let output =
        Command::new("ip")
            .args(&cmd_args)
            .output()
            .map_err(|e| RauhaError::NetworkError {
                message: format!(
                    "failed to run `ip netns exec {ns_name} ip {}`: {e}",
                    args.join(" ")
                ),
                hint: "ensure iproute2 is installed".into(),
            })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RauhaError::NetworkError {
            message: format!(
                "ip netns exec {ns_name} ip {} failed: {stderr}",
                args.join(" ")
            ),
            hint: "check namespace exists".into(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_names_are_unique_and_fit_linux_limit() {
        let first = veth_host_name("test-integration-alpha");
        let second = veth_host_name("test-integration-beta");
        assert_eq!(first, "veth5459f3b660");
        assert_ne!(first, second);
        assert!(first.len() <= 15);
        assert!(veth_peer_name("test-integration-alpha").len() <= 15);
        assert_eq!(
            legacy_veth_host_name("test-integration-alpha"),
            "veth-test-integ"
        );
    }

    #[test]
    fn recovery_uses_an_existing_legacy_veth() {
        let legacy = legacy_veth_host_name("test-integration-alpha");
        assert_eq!(
            resolve_veth_host_name("test-integration-alpha", |name| name == legacy),
            legacy
        );
    }
}
