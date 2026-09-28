//! IP address allocator for zone networking.
//!
//! Assigns IPv4 addresses from a subnet (default: 10.89.0.0/16).
//! Address .1 is reserved for the gateway (rauha0 bridge).
//! State is not persisted — it's rebuilt from Zone.network_state on startup.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use rauha_common::error::{RauhaError, Result};

pub struct IpAllocator {
    /// Network address (e.g. 10.89.0.0).
    subnet: [u8; 4],
    /// Prefix length (e.g. 16).
    prefix_len: u8,
    /// Host-part offsets that are currently allocated. Offset 1 = gateway.
    allocated: HashSet<u32>,
}

impl IpAllocator {
    pub fn new(subnet: [u8; 4], prefix_len: u8) -> Self {
        assert!(
            prefix_len <= 30,
            "prefix_len must be <= 30 to have usable host addresses"
        );
        let mut allocated = HashSet::new();
        // Reserve offset 0 (network address) and offset 1 (gateway).
        allocated.insert(0);
        allocated.insert(1);
        Self {
            subnet,
            prefix_len,
            allocated,
        }
    }

    /// Create an allocator with the default 10.89.0.0/16 subnet.
    /// Tests-only helper — production code constructs from daemon config.
    #[cfg(test)]
    pub fn default_subnet() -> Self {
        Self::new([10, 89, 0, 0], 16)
    }

    /// The gateway IP (always offset 1 in the subnet).
    pub fn gateway(&self) -> Ipv4Addr {
        self.offset_to_ip(1)
    }

    /// The prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The subnet as bytes.
    pub fn subnet(&self) -> [u8; 4] {
        self.subnet
    }

    /// Allocate the next available IP address.
    pub fn allocate(&mut self) -> Result<Ipv4Addr> {
        let max_offset = self.max_host_offset();

        // Find the lowest available offset (skip 0=network, 1=gateway).
        for offset in 2..=max_offset {
            if !self.allocated.contains(&offset) {
                self.allocated.insert(offset);
                return Ok(self.offset_to_ip(offset));
            }
        }

        Err(RauhaError::NetworkError {
            message: format!(
                "IP address pool exhausted ({} addresses allocated out of {})",
                self.allocated.len(),
                max_offset
            ),
            hint: "destroy unused zones to free IP addresses".into(),
        })
    }

    /// Mark an IP as allocated (used during recovery).
    pub fn mark_allocated(&mut self, ip: Ipv4Addr) {
        if let Some(offset) = self.validated_offset(ip) {
            self.allocated.insert(offset);
        }
    }

    /// Whether an IP is allocatable in this subnet (offset > 1, within
    /// the host range). Used at recovery to detect zones persisted under a
    /// different `[network] subnet` configuration.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.validated_offset(ip).is_some()
    }

    /// Release an IP address back to the pool.
    pub fn release(&mut self, ip: Ipv4Addr) {
        if let Some(offset) = self.validated_offset(ip) {
            self.allocated.remove(&offset);
        }
    }

    /// How many addresses are currently allocated (excluding network + gateway).
    #[cfg(test)]
    pub fn allocated_count(&self) -> usize {
        // Subtract 2 for the always-reserved network and gateway offsets.
        self.allocated.len().saturating_sub(2)
    }

    fn max_host_offset(&self) -> u32 {
        // For a /16, host part is 16 bits → 65535 max offset.
        // Subtract 1 for broadcast.
        let host_bits = 32 - self.prefix_len as u32;
        (1u32 << host_bits) - 2
    }

    fn offset_to_ip(&self, offset: u32) -> Ipv4Addr {
        let base = u32::from_be_bytes(self.subnet);
        Ipv4Addr::from((base + offset).to_be_bytes())
    }

    fn ip_to_offset(&self, ip: Ipv4Addr) -> u32 {
        let base = u32::from_be_bytes(self.subnet);
        let addr = u32::from_be_bytes(ip.octets());
        addr.wrapping_sub(base)
    }

    /// Validate that an IP is within this subnet and return its offset (> 1),
    /// or None if out of range.
    fn validated_offset(&self, ip: Ipv4Addr) -> Option<u32> {
        let offset = self.ip_to_offset(ip);
        if offset > 1 && offset <= self.max_host_offset() {
            Some(offset)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_reflects_subnet_membership() {
        let alloc = IpAllocator::new([10, 89, 0, 0], 24);
        assert!(alloc.contains(Ipv4Addr::new(10, 89, 0, 5)));
        assert!(alloc.contains(Ipv4Addr::new(10, 89, 0, 254)));
        // Outside the subnet entirely — the recovery mismatch case.
        assert!(!alloc.contains(Ipv4Addr::new(10, 90, 0, 5)));
        // In-subnet but reserved: network address and gateway.
        assert!(!alloc.contains(Ipv4Addr::new(10, 89, 0, 0)));
        assert!(!alloc.contains(Ipv4Addr::new(10, 89, 0, 1)));
    }

    #[test]
    fn allocate_returns_sequential_ips() {
        let mut alloc = IpAllocator::default_subnet();
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 2));
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 4));
    }

    #[test]
    fn release_and_reallocate() {
        let mut alloc = IpAllocator::default_subnet();
        let ip1 = alloc.allocate().unwrap();
        let ip2 = alloc.allocate().unwrap();
        let _ip3 = alloc.allocate().unwrap();

        alloc.release(ip1);
        // Should reallocate the lowest free offset (ip1).
        let ip4 = alloc.allocate().unwrap();
        assert_eq!(ip4, ip1);

        alloc.release(ip2);
        let ip5 = alloc.allocate().unwrap();
        assert_eq!(ip5, ip2);
    }

    #[test]
    fn gateway_is_not_allocatable() {
        let alloc = IpAllocator::default_subnet();
        assert_eq!(alloc.gateway(), Ipv4Addr::new(10, 89, 0, 1));
        // First allocation should be .2, not .1.
    }

    #[test]
    fn release_gateway_is_noop() {
        let mut alloc = IpAllocator::default_subnet();
        alloc.release(Ipv4Addr::new(10, 89, 0, 1));
        // Gateway should still be reserved — first alloc is still .2.
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 2));
    }

    #[test]
    fn recovered_addresses_are_not_reallocated() {
        let mut alloc = IpAllocator::default_subnet();
        alloc.mark_allocated(Ipv4Addr::new(10, 89, 0, 2));
        alloc.mark_allocated(Ipv4Addr::new(10, 89, 0, 5));

        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 3));
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 4));
        assert_eq!(alloc.allocate().unwrap(), Ipv4Addr::new(10, 89, 0, 6));
    }

    #[test]
    fn exhaustion_with_small_subnet() {
        // /30 = 4 addresses: network, gateway, and 2 hosts.
        let mut alloc = IpAllocator::new([10, 0, 0, 0], 30);
        assert!(alloc.allocate().is_ok()); // .2
                                           // .3 would be broadcast in a real /30, but our max_host_offset
                                           // calculation gives (1<<2) - 2 = 2, so only offset 2 is available.
        assert!(alloc.allocate().is_err());
    }

    #[test]
    fn allocated_count() {
        let mut alloc = IpAllocator::default_subnet();
        assert_eq!(alloc.allocated_count(), 0);
        alloc.allocate().unwrap();
        assert_eq!(alloc.allocated_count(), 1);
        alloc.allocate().unwrap();
        assert_eq!(alloc.allocated_count(), 2);
    }
}
