//! Typed wrappers for BPF map operations.
//!
//! Translates domain concepts (zones, policies, inodes) into BPF map
//! key/value pairs. All BPF map access goes through MapManager.

use aya::maps::{HashMap as AyaHashMap, MapError};
use aya::Ebpf;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ZonePolicy, ZoneType};
use rauha_ebpf_common::*;
use rauha_enforcer_api::ZoneEnforcement;

fn map_key_missing(error: &MapError) -> bool {
    matches!(error, MapError::KeyNotFound | MapError::ElementNotFound)
        || matches!(
            error,
            MapError::SyscallError(error)
                if error.io_error.raw_os_error() == Some(libc::ENOENT)
        )
}

pub struct MapManager;

fn ensure_inode_owner(inode: InodeKey, owner: Option<u32>, zone_id: u32) -> Result<()> {
    if let Some(owner) = owner.filter(|owner| *owner != zone_id) {
        return Err(RauhaError::BackendError(format!(
            "inode {inode:?} belongs to zone {owner}, not {zone_id}"
        )));
    }
    Ok(())
}

impl MapManager {
    /// Read a cgroup's kernel membership entry.
    pub fn zone_member(bpf: &Ebpf, cgroup_id: u64) -> Result<Option<ZoneInfoKernel>> {
        let map: AyaHashMap<_, u64, ZoneInfoKernel> =
            AyaHashMap::try_from(bpf.map("ZONE_MEMBERSHIP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_MEMBERSHIP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_MEMBERSHIP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.get(&cgroup_id, 0) {
            Ok(member) => Ok(Some(member)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to read zone membership: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }

    /// Register a cgroup as belonging to a zone.
    pub fn add_zone_member(
        bpf: &mut Ebpf,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> Result<()> {
        let mut flags = 0u32;
        match zone_type {
            ZoneType::Global => flags |= ZONE_FLAG_GLOBAL,
            ZoneType::Privileged => flags |= ZONE_FLAG_PRIVILEGED,
            ZoneType::NonGlobal => {}
        }

        let info = ZoneInfoKernel { zone_id, flags };

        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_MEMBERSHIP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_MEMBERSHIP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_MEMBERSHIP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(cgroup_id, info, 0)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to insert zone membership: {e}"),
                hint: "map may be full (check MAX_CGROUPS)".into(),
            })?;

        tracing::debug!(cgroup_id, zone_id, "added zone member to BPF map");
        Ok(())
    }

    /// Remove a cgroup from zone membership.
    ///
    /// NotFound is acceptable (idempotent cleanup) and logged at debug level.
    /// Other errors propagate.
    pub fn remove_zone_member(bpf: &mut Ebpf, cgroup_id: u64) -> Result<()> {
        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_MEMBERSHIP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_MEMBERSHIP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_MEMBERSHIP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            Err(e) if map_key_missing(&e) => {
                tracing::debug!(cgroup_id, "zone membership entry already removed");
                Ok(())
            }
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to remove zone membership: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }

    /// Set the enforcement policy for a zone in the BPF map.
    pub fn set_zone_policy(bpf: &mut Ebpf, zone_id: u32, policy: &ZonePolicy) -> Result<()> {
        Self::set_zone_policy_kernel(bpf, zone_id, policy_to_kernel(policy)?)
    }

    /// Write an already-translated kernel policy record into ZONE_POLICY.
    ///
    /// This is the kernel-facing half of policy application: it takes the
    /// `ZonePolicyKernel` produced from the enforcement seam's vocabulary and
    /// inserts it. The enforcer adapter calls this directly so policy that
    /// crosses the seam (`ZoneEnforcement`) lands in the same map entry as
    /// policy applied from a full `ZonePolicy`.
    pub fn set_zone_policy_kernel(
        bpf: &mut Ebpf,
        zone_id: u32,
        kernel_policy: ZonePolicyKernel,
    ) -> Result<()> {
        let mut map: AyaHashMap<_, u32, ZonePolicyKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_POLICY").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_POLICY map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_POLICY map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(zone_id, kernel_policy, 0)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to insert zone policy: {e}"),
                hint: "map may be full (check MAX_ZONES)".into(),
            })?;

        tracing::debug!(
            zone_id,
            caps_mask = kernel_policy.caps_mask,
            "set zone policy in BPF map"
        );
        Ok(())
    }

    /// Remove a zone's policy from BPF maps.
    ///
    /// NotFound is acceptable (idempotent cleanup) and logged at debug level.
    pub fn remove_zone_policy(bpf: &mut Ebpf, zone_id: u32) -> Result<()> {
        let mut map: AyaHashMap<_, u32, ZonePolicyKernel> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_POLICY").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_POLICY map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_POLICY map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.remove(&zone_id) {
            Ok(()) => Ok(()),
            Err(e) if map_key_missing(&e) => {
                tracing::debug!(zone_id, "zone policy already removed");
                Ok(())
            }
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to remove zone policy: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }

    /// Track an inode as belonging to a zone.
    pub fn set_inode_zone(bpf: &mut Ebpf, inode: InodeKey, zone_id: u32) -> Result<()> {
        if let Some(owner) = Self::inode_zone(bpf, inode)? {
            ensure_inode_owner(inode, Some(owner), zone_id)?;
            return Ok(());
        }
        let mut map: AyaHashMap<_, InodeKey, u32> =
            AyaHashMap::try_from(bpf.map_mut("INODE_ZONE_MAP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "INODE_ZONE_MAP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open INODE_ZONE_MAP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(inode, zone_id, 0)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to insert inode zone mapping: {e}"),
                hint: "map may be full (check MAX_INODES)".into(),
            })?;

        Ok(())
    }

    pub fn inode_zone(bpf: &Ebpf, inode: InodeKey) -> Result<Option<u32>> {
        let map: AyaHashMap<_, InodeKey, u32> =
            AyaHashMap::try_from(bpf.map("INODE_ZONE_MAP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "INODE_ZONE_MAP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open INODE_ZONE_MAP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.get(&inode, 0) {
            Ok(zone_id) => Ok(Some(zone_id)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to read inode ownership: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }

    /// Remove an inode from zone tracking.
    pub fn remove_inode_zone(bpf: &mut Ebpf, inode: InodeKey) -> Result<()> {
        let mut map: AyaHashMap<_, InodeKey, u32> =
            AyaHashMap::try_from(bpf.map_mut("INODE_ZONE_MAP").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "INODE_ZONE_MAP map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open INODE_ZONE_MAP map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.remove(&inode) {
            Ok(()) => Ok(()),
            Err(e) if map_key_missing(&e) => {
                tracing::debug!(?inode, "inode ownership entry already removed");
                Ok(())
            }
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to remove inode ownership: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }

    /// Insert a batch of pre-collected inodes into the INODE_ZONE_MAP.
    ///
    /// This is the BPF-touching half of inode registration. Call
    /// `collect_rootfs_inodes` first (outside any lock) to get the inode list,
    /// then call this with the lock held briefly.
    /// Returns the list of successfully inserted inodes (not the full input).
    /// Callers should store only this list for cleanup — not the original
    /// input — to avoid removing entries that were never inserted.
    pub fn insert_inodes(
        bpf: &mut Ebpf,
        inodes: &[InodeKey],
        zone_id: u32,
    ) -> Result<Vec<InodeKey>> {
        // Preflight under the enforcer lock: audit admission must not reassign
        // an object already owned by a different zone.
        for &inode in inodes {
            ensure_inode_owner(inode, Self::inode_zone(bpf, inode)?, zone_id)?;
        }
        let mut inserted = Vec::with_capacity(inodes.len());
        for &ino in inodes {
            if let Err(e) = Self::set_inode_zone(bpf, ino, zone_id) {
                tracing::debug!(?ino, zone_id, %e, "failed to register inode");
                continue;
            }
            inserted.push(ino);
        }
        tracing::debug!(
            zone_id,
            count = inserted.len(),
            total = inodes.len(),
            "inserted inodes into BPF map"
        );
        Ok(inserted)
    }

    /// Remove a batch of inodes from the INODE_ZONE_MAP.
    pub fn remove_inodes(bpf: &mut Ebpf, inodes: &[InodeKey]) -> Result<u32> {
        let mut count = 0u32;
        for &ino in inodes {
            Self::remove_inode_zone(bpf, ino)?;
            count += 1;
        }
        tracing::debug!(count, total = inodes.len(), "removed inodes from BPF map");
        Ok(count)
    }

    /// Allow cross-zone communication between two zones.
    pub fn allow_zone_comm(bpf: &mut Ebpf, src_zone: u32, dst_zone: u32) -> Result<()> {
        let key = ZoneCommKey { src_zone, dst_zone };

        let mut map: AyaHashMap<_, ZoneCommKey, u8> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_ALLOWED_COMMS").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_ALLOWED_COMMS map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_ALLOWED_COMMS map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        map.insert(key, 1u8, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to allow zone comm {src_zone} -> {dst_zone}: {e}"),
            hint: "map may be full".into(),
        })?;

        tracing::debug!(src_zone, dst_zone, "allowed cross-zone communication");
        Ok(())
    }

    /// Deny cross-zone communication between two zones.
    ///
    /// NotFound is acceptable (pair may not have been allowed) and logged at debug.
    pub fn deny_zone_comm(bpf: &mut Ebpf, src_zone: u32, dst_zone: u32) -> Result<()> {
        let key = ZoneCommKey { src_zone, dst_zone };

        let mut map: AyaHashMap<_, ZoneCommKey, u8> =
            AyaHashMap::try_from(bpf.map_mut("ZONE_ALLOWED_COMMS").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "ZONE_ALLOWED_COMMS map not found".into(),
                    hint: "eBPF programs may not be loaded".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open ZONE_ALLOWED_COMMS map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        match map.remove(&key) {
            Ok(()) => Ok(()),
            Err(e) if map_key_missing(&e) => {
                tracing::debug!(src_zone, dst_zone, "zone communication already denied");
                Ok(())
            }
            Err(e) => Err(RauhaError::EbpfError {
                message: format!("failed to deny zone comm {src_zone} -> {dst_zone}: {e}"),
                hint: "check BPF map health".into(),
            }),
        }
    }
}

/// Collect all inode numbers from a directory tree.
///
/// This is the filesystem-walking half of inode registration. It does no BPF
/// operations and needs no locks — call it outside the ebpf mutex, then pass
/// the result to `MapManager::insert_inodes` with the lock held briefly.
///
/// ## Overlayfs behavior
///
/// When `rootfs_path` is an overlayfs merged mount (the normal case for
/// containers with `overlay_layers`), `stat()` returns the overlayfs inode
/// number. This matches what the kernel sees in `file->f_inode->i_ino` when
/// the container process opens files through the same mount — so the inode
/// numbers are consistent between collection and enforcement.
///
/// **Known limitation — copy-up:** When a container modifies a file from a
/// lower (read-only) layer, overlayfs copies it to the upper (writable) layer.
/// The copied-up file gets a new inode number not present in INODE_ZONE_MAP.
/// The eBPF `file_open` hook treats untracked inodes as allowed (fail-open),
/// so copy-up creates a narrow enforcement gap for modified files. This is
/// acceptable because mount namespaces are the primary isolation barrier and
/// eBPF is defense-in-depth.
///
/// Returns the collected inodes (capped at `max_inodes`).
pub fn collect_rootfs_inodes(
    rootfs_path: &std::path::Path,
    max_inodes: u32,
) -> Result<Vec<InodeKey>> {
    use std::collections::HashSet;
    use std::os::unix::fs::MetadataExt;

    let mut inodes = Vec::new();
    let mut visited_dirs = HashSet::new(); // Prevents cycles from hardlinked/bind-mounted dirs.
    let mut stack = vec![rootfs_path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to read rootfs directory {}: {e}", dir.display()),
        })?;

        for entry in entries {
            if inodes.len() as u32 >= max_inodes {
                return Err(RauhaError::RootfsError {
                    message: format!(
                        "rootfs inode count exceeds enforcement capacity of {max_inodes}"
                    ),
                });
            }

            let entry = entry.map_err(|e| RauhaError::RootfsError {
                message: format!("failed to enumerate rootfs {}: {e}", dir.display()),
            })?;

            let meta =
                std::fs::symlink_metadata(entry.path()).map_err(|e| RauhaError::RootfsError {
                    message: format!(
                        "failed to inspect rootfs entry {}: {e}",
                        entry.path().display()
                    ),
                })?;

            let key = InodeKey {
                device: ((libc::major(meta.dev()) as u64) << 20) | libc::minor(meta.dev()) as u64,
                inode: meta.ino(),
            };
            inodes.push(key);

            if meta.is_dir() && visited_dirs.insert(key) {
                stack.push(entry.path());
            }
        }
    }

    tracing::debug!(count = inodes.len(), path = %rootfs_path.display(), "collected rootfs inodes");
    Ok(inodes)
}

/// Convert userspace ZonePolicy to kernel-side ZonePolicyKernel.
///
/// Maps capability names to a bitmask and policy settings to flag bits.
/// Map the enforcement seam's neutral zone flags onto the kernel policy record.
///
/// This is the only place that knows the kernel's flag-bit ABI
/// (`POLICY_FLAG_*`). Everything upstream speaks `ZoneEnforcement`.
pub fn enforcement_to_kernel(zone: &ZoneEnforcement) -> ZonePolicyKernel {
    let mut flags = 0u32;
    if zone.allow_ptrace {
        flags |= POLICY_FLAG_ALLOW_PTRACE;
    }
    if zone.allow_host_net {
        flags |= POLICY_FLAG_ALLOW_HOST_NET;
    }

    ZonePolicyKernel {
        caps_mask: zone.caps_mask,
        flags,
        _pad: 0,
    }
}

/// Translate a full Rauha `ZonePolicy` into a kernel policy record.
///
/// Goes through the enforcement seam's `ZoneEnforcement` vocabulary so there is
/// a single source of truth for policy meaning (`ZonePolicy::to_enforcement`)
/// and a single place that knows the kernel ABI (`enforcement_to_kernel`).
fn policy_to_kernel(policy: &ZonePolicy) -> Result<ZonePolicyKernel> {
    Ok(enforcement_to_kernel(&policy.to_enforcement()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::zone::{NetworkMode, ZonePolicy};

    #[test]
    fn inode_registration_cannot_replace_another_zone_owner() {
        let inode = InodeKey {
            device: 3,
            inode: 7,
        };
        assert!(ensure_inode_owner(inode, None, 1).is_ok());
        assert!(ensure_inode_owner(inode, Some(1), 1).is_ok());
        assert!(ensure_inode_owner(inode, Some(2), 1).is_err());
    }

    #[test]
    fn collected_inode_device_matches_kernel_dev_t_layout() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("file");
        std::fs::write(&file, b"data").unwrap();
        let metadata = file.metadata().unwrap();
        let inodes = collect_rootfs_inodes(root.path(), 1).unwrap();
        assert_eq!(
            inodes,
            vec![InodeKey {
                device: ((libc::major(metadata.dev()) as u64) << 20)
                    | libc::minor(metadata.dev()) as u64,
                inode: metadata.ino(),
            }]
        );
    }

    fn default_policy_with_caps(caps: Vec<&str>) -> ZonePolicy {
        let mut p = ZonePolicy::default();
        p.capabilities.allowed = caps.into_iter().map(String::from).collect();
        p
    }

    #[test]
    fn policy_to_kernel_default_has_empty_capability_allow_list() {
        let k = policy_to_kernel(&ZonePolicy::default()).unwrap();
        assert_eq!(k.caps_mask, 0);
        assert_eq!(k.flags, 0);
        assert_eq!(k._pad, 0);
    }

    #[test]
    fn policy_to_kernel_empty_capabilities_mean_allow_none() {
        let k = policy_to_kernel(&default_policy_with_caps(vec![])).unwrap();
        assert_eq!(k.caps_mask, 0);
    }

    #[test]
    fn policy_to_kernel_sets_ptrace_flag_from_cap() {
        let k = policy_to_kernel(&default_policy_with_caps(vec!["CAP_SYS_PTRACE"])).unwrap();
        assert_ne!(k.flags & POLICY_FLAG_ALLOW_PTRACE, 0);
    }

    #[test]
    fn policy_to_kernel_sets_ptrace_flag_from_short_form() {
        let k = policy_to_kernel(&default_policy_with_caps(vec!["SYS_PTRACE"])).unwrap();
        assert_ne!(k.flags & POLICY_FLAG_ALLOW_PTRACE, 0);
    }

    #[test]
    fn policy_to_kernel_ptrace_flag_case_insensitive() {
        let k = policy_to_kernel(&default_policy_with_caps(vec!["cap_sys_ptrace"])).unwrap();
        assert_ne!(k.flags & POLICY_FLAG_ALLOW_PTRACE, 0);
    }

    #[test]
    fn policy_to_kernel_host_network_sets_flag() {
        let mut p = ZonePolicy::default();
        p.network.mode = NetworkMode::Host;
        let k = policy_to_kernel(&p).unwrap();
        assert_ne!(k.flags & POLICY_FLAG_ALLOW_HOST_NET, 0);
    }

    #[test]
    fn policy_to_kernel_isolated_network_no_flag() {
        let p = ZonePolicy::default(); // default is Isolated
        let k = policy_to_kernel(&p).unwrap();
        assert_eq!(k.flags & POLICY_FLAG_ALLOW_HOST_NET, 0);
    }

    #[test]
    fn policy_to_kernel_caps_mask_correct() {
        let k = policy_to_kernel(&default_policy_with_caps(vec![
            "CAP_NET_ADMIN",
            "CAP_SYS_ADMIN",
        ]))
        .unwrap();
        // CAP_NET_ADMIN = bit 12, CAP_SYS_ADMIN = bit 21
        assert_eq!(k.caps_mask, (1 << 12) | (1 << 21));
    }

    #[test]
    fn policy_to_kernel_unknown_cap_rejected() {
        assert!(policy_to_kernel(&default_policy_with_caps(vec!["CAP_NONEXISTENT"])).is_err());
    }

    #[test]
    fn inode_collection_fails_instead_of_truncating() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("one"), b"1").unwrap();
        std::fs::write(root.path().join("two"), b"2").unwrap();

        let err = collect_rootfs_inodes(root.path(), 1)
            .expect_err("an incomplete ownership set must not look successful");
        assert!(err.to_string().contains("enforcement capacity"));
    }
}
