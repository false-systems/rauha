//! eBPF program lifecycle for rauha-enforce.
//!
//! Loads and attaches the same LSM programs as rauhad. Provides typed
//! wrappers for BPF map operations (zone membership, policy, comms).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use aya::maps::HashMap as AyaHashMap;
use aya::maps::RingBuf;
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader, Btf};
use rauha_common::zone::{capabilities_to_mask, ZonePolicy, ZoneType};
use rauha_ebpf_common::*;

const BPF_PIN_PATH: &str = "/sys/fs/bpf/rauha";

const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("rauha_file_open", "file_open"),
    ("rauha_bprm_check", "bprm_check_security"),
    ("rauha_ptrace_check", "ptrace_access_check"),
    ("rauha_task_kill", "task_kill"),
    ("rauha_cgroup_attach", "cgroup_attach_task"),
    ("rauha_capable", "capable"),
    ("rauha_socket_connect", "socket_connect"),
];

const MAP_NAMES: &[&str] = &[
    "ZONE_MEMBERSHIP",
    "ZONE_POLICY",
    "INODE_ZONE_MAP",
    "ZONE_ALLOWED_COMMS",
    "SELF_TEST",
    "ENFORCEMENT_COUNTERS",
    "ENFORCEMENT_EVENTS",
];

/// eBPF manager for the standalone enforce agent.
pub struct EnforceEbpf {
    bpf: Bpf,
    pin_path: PathBuf,
}

impl EnforceEbpf {
    /// Load and attach eBPF programs.
    pub fn load(ebpf_obj: Option<&Path>) -> anyhow::Result<Self> {
        let obj_path = match ebpf_obj {
            Some(p) => p.to_path_buf(),
            None => find_ebpf_object()?,
        };

        let pin_path = PathBuf::from(BPF_PIN_PATH);

        // Check for mutual exclusion — if maps are already pinned, another
        // instance (rauhad or rauha-enforce) is running.
        if pin_path.exists() {
            let has_maps = fs::read_dir(&pin_path)
                .map(|entries| entries.count() > 0)
                .unwrap_or(false);
            if has_maps {
                anyhow::bail!(
                    "BPF maps already pinned at {BPF_PIN_PATH} — another rauha instance \
                     (rauhad or rauha-enforce) may be running. Stop it first, or remove \
                     stale pins with: rm -rf {BPF_PIN_PATH}"
                );
            }
        }

        fs::create_dir_all(&pin_path)?;

        let btf = Btf::from_sys_fs()
            .map_err(|e| anyhow::anyhow!("failed to load BTF: {e} — kernel needs CONFIG_DEBUG_INFO_BTF=y"))?;

        // Resolve kernel struct offsets via pahole.
        // Validate compiled offsets against the running kernel via pahole.
        // Fail if any mismatch — wrong offsets cause silent enforcement failure.
        let resolved = resolve_offsets();
        for &(_, _, global_name, default) in OFFSET_DEFS {
            if let Some(&(_, val)) = resolved.iter().find(|(n, _)| n == global_name) {
                if val != default {
                    anyhow::bail!(
                        "kernel offset mismatch for {global_name}: kernel={val}, compiled={default}. \
                         Rebuild eBPF with `cargo xtask build-ebpf`"
                    );
                }
            }
        }

        let obj_data = fs::read(&obj_path)
            .map_err(|e| anyhow::anyhow!("failed to read eBPF object {}: {e}", obj_path.display()))?;

        let mut loader = BpfLoader::new();
        loader.btf(Some(&btf)).map_pin_path(&pin_path);

        let mut bpf = loader
            .load(&obj_data)
            .map_err(|e| anyhow::anyhow!("failed to load eBPF: {e} — check CONFIG_BPF_LSM=y and lsm=bpf"))?;

        // Attach all LSM programs.
        for &(prog_name, hook_name) in LSM_PROGRAMS {
            let prog: &mut Lsm = bpf
                .program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("LSM program '{prog_name}' not found"))?
                .try_into()?;
            prog.load(hook_name, &btf)?;
            prog.attach()?;
            tracing::info!(program = prog_name, hook = hook_name, "attached LSM program");
        }

        tracing::info!(programs = LSM_PROGRAMS.len(), "eBPF programs loaded");

        Ok(Self { bpf, pin_path })
    }

    /// Take ownership of the ring buffer for event streaming.
    pub fn take_event_ring_buf(&mut self) -> Option<RingBuf<aya::maps::MapData>> {
        let map = self.bpf.take_map("ENFORCEMENT_EVENTS")?;
        RingBuf::try_from(map).ok()
    }

    /// Register a cgroup as belonging to a zone.
    pub fn add_zone_member(
        &mut self,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> anyhow::Result<()> {
        let mut flags = 0u32;
        match zone_type {
            ZoneType::Global => flags |= ZONE_FLAG_GLOBAL,
            ZoneType::Privileged => flags |= ZONE_FLAG_PRIVILEGED,
            ZoneType::NonGlobal => {}
        }

        let info = ZoneInfoKernel { zone_id, flags };

        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;

        map.insert(cgroup_id, info, 0)?;
        Ok(())
    }

    /// Remove a cgroup from zone membership.
    pub fn remove_zone_member(&mut self, cgroup_id: u64) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;
        let _ = map.remove(&cgroup_id);
        Ok(())
    }

    /// Set enforcement policy for a zone.
    pub fn set_zone_policy(&mut self, zone_id: u32, policy: &ZonePolicy) -> anyhow::Result<()> {
        let kernel_policy = policy_to_kernel(policy)?;

        let mut map: AyaHashMap<_, u32, ZonePolicyKernel> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_POLICY")
                .ok_or_else(|| anyhow::anyhow!("ZONE_POLICY map not found"))?,
        )?;

        map.insert(zone_id, kernel_policy, 0)?;
        Ok(())
    }

    /// Read enforcement counters, summed across all CPUs.
    pub fn read_counters(&self) -> anyhow::Result<Vec<(String, EnforcementCounters)>> {
        use aya::maps::PerCpuArray;

        let map = PerCpuArray::<_, EnforcementCounters>::try_from(
            self.bpf.map("ENFORCEMENT_COUNTERS")
                .ok_or_else(|| anyhow::anyhow!("ENFORCEMENT_COUNTERS map not found"))?,
        )?;

        let mut results = Vec::new();
        for (idx, &(prog_name, _)) in LSM_PROGRAMS.iter().enumerate() {
            let per_cpu = map.get(&(idx as u32), 0)?;
            let mut total = EnforcementCounters { allow: 0, deny: 0, error: 0 };
            for cpu_val in per_cpu.iter() {
                total.allow += cpu_val.allow;
                total.deny += cpu_val.deny;
                total.error += cpu_val.error;
            }
            results.push((prog_name.to_string(), total));
        }

        Ok(results)
    }

    /// Clean up pinned maps on shutdown.
    pub fn cleanup(&self) {
        for &name in MAP_NAMES {
            let path = self.pin_path.join(name);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }
        let _ = fs::remove_dir(&self.pin_path);
        tracing::info!("cleaned up BPF pin directory");
    }
}

fn find_ebpf_object() -> anyhow::Result<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/lib/rauha/rauha-ebpf"),
        PathBuf::from("/var/lib/rauha/rauha-ebpf"),
        // Development build paths.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("rauha-ebpf/target/bpfel-unknown-none/debug/rauha-ebpf"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("rauha-ebpf/target/bpfel-unknown-none/release/rauha-ebpf"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    anyhow::bail!(
        "eBPF object not found — run `cargo xtask build-ebpf` or pass --ebpf-obj"
    )
}

fn policy_to_kernel(policy: &ZonePolicy) -> anyhow::Result<ZonePolicyKernel> {
    let caps_mask = capabilities_to_mask(&policy.capabilities.allowed)?;

    let mut flags = 0u32;
    if policy.capabilities.allowed.iter().any(|c| {
        let upper = c.to_uppercase();
        upper == "CAP_SYS_PTRACE" || upper == "SYS_PTRACE"
    }) {
        flags |= POLICY_FLAG_ALLOW_PTRACE;
    }

    if policy.network.mode == rauha_common::zone::NetworkMode::Host {
        flags |= POLICY_FLAG_ALLOW_HOST_NET;
    }

    Ok(ZonePolicyKernel {
        caps_mask,
        flags,
        _pad: 0,
    })
}

/// Offset definitions: (struct, field, global_name, default)
const OFFSET_DEFS: &[(&str, &str, &str, u64)] = &[
    ("task_struct", "cgroups", "TASK_CGROUPS_OFFSET", 3920),
    ("css_set", "dfl_cgrp", "CSS_SET_DFL_CGRP_OFFSET", 136),
    ("cgroup", "kn", "CGROUP_KN_OFFSET", 256),
    ("kernfs_node", "id", "KERNFS_NODE_ID_OFFSET", 96),
    ("file", "f_inode", "FILE_F_INODE_OFFSET", 32),
    ("inode", "i_ino", "INODE_I_INO_OFFSET", 64),
    ("linux_binprm", "executable", "BPRM_FILE_OFFSET", 48),
];

fn resolve_offsets() -> Vec<(String, u64)> {
    let pahole = ["/usr/bin/pahole", "/usr/local/bin/pahole"]
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| PathBuf::from(p));

    let pahole = match pahole {
        Some(p) => p,
        None => {
            tracing::warn!("pahole not found — using default struct offsets");
            return OFFSET_DEFS
                .iter()
                .map(|&(_, _, name, default)| (name.to_string(), default))
                .collect();
        }
    };

    OFFSET_DEFS
        .iter()
        .map(|&(type_name, field_name, global_name, default)| {
            let offset = pahole_field_offset(&pahole, type_name, field_name)
                .map(|v| v as u64)
                .unwrap_or_else(|_| {
                    tracing::debug!(r#type = type_name, field = field_name, "using default offset");
                    default
                });

            if offset != default {
                tracing::info!(
                    r#type = type_name, field = field_name, default, resolved = offset,
                    "kernel offset differs — using resolved value"
                );
            }

            (global_name.to_string(), offset)
        })
        .collect()
}

fn pahole_field_offset(pahole: &Path, type_name: &str, field_name: &str) -> Result<usize, String> {
    let output = std::process::Command::new(pahole)
        .args(["-C", type_name, "/sys/kernel/btf/vmlinux"])
        .output()
        .map_err(|e| format!("failed to run pahole: {e}"))?;

    if !output.status.success() {
        return Err(format!("pahole failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        let is_word_match = trimmed.split_whitespace().any(|word| {
            let clean = word.trim_end_matches(';');
            clean == field_name
        });
        if !is_word_match {
            continue;
        }
        if let Some(comment_start) = trimmed.rfind("/*") {
            let comment = &trimmed[comment_start + 2..];
            if let Some(comment_end) = comment.find("*/") {
                let nums = &comment[..comment_end].trim();
                if let Some(offset_str) = nums.split_whitespace().next() {
                    if let Ok(offset) = offset_str.parse::<usize>() {
                        return Ok(offset);
                    }
                }
            }
        }
    }

    Err(format!("field '{field_name}' not found in pahole output for '{type_name}'"))
}
