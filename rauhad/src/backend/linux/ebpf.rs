//! eBPF program lifecycle: load, attach, pin, health check.
//!
//! Uses Aya to load the compiled rauha-ebpf object, attach LSM hooks,
//! and pin maps to /sys/fs/bpf/rauha/ for persistence.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use aya::programs::Lsm;
use aya::{Bpf, BpfLoader, Btf};
use aya_obj::btf::BtfKind;
use rauha_common::error::{RauhaError, Result};
use rauha_ebpf_common::offsets::{
    object_sha256, offsets_sidecar_path, parse_offsets_sidecar, resolve_kernel_offsets_map,
    OFFSET_DEFS,
};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/rauha";

/// LSM programs: (program_name_in_object, lsm_hook_name).
/// The hook name is what Aya passes to the kernel BTF lookup.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("rauha_file_open", "file_open"),
    ("rauha_bprm_check", "bprm_check_security"),
    ("rauha_ptrace_check", "ptrace_access_check"),
    ("rauha_task_kill", "task_kill"),
    ("rauha_cgroup_attach", "cgroup_attach_task"),
    ("rauha_capable", "capable"),
    ("rauha_socket_connect", "socket_connect"),
];

/// Names of maps to pin for persistence.
const MAP_NAMES: &[&str] = &[
    "ZONE_MEMBERSHIP",
    "ZONE_POLICY",
    "INODE_ZONE_MAP",
    "ZONE_ALLOWED_COMMS",
    "SELF_TEST",
    "ENFORCEMENT_COUNTERS",
    "ENFORCEMENT_EVENTS",
];

pub struct EbpfManager {
    // IMPORTANT: field order matters for drop safety. `program_fds` contains
    // raw fd integers borrowed from `bpf`. Rust drops fields in declaration
    // order, so `program_fds` (just integers, no Drop) drops before `bpf`
    // (which owns the actual fds). Do not reorder these fields.
    bpf: Bpf,
    pin_path: PathBuf,
    /// Program fds recorded after attach, keyed by program name.
    /// Used in health_check to verify programs are still loaded.
    ///
    /// Note: this checks program validity, not link validity. A program
    /// can theoretically be loaded but have its LSM link detached (e.g. via
    /// bpftool). Aya 0.13 doesn't expose link fds publicly. The link is
    /// owned internally by the Bpf object and stays attached as long as
    /// it's not explicitly detached or the Bpf object dropped.
    program_fds: HashMap<String, i32>,
}

impl EbpfManager {
    /// Load eBPF programs and maps from the compiled object file.
    ///
    /// The object file is expected at `{ebpf_obj_path}`. On production systems
    /// this is typically `/usr/lib/rauha/rauha-ebpf` or built by `cargo xtask build-ebpf`.
    pub fn load(ebpf_obj_path: &Path) -> Result<Self> {
        check_kernel_version()?;

        if !ebpf_obj_path.exists() {
            return Err(RauhaError::EbpfError {
                message: format!("eBPF object not found: {}", ebpf_obj_path.display()),
                hint: "run `cargo xtask build-ebpf` to compile the eBPF programs".into(),
            });
        }

        let pin_path = PathBuf::from(BPF_PIN_PATH);

        // Remove any stale pinned maps from a previous run (crash recovery).
        // BpfLoader::map_pin_path() reuses existing pins, which would leave
        // stale zone_id entries from the old run. Since recover_zone()
        // repopulates all maps from redb, starting fresh is correct.
        if pin_path.exists() {
            for entry in fs::read_dir(&pin_path).into_iter().flatten().flatten() {
                let _ = fs::remove_file(entry.path());
            }
            tracing::debug!("cleared stale BPF pin files from previous run");
        }

        fs::create_dir_all(&pin_path).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to create BPF pin directory: {e}"),
            hint: "run rauhad as root with BPF filesystem mounted".into(),
        })?;

        let btf = Btf::from_sys_fs().map_err(|e| RauhaError::EbpfError {
            message: format!("failed to load BTF from sysfs: {e}"),
            hint: "kernel must have CONFIG_DEBUG_INFO_BTF=y".into(),
        })?;

        // Validate the offsets compiled into the object against this kernel's
        // BTF before loading. Wrong offsets make enforcement unsound.
        let resolved_offsets = resolve_kernel_offsets_map().map_err(|e| RauhaError::EbpfError {
            message: format!("failed to resolve kernel offsets: {e}"),
            hint: "install dwarves/pahole and ensure /sys/kernel/btf/vmlinux is present".into(),
        })?;
        let compiled_offsets = read_compiled_offsets(ebpf_obj_path)?;
        for def in OFFSET_DEFS {
            let resolved =
                resolved_offsets
                    .get(def.manifest_key)
                    .ok_or_else(|| RauhaError::EbpfError {
                        message: format!("resolved offset {} is missing", def.manifest_key),
                        hint: "install dwarves/pahole and rebuild eBPF programs".into(),
                    })?;
            let compiled =
                compiled_offsets
                    .get(def.manifest_key)
                    .ok_or_else(|| RauhaError::EbpfError {
                        message: format!(
                            "compiled offset {} is missing from sidecar",
                            def.manifest_key
                        ),
                        hint:
                            "run `cargo xtask build-ebpf` to regenerate the eBPF object and sidecar"
                                .into(),
                    })?;
            if resolved != compiled {
                return Err(RauhaError::EbpfError {
                    message: format!(
                        "kernel struct offset mismatch for {}: running kernel has {resolved} \
                         but eBPF object was compiled with {compiled}",
                        def.manifest_key
                    ),
                    hint: "rebuild eBPF on this kernel with `cargo xtask build-ebpf`".into(),
                });
            }
        }

        let obj_data = fs::read(ebpf_obj_path).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to read eBPF object: {e}"),
            hint: format!("check permissions on {}", ebpf_obj_path.display()),
        })?;

        let mut loader = BpfLoader::new();
        loader.btf(Some(&btf)).map_pin_path(&pin_path);

        let mut bpf = loader.load(&obj_data).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to load eBPF programs: {e}"),
            hint: "check kernel has CONFIG_BPF_LSM=y and `lsm=bpf` in cmdline".into(),
        })?;

        let mut program_fds = HashMap::new();

        // Attach every declared LSM program that this kernel can support.
        //
        // Policy: a hook the running kernel does not expose as a BPF-LSM attach
        // point is skipped (best-effort, degraded enforcement). Any *other*
        // failure — the program missing from our own object, or the kernel
        // rejecting an attach for a hook it does expose — is still fatal: we
        // refuse to run with a boundary that should exist but silently broke.
        let mut skipped_hooks: Vec<&str> = Vec::new();

        for &(prog_name, hook_name) in LSM_PROGRAMS {
            // Probe the kernel BTF for `bpf_lsm_<hook>`. If the kernel was not
            // built exposing this LSM hook to BPF (e.g. cgroup_attach_task is
            // absent on many stock kernels), skip it gracefully rather than
            // failing the whole daemon.
            if btf
                .id_by_type_name_kind(&format!("bpf_lsm_{hook_name}"), BtfKind::Func)
                .is_err()
            {
                tracing::warn!(
                    program = prog_name,
                    hook = hook_name,
                    "kernel does not expose this BPF-LSM hook; skipping (degraded enforcement)"
                );
                skipped_hooks.push(hook_name);
                continue;
            }

            let prog: &mut Lsm = match bpf.program_mut(prog_name) {
                Some(p) => match p.try_into() {
                    Ok(lsm) => lsm,
                    Err(e) => {
                        return Err(RauhaError::EbpfError {
                            message: format!("eBPF program {prog_name} is not an LSM program: {e}"),
                            hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
                        });
                    }
                },
                None => {
                    return Err(RauhaError::EbpfError {
                        message: format!("required eBPF program {prog_name} not found in object"),
                        hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
                    });
                }
            };

            prog.load(hook_name, &btf).map_err(|e| RauhaError::EbpfError {
                message: format!(
                    "failed to load required LSM program {prog_name} for hook {hook_name}: {e}"
                ),
                hint: "check kernel has CONFIG_BPF_LSM=y, `lsm=bpf` in cmdline, and exposes every required hook".into(),
            })?;

            prog.attach().map_err(|e| RauhaError::EbpfError {
                message: format!("failed to attach required LSM program {prog_name}: {e}"),
                hint: "check kernel BPF-LSM support and process privileges".into(),
            })?;

            let prog_fd = prog.fd().map_err(|e| RauhaError::EbpfError {
                message: format!("failed to record fd for required LSM program {prog_name}: {e}"),
                hint: "restart rauhad to reload and reattach eBPF programs".into(),
            })?;
            program_fds.insert(prog_name.to_string(), prog_fd.as_fd().as_raw_fd());

            tracing::info!(
                program = prog_name,
                hook = hook_name,
                "attached LSM program"
            );
        }

        // Every hook the kernel *does* expose must have attached — the loop
        // hard-fails otherwise — so this should always hold. Kept as a
        // defensive invariant against future refactors of the loop above.
        let expected = LSM_PROGRAMS.len() - skipped_hooks.len();
        if program_fds.len() != expected {
            return Err(RauhaError::EbpfError {
                message: format!(
                    "partial LSM attachment: attached {} of {} attachable programs",
                    program_fds.len(),
                    expected
                ),
                hint: "restart rauhad after fixing kernel BPF-LSM support".into(),
            });
        }

        // Refuse to run with zero enforcement — that is indistinguishable from
        // having no sandbox at all, and is never what the operator wants.
        if program_fds.is_empty() {
            return Err(RauhaError::EbpfError {
                message: "no LSM hooks could be attached on this kernel".into(),
                hint: "kernel exposes none of Rauha's BPF-LSM hooks; check \
                       CONFIG_BPF_LSM=y and `lsm=bpf` in the kernel cmdline"
                    .into(),
            });
        }

        if !skipped_hooks.is_empty() {
            tracing::warn!(
                skipped = ?skipped_hooks,
                attached = program_fds.len(),
                total = LSM_PROGRAMS.len(),
                "running with DEGRADED enforcement: some LSM hooks are \
                 unavailable on this kernel"
            );
        }

        tracing::info!(
            attached = program_fds.len(),
            total = LSM_PROGRAMS.len(),
            skipped = skipped_hooks.len(),
            pin_path = %pin_path.display(),
            "eBPF programs loaded"
        );

        let mut mgr = Self {
            bpf,
            pin_path,
            program_fds,
        };

        // Run the offset self-test: trigger file_open to populate SELF_TEST map,
        // then verify the two cgroup_id derivation paths match.
        mgr.verify_offset_self_test()?;

        Ok(mgr)
    }

    /// Take ownership of the ENFORCEMENT_EVENTS ring buffer map.
    ///
    /// Transfers the map out of the Bpf object so it can be moved into a
    /// background task without lifetime issues. Can only be called once.
    pub fn take_event_ring_buf(&mut self) -> Result<aya::maps::RingBuf<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("ENFORCEMENT_EVENTS")
            .ok_or_else(|| RauhaError::EbpfError {
                message: "ENFORCEMENT_EVENTS map not found or already taken".into(),
                hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
            })?;
        aya::maps::RingBuf::try_from(map).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to create RingBuf from ENFORCEMENT_EVENTS: {e}"),
            hint: "check eBPF object was built correctly".into(),
        })
    }

    /// Get a mutable reference to the inner Bpf object for map access.
    pub fn bpf_mut(&mut self) -> &mut Bpf {
        &mut self.bpf
    }

    /// Get a reference to the inner Bpf object for map reads.
    pub fn bpf(&self) -> &Bpf {
        &self.bpf
    }

    /// Check that all programs are still loaded and their fds are valid.
    ///
    /// Verifies two things per program:
    /// 1. The program exists in the Bpf handle (loaded).
    /// 2. The program fd is still valid (kernel hasn't reclaimed it).
    ///
    /// The program fd being valid is a necessary condition for enforcement.
    /// The LSM link (which actually hooks the program into the LSM framework)
    /// is managed internally by aya — aya 0.13 doesn't expose link fds
    /// publicly. The link stays attached as long as the Bpf object is alive
    /// and nobody explicitly detaches it.
    pub fn health_check(&self) -> Result<Vec<ProgramStatus>> {
        let mut statuses = Vec::new();

        // Only check programs that were successfully loaded and attached.
        // Programs skipped during load (unsupported kernel hooks) are not
        // included — their absence is expected, not a health failure.
        for &(prog_name, _) in LSM_PROGRAMS {
            // Skip programs that weren't loaded (no fd recorded).
            if !self.program_fds.contains_key(prog_name) {
                continue;
            }

            let loaded = self.bpf.program(prog_name).is_some();

            let attached = if let Some(&fd) = self.program_fds.get(prog_name) {
                fd >= 0 && Path::new(&format!("/proc/self/fd/{fd}")).exists()
            } else {
                false
            };

            if !loaded {
                tracing::warn!(program = prog_name, "LSM program not found in BPF object");
            } else if !attached {
                tracing::warn!(
                    program = prog_name,
                    "LSM program fd invalid — enforcement may be inactive. \
                     Restart rauhad to re-attach."
                );
            }

            statuses.push(ProgramStatus {
                name: prog_name.to_string(),
                loaded,
                attached,
            });
        }

        Ok(statuses)
    }

    /// Verify that the compiled kernel struct offsets produce correct results.
    ///
    /// Triggers a file_open event (by opening /proc/self/status) which causes
    /// the eBPF program to write both `bpf_get_current_cgroup_id()` and the
    /// offset-chain-derived cgroup_id to the SELF_TEST map. If they differ,
    /// the offsets are wrong for this kernel.
    fn verify_offset_self_test(&mut self) -> Result<()> {
        use aya::maps::Array;
        use rauha_ebpf_common::SelfTestResult;

        // Trigger file_open by opening a file. The eBPF hook will populate SELF_TEST.
        let _trigger = fs::File::open("/proc/self/status");

        // Brief sleep to let the BPF program execute.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let map =
            Array::<_, SelfTestResult>::try_from(self.bpf.map("SELF_TEST").ok_or_else(|| {
                RauhaError::EbpfError {
                    message: "SELF_TEST map not found".into(),
                    hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
                }
            })?)
            .map_err(|e| RauhaError::EbpfError {
                message: format!("failed to open SELF_TEST map: {e}"),
                hint: "check eBPF object was built correctly".into(),
            })?;

        let result = map.get(&0, 0).map_err(|e| RauhaError::EbpfError {
            message: format!("failed to read SELF_TEST map: {e}"),
            hint: "eBPF program may not have executed yet".into(),
        })?;

        if result.helper_cgroup_id == 0 && result.offset_cgroup_id == 0 {
            tracing::warn!(
                "offset self-test inconclusive — file_open hook may not have fired. \
                 Continuing with pahole validation only."
            );
            return Ok(());
        }

        if result.helper_cgroup_id != result.offset_cgroup_id {
            return Err(RauhaError::EbpfError {
                message: format!(
                    "offset self-test FAILED: bpf_get_current_cgroup_id()={} but \
                     offset chain produced {}. Compiled struct offsets are wrong \
                     for this kernel.",
                    result.helper_cgroup_id, result.offset_cgroup_id
                ),
                hint: "update offsets in rauha-ebpf/src/main.rs using \
                       `pahole -C task_struct /sys/kernel/btf/vmlinux` and rebuild"
                    .into(),
            });
        }

        // Ground truth check: verify against /proc/self/cgroup.
        // The internal check only proves the two derivation paths agree —
        // they could both be wrong the same way. Cross-check against the
        // actual cgroup_id from /proc to catch this.
        match read_proc_self_cgroup_id() {
            Ok(proc_cgroup_id) => {
                if result.helper_cgroup_id != proc_cgroup_id {
                    tracing::warn!(
                        bpf = result.helper_cgroup_id,
                        proc = proc_cgroup_id,
                        "self-test internal check passed but disagrees with /proc — \
                         offsets may be incorrect for this kernel"
                    );
                } else {
                    tracing::info!(
                        cgroup_id = result.helper_cgroup_id,
                        "offset self-test passed — verified against /proc/self/cgroup"
                    );
                }
            }
            Err(e) => {
                tracing::debug!(%e, "could not verify self-test against /proc — skipping ground truth check");
                tracing::info!(
                    cgroup_id = result.helper_cgroup_id,
                    "offset self-test passed — internal check only (proc verification unavailable)"
                );
            }
        }
        Ok(())
    }

    /// Read per-hook enforcement counters, summed across all CPUs.
    ///
    /// Returns a vec of (program_name, counters) tuples.
    pub fn read_enforcement_counters(
        &self,
    ) -> Result<Vec<(String, rauha_ebpf_common::EnforcementCounters)>> {
        use aya::maps::PerCpuArray;
        use rauha_ebpf_common::EnforcementCounters;

        let map = PerCpuArray::<_, EnforcementCounters>::try_from(
            self.bpf
                .map("ENFORCEMENT_COUNTERS")
                .ok_or_else(|| RauhaError::EbpfError {
                    message: "ENFORCEMENT_COUNTERS map not found".into(),
                    hint: "rebuild eBPF programs with `cargo xtask build-ebpf`".into(),
                })?,
        )
        .map_err(|e| RauhaError::EbpfError {
            message: format!("failed to open ENFORCEMENT_COUNTERS map: {e}"),
            hint: "check eBPF object was built correctly".into(),
        })?;

        let mut results = Vec::new();
        for (idx, &(prog_name, _)) in LSM_PROGRAMS.iter().enumerate() {
            let per_cpu = map
                .get(&(idx as u32), 0)
                .map_err(|e| RauhaError::EbpfError {
                    message: format!("failed to read counters for {prog_name}: {e}"),
                    hint: "".into(),
                })?;

            // Sum across all CPUs.
            let mut total = EnforcementCounters {
                allow: 0,
                deny: 0,
                error: 0,
            };
            for cpu_val in per_cpu.iter() {
                total.allow += cpu_val.allow;
                total.deny += cpu_val.deny;
                total.error += cpu_val.error;
            }

            results.push((prog_name.to_string(), total));
        }

        Ok(results)
    }

    /// Unpin all maps (called on clean shutdown).
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

#[derive(Debug)]
pub struct ProgramStatus {
    pub name: String,
    pub loaded: bool,
    /// Whether the link fd is valid (LSM hook attached).
    pub attached: bool,
}

fn read_compiled_offsets(ebpf_obj_path: &Path) -> Result<BTreeMap<String, u64>> {
    let sidecar = offsets_sidecar_path(ebpf_obj_path);
    let content = fs::read_to_string(&sidecar).map_err(|e| RauhaError::EbpfError {
        message: format!(
            "failed to read eBPF offsets sidecar {}: {e}",
            sidecar.display()
        ),
        hint: "run `cargo xtask build-ebpf` to regenerate the eBPF object and sidecar".into(),
    })?;

    let manifest = parse_offsets_sidecar(&content).map_err(|e| RauhaError::EbpfError {
        message: format!("invalid eBPF offsets sidecar {}: {e}", sidecar.display()),
        hint: "run `cargo xtask build-ebpf` to regenerate the sidecar".into(),
    })?;

    let actual_hash = object_sha256(ebpf_obj_path).map_err(|e| RauhaError::EbpfError {
        message: format!(
            "failed to hash eBPF object {}: {e}",
            ebpf_obj_path.display()
        ),
        hint: "check eBPF object permissions and rebuild if needed".into(),
    })?;
    if actual_hash != manifest.object_sha256 {
        return Err(RauhaError::EbpfError {
            message: format!(
                "eBPF object hash mismatch: sidecar has {} but object hashes to {}",
                manifest.object_sha256, actual_hash
            ),
            hint: "run `cargo xtask build-ebpf` to regenerate the sidecar".into(),
        });
    }

    Ok(manifest.offsets)
}

/// Check that the kernel is new enough for BPF LSM (6.1+).
fn check_kernel_version() -> Result<()> {
    let release =
        fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|e| RauhaError::EbpfError {
            message: format!("cannot read kernel version: {e}"),
            hint: "is /proc mounted?".into(),
        })?;

    let release = release.trim();
    let parts: Vec<&str> = release.split('.').collect();
    if parts.len() < 2 {
        return Err(RauhaError::KernelTooOld {
            required: "6.1".into(),
            found: release.into(),
        });
    }

    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);

    if major < 6 || (major == 6 && minor < 1) {
        return Err(RauhaError::KernelTooOld {
            required: "6.1".into(),
            found: release.into(),
        });
    }

    tracing::debug!(kernel = release, "kernel version check passed");
    Ok(())
}

/// Read the current process's cgroup_id from /proc/self/cgroup.
///
/// Parses the cgroup v2 entry (line starting with "0::"), stats the
/// corresponding directory in /sys/fs/cgroup, and returns the inode number.
/// This is the ground truth for what bpf_get_current_cgroup_id() returns.
fn read_proc_self_cgroup_id() -> std::result::Result<u64, String> {
    use std::os::unix::fs::MetadataExt;

    let content = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("failed to read /proc/self/cgroup: {e}"))?;

    for line in content.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let cgroup_dir = format!("/sys/fs/cgroup{path}");
            let meta = fs::metadata(&cgroup_dir)
                .map_err(|e| format!("failed to stat {cgroup_dir}: {e}"))?;
            return Ok(meta.ino());
        }
    }

    Err("no cgroup v2 entry found in /proc/self/cgroup".into())
}

#[cfg(test)]
mod tests {
    use super::read_compiled_offsets;
    use rauha_ebpf_common::offsets::{object_sha256, offsets_sidecar_path};

    #[test]
    fn offsets_sidecar_uses_object_file_name() {
        let path = std::path::Path::new("/tmp/rauha-ebpf");
        assert_eq!(
            offsets_sidecar_path(path),
            std::path::PathBuf::from("/tmp/rauha-ebpf.offsets")
        );
    }

    #[test]
    fn reads_compiled_offsets_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join("rauha-ebpf");
        let sidecar = dir.path().join("rauha-ebpf.offsets");
        std::fs::write(&obj, b"object").unwrap();
        let hash = object_sha256(&obj).unwrap();
        std::fs::write(
            &sidecar,
            format!(
                "# generated\nOBJECT_SHA256={hash}\nTASK_CGROUPS_OFFSET=2608\nFILE_F_INODE_OFFSET=168\n"
            ),
        )
        .unwrap();

        let offsets = read_compiled_offsets(&obj).unwrap();
        assert_eq!(offsets.get("TASK_CGROUPS_OFFSET"), Some(&2608));
        assert_eq!(offsets.get("FILE_F_INODE_OFFSET"), Some(&168));
    }

    #[test]
    fn rejects_sidecar_for_different_object() {
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join("rauha-ebpf");
        let sidecar = dir.path().join("rauha-ebpf.offsets");
        std::fs::write(&obj, b"object-a").unwrap();
        let stale_hash = object_sha256(&obj).unwrap();
        std::fs::write(&obj, b"object-b").unwrap();
        std::fs::write(
            &sidecar,
            format!("OBJECT_SHA256={stale_hash}\nTASK_CGROUPS_OFFSET=2608\n"),
        )
        .unwrap();

        assert!(read_compiled_offsets(&obj).is_err());
    }

    #[test]
    fn rejects_malformed_offsets_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let obj = dir.path().join("rauha-ebpf");
        let sidecar = dir.path().join("rauha-ebpf.offsets");
        std::fs::write(&obj, b"object").unwrap();
        std::fs::write(&sidecar, b"TASK_CGROUPS_OFFSET:not-a-kv\n").unwrap();

        assert!(read_compiled_offsets(&obj).is_err());
    }
}
