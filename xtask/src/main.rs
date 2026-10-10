use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use rauha_ebpf_common::offsets::{
    object_sha256, offsets_sidecar_path, render_offsets_sidecar, resolve_kernel_offsets,
    ResolvedOffset,
};

mod checks;
mod gate;
mod probes;

#[derive(Parser)]
#[allow(clippy::enum_variant_names)] // Keep the established `build-*` CLI names.
enum Cli {
    /// Run a privileged integration scenario against RAUHA_ADDR.
    Integration { name: String },
    /// Build and run all privileged Linux security gates (or select a Lima VM).
    Security,
    /// Linux-only privileged gate, including workspace quality checks.
    LinuxGate,
    #[clap(hide = true)]
    GateRuntime {
        #[clap(long)]
        containerd_only: bool,
        output_test: PathBuf,
        oracle_test: PathBuf,
        oci_test: PathBuf,
        containerd_test: PathBuf,
    },
    #[clap(hide = true)]
    GateRuntimeInner {
        #[clap(long)]
        containerd_only: bool,
        output_test: PathBuf,
        oracle_test: PathBuf,
        oci_test: PathBuf,
        containerd_test: PathBuf,
    },
    /// Prepare or verify a workload across a daemon crash.
    Recovery { phase: String, state: PathBuf },
    /// Verify the crun create/enroll/start handoff.
    OciProbe,
    /// Measure the installed crun Wasm handler.
    WasmProbe,
    /// Run an isolated end-to-end demonstration.
    Demo,
    #[clap(hide = true)]
    CgroupHelper { target: PathBuf },
    #[clap(hide = true)]
    FileOpenHelper {
        cgroup: PathBuf,
        own: PathBuf,
        foreign: PathBuf,
    },
    #[clap(hide = true)]
    OracleProxy { executable: PathBuf },
    /// Build the eBPF programs for rauha-ebpf.
    BuildEbpf {
        /// Build in release mode.
        #[clap(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::Integration { name } => checks::run(&name),
        Cli::Security => gate::dispatch(),
        Cli::LinuxGate => gate::run(),
        Cli::GateRuntime {
            containerd_only,
            output_test,
            oracle_test,
            oci_test,
            containerd_test,
        } => gate::isolated_runtime(
            &output_test,
            &oracle_test,
            &oci_test,
            &containerd_test,
            containerd_only,
        ),
        Cli::GateRuntimeInner {
            containerd_only,
            output_test,
            oracle_test,
            oci_test,
            containerd_test,
        } => gate::runtime(
            &output_test,
            &oracle_test,
            &oci_test,
            &containerd_test,
            containerd_only,
        ),
        Cli::Recovery { phase, state } => probes::recovery(&phase, &state),
        Cli::OciProbe => probes::oci(),
        Cli::WasmProbe => probes::wasm(),
        Cli::Demo => gate::demo(),
        Cli::CgroupHelper { target } => checks::cgroup_helper(&target),
        Cli::FileOpenHelper {
            cgroup,
            own,
            foreign,
        } => checks::file_open_helper(&cgroup, &own, &foreign),
        Cli::OracleProxy { executable } => gate::oracle_proxy(&executable),
        Cli::BuildEbpf { release } => build_ebpf(release),
    }
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask is in project root")
        .to_path_buf()
}

fn target_dir(root: &Path, configured: Option<&OsStr>, fallback: PathBuf) -> PathBuf {
    match configured.map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => root.join(path),
        None => fallback,
    }
}

fn configured_target_dir(root: &Path, fallback: PathBuf) -> PathBuf {
    let configured = std::env::var_os("CARGO_TARGET_DIR");
    target_dir(root, configured.as_deref(), fallback)
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = project_root();
    let ebpf_dir = root.join("rauha-ebpf");

    if !ebpf_dir.exists() {
        bail!(
            "rauha-ebpf directory not found at {}. Create it first.",
            ebpf_dir.display()
        );
    }

    let ebpf_target = configured_target_dir(&root, ebpf_dir.join("target"));
    let generated_offsets = generate_ebpf_offsets(&root)?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("CARGO_TARGET_DIR", &ebpf_target)
        .env("RAUHA_EBPF_OFFSETS", &generated_offsets.source_path)
        // Disable UB checks — the alignment panic intrinsics they emit
        // produce .text.unlikely. functions that the BPF verifier rejects.
        .env("RUSTFLAGS", "-Zub-checks=no -Dwarnings")
        .args([
            "+nightly",
            "build",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--features",
            "generated-offsets",
        ]);

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("failed to run cargo build for eBPF")?;
    if !status.success() {
        bail!("eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let artifact = ebpf_target
        .join("bpfel-unknown-none")
        .join(profile)
        .join("rauha-ebpf");

    let sidecar = write_offsets_sidecar(&artifact, &generated_offsets.offsets)?;

    println!("eBPF object built: {}", artifact.display());
    println!("eBPF offsets sidecar: {}", sidecar.display());
    Ok(())
}

struct GeneratedOffsets {
    source_path: PathBuf,
    offsets: Vec<ResolvedOffset>,
}

fn generate_ebpf_offsets(root: &Path) -> Result<GeneratedOffsets> {
    let btf = Path::new("/sys/kernel/btf/vmlinux");
    if !btf.exists() {
        bail!("cannot build production eBPF object: /sys/kernel/btf/vmlinux is missing");
    }

    let offsets = resolve_kernel_offsets().map_err(anyhow::Error::msg)?;

    let out_dir = configured_target_dir(root, root.join("target")).join("rauha-ebpf-generated");
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    let source_path = out_dir.join("offsets.rs");

    let mut source =
        String::from("// Generated by `cargo xtask build-ebpf` from /sys/kernel/btf/vmlinux.\n");
    source.push_str("// Do not edit by hand.\n\n");
    for offset in &offsets {
        source.push_str(&format!(
            "pub const {}: usize = {};\n",
            offset.rust_const, offset.offset
        ));
    }

    fs::write(&source_path, source)
        .with_context(|| format!("failed to write {}", source_path.display()))?;

    Ok(GeneratedOffsets {
        source_path,
        offsets,
    })
}

fn write_offsets_sidecar(artifact: &Path, offsets: &[ResolvedOffset]) -> Result<PathBuf> {
    let sidecar = offsets_sidecar_path(artifact);
    let object_hash = object_sha256(artifact).map_err(anyhow::Error::msg)?;
    let manifest = render_offsets_sidecar(&object_hash, offsets);

    fs::write(&sidecar, manifest)
        .with_context(|| format!("failed to write {}", sidecar.display()))?;
    Ok(sidecar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_target_dir_is_resolved_from_project_root() {
        assert_eq!(
            target_dir(
                Path::new("/repo"),
                Some(OsStr::new("cache")),
                PathBuf::from("unused")
            ),
            PathBuf::from("/repo/cache")
        );
    }
}
