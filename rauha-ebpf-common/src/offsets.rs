use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

pub const OBJECT_SHA256_KEY: &str = "OBJECT_SHA256";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetDef {
    pub type_name: &'static str,
    pub field_names: &'static [&'static str],
    pub rust_const: &'static str,
    pub manifest_key: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedOffset {
    pub rust_const: &'static str,
    pub manifest_key: &'static str,
    pub offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OffsetManifest {
    pub object_sha256: String,
    pub offsets: BTreeMap<String, u64>,
}

pub const OFFSET_DEFS: &[OffsetDef] = &[
    OffsetDef {
        type_name: "task_struct",
        field_names: &["cgroups"],
        rust_const: "TASK_CGROUPS",
        manifest_key: "TASK_CGROUPS_OFFSET",
    },
    OffsetDef {
        type_name: "css_set",
        field_names: &["dfl_cgrp"],
        rust_const: "CSS_SET_DFL_CGRP",
        manifest_key: "CSS_SET_DFL_CGRP_OFFSET",
    },
    OffsetDef {
        type_name: "cgroup",
        field_names: &["kn"],
        rust_const: "CGROUP_KN",
        manifest_key: "CGROUP_KN_OFFSET",
    },
    OffsetDef {
        type_name: "kernfs_node",
        field_names: &["id"],
        rust_const: "KERNFS_NODE_ID",
        manifest_key: "KERNFS_NODE_ID_OFFSET",
    },
    OffsetDef {
        type_name: "file",
        field_names: &["f_inode"],
        rust_const: "FILE_F_INODE",
        manifest_key: "FILE_F_INODE_OFFSET",
    },
    OffsetDef {
        type_name: "inode",
        field_names: &["i_ino"],
        rust_const: "INODE_I_INO",
        manifest_key: "INODE_I_INO_OFFSET",
    },
    OffsetDef {
        type_name: "linux_binprm",
        // bprm_check_security inspects bprm->file. On newer kernels
        // bprm->executable is distinct and can be populated later.
        field_names: &["file", "executable"],
        rust_const: "BPRM_FILE",
        manifest_key: "BPRM_FILE_OFFSET",
    },
];

pub fn resolve_kernel_offsets() -> Result<Vec<ResolvedOffset>, String> {
    let pahole = which_pahole()
        .ok_or_else(|| "pahole not found; install dwarves or put pahole on PATH".to_string())?;

    let mut offsets = Vec::with_capacity(OFFSET_DEFS.len());
    for def in OFFSET_DEFS {
        let offset = pahole_field_offset_any(&pahole, def.type_name, def.field_names)?;
        offsets.push(ResolvedOffset {
            rust_const: def.rust_const,
            manifest_key: def.manifest_key,
            offset,
        });
    }
    Ok(offsets)
}

pub fn resolve_kernel_offsets_map() -> Result<BTreeMap<String, u64>, String> {
    let mut offsets = BTreeMap::new();
    for offset in resolve_kernel_offsets()? {
        offsets.insert(offset.manifest_key.to_string(), offset.offset as u64);
    }
    Ok(offsets)
}

pub fn which_pahole() -> Option<PathBuf> {
    for path in ["/usr/bin/pahole", "/usr/local/bin/pahole"] {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }

    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join("pahole");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn pahole_field_offset_any(
    pahole: &Path,
    type_name: &str,
    field_names: &[&str],
) -> Result<usize, String> {
    for field_name in field_names {
        if let Ok(offset) = pahole_field_offset(pahole, type_name, field_name) {
            return Ok(offset);
        }
    }
    Err(format!(
        "none of fields [{}] found in pahole output for '{type_name}'",
        field_names.join(", ")
    ))
}

pub fn pahole_field_offset(
    pahole: &Path,
    type_name: &str,
    field_name: &str,
) -> Result<usize, String> {
    let output = Command::new(pahole)
        .args(["-C", type_name, "/sys/kernel/btf/vmlinux"])
        .output()
        .map_err(|e| format!("failed to run {}: {e}", pahole.display()))?;

    if !output.status.success() {
        return Err(format!(
            "pahole failed for {type_name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    parse_pahole_field_offset(&String::from_utf8_lossy(&output.stdout), field_name)
}

pub fn parse_pahole_field_offset(output: &str, field_name: &str) -> Result<usize, String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let Some(comment_start) = trimmed.rfind("/*") else {
            continue;
        };
        let before_comment = trimmed[..comment_start].trim();
        let Some(declaration) = before_comment.split(';').next() else {
            continue;
        };
        let Some(identifier) = declaration.split_whitespace().last() else {
            continue;
        };
        let identifier = identifier
            .trim_start_matches('*')
            .split(':')
            .next()
            .unwrap_or(identifier);
        if identifier != field_name {
            continue;
        }

        let comment = &trimmed[comment_start + 2..];
        let Some(comment_end) = comment.find("*/") else {
            continue;
        };
        let nums = comment[..comment_end].trim();
        if let Some(offset_str) = nums.split_whitespace().next() {
            if let Ok(offset) = offset_str.parse::<usize>() {
                return Ok(offset);
            }
        }
    }

    Err(format!("field '{field_name}' not found in pahole output"))
}

pub fn object_sha256(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&data)))
}

pub fn offsets_sidecar_path(ebpf_obj_path: &Path) -> PathBuf {
    ebpf_obj_path.with_file_name(format!(
        "{}.offsets",
        ebpf_obj_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rauha-ebpf")
    ))
}

pub fn render_offsets_sidecar(object_sha256: &str, offsets: &[ResolvedOffset]) -> String {
    let mut manifest = String::from("# Generated by `cargo xtask build-ebpf`.\n");
    manifest.push_str("# key=value byte offsets compiled into the eBPF object.\n");
    manifest.push_str(&format!("{OBJECT_SHA256_KEY}={object_sha256}\n"));
    for offset in offsets {
        manifest.push_str(&format!("{}={}\n", offset.manifest_key, offset.offset));
    }
    manifest
}

pub fn parse_offsets_sidecar(content: &str) -> Result<OffsetManifest, String> {
    let mut object_sha256 = None;
    let mut offsets = BTreeMap::new();

    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| format!("invalid offsets sidecar line {}", line_no + 1))?;
        let key = key.trim();
        let value = value.trim();
        if key == OBJECT_SHA256_KEY {
            if object_sha256.replace(value.to_string()).is_some() {
                return Err(format!("duplicate {OBJECT_SHA256_KEY} in offsets sidecar"));
            }
            continue;
        }

        let offset = value
            .parse::<u64>()
            .map_err(|e| format!("invalid offset value for {key}: {e}"))?;
        if offsets.insert(key.to_string(), offset).is_some() {
            return Err(format!("duplicate offset key {key} in offsets sidecar"));
        }
    }

    let object_sha256 =
        object_sha256.ok_or_else(|| format!("missing {OBJECT_SHA256_KEY} in offsets sidecar"))?;

    Ok(OffsetManifest {
        object_sha256,
        offsets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TASK_STRUCT_SAMPLE: &str = r#"
struct task_struct {
        int                        unrelated;            /*    12     4 */
        struct css_set *           cgroups;              /*  2608     8 */
};
"#;

    const BINPRM_SAMPLE: &str = r#"
struct linux_binprm {
        struct file *              file;                 /*    40     8 */
        struct file *              executable;           /*    48     8 */
};
"#;

    #[test]
    fn parses_pahole_task_struct_field() {
        assert_eq!(
            parse_pahole_field_offset(TASK_STRUCT_SAMPLE, "cgroups"),
            Ok(2608)
        );
    }

    #[test]
    fn parses_linux_binprm_file_before_executable() {
        assert_eq!(parse_pahole_field_offset(BINPRM_SAMPLE, "file"), Ok(40));
    }

    #[test]
    fn linux_binprm_prefers_file_before_executable() {
        let def = OFFSET_DEFS
            .iter()
            .find(|def| def.manifest_key == "BPRM_FILE_OFFSET")
            .unwrap();
        assert_eq!(def.field_names, &["file", "executable"]);
    }

    #[test]
    fn sidecar_parser_rejects_duplicates() {
        let content = "OBJECT_SHA256=abc\nTASK_CGROUPS_OFFSET=1\nTASK_CGROUPS_OFFSET=2\n";
        assert!(parse_offsets_sidecar(content).is_err());
    }

    #[test]
    fn sidecar_parser_requires_object_hash() {
        let content = "TASK_CGROUPS_OFFSET=1\n";
        assert!(parse_offsets_sidecar(content).is_err());
    }

    #[test]
    fn renders_and_parses_sidecar() {
        let offsets = [ResolvedOffset {
            rust_const: "TASK_CGROUPS",
            manifest_key: "TASK_CGROUPS_OFFSET",
            offset: 2608,
        }];
        let sidecar = render_offsets_sidecar("abc123", &offsets);
        let parsed = parse_offsets_sidecar(&sidecar).unwrap();
        assert_eq!(parsed.object_sha256, "abc123");
        assert_eq!(parsed.offsets.get("TASK_CGROUPS_OFFSET"), Some(&2608));
    }
}
