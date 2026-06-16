// Fallback offsets for source checking only. Production eBPF artifacts are
// built by `cargo xtask build-ebpf`, which generates target-kernel offsets and
// writes a sidecar manifest that rauhad validates before loading.

// Verified via pahole on Linux 6.19.9 (Fedora 43).
pub const TASK_CGROUPS: usize = 3920;
pub const CSS_SET_DFL_CGRP: usize = 136;
pub const CGROUP_KN: usize = 256;
pub const KERNFS_NODE_ID: usize = 96;
pub const FILE_F_INODE: usize = 32;
pub const INODE_I_INO: usize = 64;
// linux_binprm renamed 'file' to 'executable' in recent kernels.
pub const BPRM_FILE: usize = 48;
