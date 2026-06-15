//! task_kill LSM hook — deny cross-zone signals.
//!
//! Prevents a process in one zone from sending signals (kill, SIGTERM, etc.)
//! to processes in other zones.

use aya_ebpf::programs::LsmContext;

use crate::{check_cross_zone_task_access, count_decision};
use rauha_ebpf_common::{PROG_TASK_KILL, HOOK_TASK_KILL};

/// Called from the task_kill LSM hook.
///
/// LSM args: task_kill(struct task_struct *p, struct kernel_siginfo *info,
///                     int sig, const struct cred *cred)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn task_kill(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match check_cross_zone_task_access(ctx, HOOK_TASK_KILL) {
        Ok(ret) => (ret, false),
        Err(_) => {
            crate::emit_error_event(HOOK_TASK_KILL);
            (-1, true)
        }
    };
    count_decision(PROG_TASK_KILL, ret == 0, is_error);
    ret
}
