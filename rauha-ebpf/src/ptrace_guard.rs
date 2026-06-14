//! ptrace_access_check LSM hook — deny cross-zone ptrace.
//!
//! Prevents a process in one zone from ptracing a process in another zone.
//! This is critical for isolation: ptrace can read/write memory and registers.
//!
//! Also checks ZONE_POLICY: if the caller's zone policy has
//! POLICY_FLAG_ALLOW_PTRACE set (via CAP_SYS_PTRACE in policy), ptrace is
//! allowed even cross-zone.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, check_cross_zone_task_access, count_decision, ZONE_POLICY};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, POLICY_FLAG_ALLOW_PTRACE, PROG_PTRACE_CHECK, HOOK_PTRACE_CHECK};

/// Called from the ptrace_access_check LSM hook.
///
/// LSM args: ptrace_access_check(struct task_struct *child, unsigned int mode)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn ptrace_access_check(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_ptrace_check(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            crate::emit_error_event(HOOK_PTRACE_CHECK);
            (-1, true)
        }
    };
    count_decision(PROG_PTRACE_CHECK, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_ptrace_check(ctx: &LsmContext) -> Result<i32, i64> {
    // Check zone policy first: ALLOW_PTRACE bypasses cross-zone check.
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    if let Some(policy) = unsafe { ZONE_POLICY.get(&caller.zone_id) } {
        if policy.flags & POLICY_FLAG_ALLOW_PTRACE != 0 {
            return Ok(0);
        }
    }

    // Fall through to the shared cross-zone task access check.
    check_cross_zone_task_access(ctx, HOOK_PTRACE_CHECK)
}
