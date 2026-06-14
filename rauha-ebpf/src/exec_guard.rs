//! bprm_check_security LSM hook — deny cross-zone exec.
//!
//! Prevents a process in one zone from executing a binary that
//! belongs to a different zone.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, read_file_ino, read_kernel_u64,
            count_decision, emit_deny_event, emit_error_event, offsets, INODE_ZONE_MAP};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_BPRM_CHECK, HOOK_BPRM_CHECK};

/// Called from the bprm_check_security LSM hook.
///
/// LSM args: bprm_check_security(struct linux_binprm *bprm)
/// We need bprm->file->f_inode->i_ino.
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn bprm_check_security(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_bprm_check(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            emit_error_event(HOOK_BPRM_CHECK);
            (-1, true)
        }
    };
    count_decision(PROG_BPRM_CHECK, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // linux_binprm->file (CO-RE safe read).
    let bprm_ptr: u64 = unsafe { ctx.arg(0) };
    if bprm_ptr == 0 {
        return Ok(0);
    }

    let file_ptr = unsafe { read_kernel_u64(bprm_ptr, offsets::BPRM_FILE)? };

    // file->f_inode->i_ino
    let ino = unsafe { read_file_ino(file_ptr)? };

    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&ino) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0),
    };

    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    emit_deny_event(HOOK_BPRM_CHECK, caller.zone_id, file_zone_id, ino);
    Ok(-1)
}
