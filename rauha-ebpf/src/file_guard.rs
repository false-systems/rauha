//! file_open LSM hook — deny cross-zone file access.
//!
//! When a process opens a file, check if the file's inode belongs to a
//! different zone. If so, deny unless the zones are allowed to communicate.
//!
//! Also triggers the one-shot offset self-test on first invocation.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, is_cross_zone_allowed, read_file_ino, maybe_run_self_test,
            count_decision, emit_deny_event, emit_error_event, INODE_ZONE_MAP};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_FILE_OPEN, HOOK_FILE_OPEN};

/// Called from the file_open LSM hook.
///
/// LSM args: file_open(struct file *file)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn file_open(ctx: &LsmContext) -> i32 {
    // One-shot self-test: validates offset chain on first file_open after load.
    unsafe { maybe_run_self_test() };

    let (ret, is_error) = match try_file_open(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            emit_error_event(HOOK_FILE_OPEN);
            (-1, true)
        }
    };
    count_decision(PROG_FILE_OPEN, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → global → allow.
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Read the file's inode number via CO-RE safe helpers.
    let file_ptr: u64 = unsafe { ctx.arg(0) };
    let ino = unsafe { read_file_ino(file_ptr)? };

    // Look up which zone owns this inode.
    let file_zone_id = match unsafe { INODE_ZONE_MAP.get(&ino) } {
        Some(&zone_id) => zone_id,
        None => return Ok(0), // Untracked inode → allow.
    };

    if caller.zone_id == file_zone_id {
        return Ok(0);
    }

    if is_cross_zone_allowed(caller.zone_id, file_zone_id) {
        return Ok(0);
    }

    emit_deny_event(HOOK_FILE_OPEN, caller.zone_id, file_zone_id, ino);
    Ok(-1)
}
