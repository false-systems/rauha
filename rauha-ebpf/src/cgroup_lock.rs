//! cgroup_attach_task LSM hook — prevent zone escape.
//!
//! A task in a zone may be moved within its own zone's cgroup subtree,
//! but must not be moved to a cgroup belonging to a different zone.
//!
//! The shim enrollment flow is safe: the shim process runs unzoned
//! (inherits daemon's cgroup, not in ZONE_MEMBERSHIP), so its cgroup
//! writes to zone-{name}/cgroup.procs are allowed by the "not in a zone"
//! early return. The child blocks on the sync pipe until enrollment
//! completes, so it cannot act before cgroup assignment.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, read_kernel_u64, count_decision, emit_deny_event, offsets, ZONE_MEMBERSHIP};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_CGROUP_ATTACH, HOOK_CGROUP_ATTACH};

/// Called from the cgroup_attach_task LSM hook.
///
/// LSM args: cgroup_attach_task(struct cgroup *dst_cgrp, struct task_struct *leader)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn cgroup_attach_task(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_cgroup_attach(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            crate::emit_error_event(HOOK_CGROUP_ATTACH);
            (-1, true)
        }
    };
    count_decision(PROG_CGROUP_ATTACH, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_cgroup_attach(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → global → allow cgroup operations.
    };

    // Global zones manage other zones — they can move tasks freely.
    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Read the destination cgroup's ID.
    // arg 0 is struct cgroup *dst_cgrp.
    let dst_cgrp_ptr: u64 = unsafe { ctx.arg(0) };
    if dst_cgrp_ptr == 0 {
        return Ok(0);
    }

    // Read dst_cgrp->kn->id to get the destination cgroup_id.
    let kn_ptr = unsafe { read_kernel_u64(dst_cgrp_ptr, offsets::CGROUP_KN)? };
    if kn_ptr == 0 {
        return Ok(0);
    }
    let dst_cgroup_id = unsafe { read_kernel_u64(kn_ptr, offsets::KERNFS_NODE_ID)? };

    // Look up which zone the destination cgroup belongs to.
    let dst_zone = unsafe { ZONE_MEMBERSHIP.get(&dst_cgroup_id) };

    match dst_zone {
        Some(dst_info) => {
            // Destination is a known zone cgroup.
            // Allow if it's the same zone (within-zone subtree move).
            if caller.zone_id == dst_info.zone_id {
                Ok(0)
            } else {
                // Moving to a different zone's cgroup → zone escape. Deny.
                emit_deny_event(HOOK_CGROUP_ATTACH, caller.zone_id, dst_info.zone_id, dst_cgroup_id);
                Ok(-1)
            }
        }
        None => {
            // Destination cgroup is not in ZONE_MEMBERSHIP.
            // This could be:
            // - A cgroup outside any zone (escape attempt) → deny
            // - A child cgroup within the zone that hasn't been registered yet
            //
            // Since legitimate within-zone child cgroups are registered by the
            // daemon before use, an unregistered destination is treated as a
            // potential escape. Deny for non-global zoned processes.
            emit_deny_event(HOOK_CGROUP_ATTACH, caller.zone_id, 0, dst_cgroup_id);
            Ok(-1)
        }
    }
}
