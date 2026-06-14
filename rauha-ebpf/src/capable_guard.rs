//! capable LSM hook — enforce capability checks against zone policy.
//!
//! Prevents processes in non-global zones from using capabilities not
//! explicitly permitted in their zone's ZONE_POLICY.caps_mask.
//!
//! This closes the privilege escalation gap: without this hook, a process
//! in a restricted zone could call setuid(0) or load kernel modules if the
//! capability was available in the namespace.

use aya_ebpf::programs::LsmContext;

use crate::{lookup_caller_zone, count_decision, emit_deny_event, ZONE_POLICY};
use rauha_ebpf_common::{ZONE_FLAG_GLOBAL, PROG_CAPABLE, HOOK_CAPABLE};

/// Called from the capable LSM hook.
///
/// LSM args: capable(const struct cred *cred, struct user_namespace *ns,
///                   int cap, unsigned int opts)
///
/// Returns 0 to allow, -1 (EPERM) to deny.
pub fn capable(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_capable(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            crate::emit_error_event(HOOK_CAPABLE);
            (-1, true)
        }
    };
    count_decision(PROG_CAPABLE, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_capable(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0), // Not in a zone → allow.
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // arg(2) is the capability number (int cap).
    let cap: i32 = unsafe { ctx.arg(2) };
    if cap < 0 || cap > 63 {
        emit_deny_event(HOOK_CAPABLE, caller.zone_id, 0, cap as u64);
        return Ok(-1);
    }

    // Check if this capability is permitted by the zone's policy.
    let policy = match unsafe { ZONE_POLICY.get(&caller.zone_id) } {
        Some(p) => p,
        None => {
            emit_deny_event(HOOK_CAPABLE, caller.zone_id, 0, cap as u64);
            return Ok(-1);
        }
    };

    // caps_mask == 0 means the policy has no [capabilities] section, i.e. it
    // opts out of capability restriction. Treat as unrestricted (allow): the
    // explicit allowlist is opt-in. Denying every capability for such a zone
    // would break routine kernel capable() checks (CAP_DAC_OVERRIDE,
    // CAP_SETUID, ...) and make any policy without a [capabilities] block
    // unusable. The error path above still fails closed.
    if policy.caps_mask == 0 {
        return Ok(0);
    }

    let cap_bit = 1u64 << (cap as u64);
    if policy.caps_mask & cap_bit != 0 {
        return Ok(0); // Capability explicitly permitted.
    }

    // Capability not in allowed set — deny.
    emit_deny_event(HOOK_CAPABLE, caller.zone_id, 0, cap as u64);
    Ok(-1)
}
