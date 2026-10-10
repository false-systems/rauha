//! socket_connect LSM hook — audit cross-zone network connections.
//!
//! AUDIT ONLY — enforcement is handled by nftables. This hook provides
//! visibility into socket-level connection attempts for observability
//! and compliance auditing. It does NOT return -EACCES.
//!
//! Future: once zone IP ranges are tracked in a BPF map, this can
//! enforce cross-zone network isolation at the socket level.

use aya_ebpf::programs::LsmContext;

use crate::{count_decision, emit_deny_event, lookup_caller_zone};
use rauha_ebpf_common::{HOOK_SOCKET_CONNECT, PROG_SOCKET_CONNECT, ZONE_FLAG_GLOBAL};

/// Called from the socket_connect LSM hook.
///
/// LSM args: socket_connect(struct socket *sock, struct sockaddr *address,
///                          int addrlen)
///
/// Returns 0 always (audit only). Emits events for zoned processes.
pub fn socket_connect(ctx: &LsmContext) -> i32 {
    let (ret, is_error) = match try_socket_connect(ctx) {
        Ok(ret) => (ret, false),
        Err(_) => {
            crate::emit_error_event(HOOK_SOCKET_CONNECT);
            (0, true)
        }
    };
    count_decision(PROG_SOCKET_CONNECT, ret == 0, is_error);
    ret
}

#[inline(always)]
fn try_socket_connect(ctx: &LsmContext) -> Result<i32, i64> {
    let caller = match lookup_caller_zone(ctx) {
        Some(info) => info,
        None => return Ok(0),
    };

    if caller.flags & ZONE_FLAG_GLOBAL != 0 {
        return Ok(0);
    }

    // Emit an audit event for every connection from a zoned process.
    // The context field carries the zone_id for correlation.
    // This is audit-only — always returns 0 (allow).
    emit_deny_event(HOOK_SOCKET_CONNECT, caller.zone_id, 0, 0);

    // AUDIT ONLY: do not deny. nftables handles actual network enforcement.
    Ok(0)
}
