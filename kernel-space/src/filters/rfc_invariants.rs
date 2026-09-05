// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/filters/rfc_invariants.rs

use common::{tcp_flags, DropReason};

/// 6-bit control-flag mask isolating the classic TCP control bits (CWR, ECE
/// excluded) from RFC 3168 ECN signaling bits. NULL/XMAS/SYN-FIN scan
/// signatures are defined purely in terms of FIN/SYN/RST/PSH/ACK/URG;
/// masking before evaluation makes that explicit and immune to a future
/// flag-combination change, rather than relying on incidental behavior of
/// each check's own bitmask arithmetic.
const CONTROL_FLAG_MASK: u8 = 0x3F;

/// Tests whether a raw (host-endianness-dependent, as captured by
/// parsers::ipv4 without `from_be()` conversion) IPv4 address is within
/// 127.0.0.0/8. `.to_be()` normalizes the value back to network byte order
/// regardless of host architecture before masking the top octet, so this is
/// correct on both little- and big-endian targets — not just x86/aarch64.
#[inline(always)]
fn is_loopback(ip_raw: u32) -> bool {
    (ip_raw.to_be() & 0xFF00_0000) == 0x7F00_0000
}

#[inline(always)]
pub fn validate_rfc_invariants(
    src_ip: u32,
    dst_ip: u32,
    proto: u8,
    tcp_flags_val: u8,
) -> Result<(), DropReason> {
    // 1. Land Attack (identical non-zero Src and Dst IP) — exempting
    // loopback first. 127.0.0.1 -> 127.0.0.1 is completely ordinary local
    // IPC (health checks, sidecar communication, local Prometheus scrape
    // targets) and previously false-positived as a Land Attack purely
    // because src == dst, which is the loopback interface's entire purpose.
    if is_loopback(src_ip) || is_loopback(dst_ip) {
        // Loopback traffic is exempt from the identical-address heuristic
        // entirely; fall through to the TCP flag checks below, which still
        // apply (a NULL/XMAS scan against 127.0.0.1 is still a scan).
    } else if src_ip != 0 && src_ip == dst_ip {
        return Err(DropReason::RfcLandAttack);
    }

    // 2. Inspect TCP flag anomalies (only if protocol is TCP)
    if proto == 6 {
        let control_flags = tcp_flags_val & CONTROL_FLAG_MASK;

        // A) NULL Scan: all *control* flags are zero. Masking ECE/CWR first
        // means a crafted packet can't evade this check by setting a stray
        // ECN bit while leaving every real control flag at zero — and a
        // legitimate ECN-negotiated packet's CWR/ECE bits can never trip it,
        // since they're excluded from the comparison in both directions.
        if control_flags == 0 {
            return Err(DropReason::RfcNullScan);
        }

        // B) SYN + FIN Conflict: starting and terminating connection simultaneously
        if (control_flags & tcp_flags::SYN != 0) && (control_flags & tcp_flags::FIN != 0) {
            return Err(DropReason::RfcSynFin);
        }

        // C) XMAS Scan: FIN, PSH, and URG all set (evaluated against the
        // masked control flags for the same evasion-resistance reason as A).
        let xmas_mask = tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG;
        if (control_flags & xmas_mask) == xmas_mask {
            return Err(DropReason::RfcXmasScan);
        }
    }

    Ok(())
}
