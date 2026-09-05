// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/filters/port_gate.rs

use crate::maps::PORT_GATE_MAP;
use common::{ip_proto, tcp_flags};

/// Direction-aware port gate.
///
/// The naive version of this check (`dst_port` alone) is a false-positive
/// factory: it blocks *any* packet destined for a gated port, including the
/// ephemeral-port return leg of an outbound connection *we* initiated (e.g.
/// a local client's `-> remote:443` request comes back as `remote:443 ->
/// local:<ephemeral>` — if that ephemeral port happens to be gated, or the
/// operator gates 443 thinking "inbound HTTPS", legitimate replies die).
///
/// Correct semantics: PORT_GATE_MAP encodes policy for *inbound connection
/// attempts to locally-listening services*, not for reply traffic. So:
///   - TCP: only gate a fresh connection attempt — SYN set, ACK clear. Any
///     packet carrying ACK (established-connection data, or a reply leg) is
///     definitionally not a new inbound request and bypasses the gate.
///   - UDP: has no connection-state flags to inspect, so ephemeral client
///     ports (>= 32768, the common Linux `ip_local_port_range` floor) are
///     treated as reply/return traffic and exempted outright, mirroring the
///     TCP ACK exemption in spirit.
///   - Everything else (ICMP, etc.) is unaffected by PORT_GATE_MAP, which is
///     an L4-port concept.
#[inline(always)]
pub fn is_port_blocked(protocol: u8, dst_port: u16, flags: u8) -> bool {
    if dst_port == 0 {
        return false;
    }

    match protocol {
        ip_proto::TCP => {
            let is_new_inbound_request = (flags & tcp_flags::SYN != 0) && (flags & tcp_flags::ACK == 0);
            if !is_new_inbound_request {
                // Established traffic, replies, and control packets (FIN/RST
                // on a connection we already permitted) all carry ACK (or
                // aren't SYN at all) — never subject to the inbound gate.
                return false;
            }
        }
        ip_proto::UDP => {
            if dst_port >= 32_768 {
                // Ephemeral client range: presumed reply traffic to a
                // locally-initiated request, never a request *to* a
                // listening service on this host.
                return false;
            }
        }
        _ => return false,
    }

    if let Some(status) = PORT_GATE_MAP.get(dst_port as u32) {
        if *status == 2 {
            return true;
        }
    }

    false
}
