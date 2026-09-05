// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/main.rs

#![no_std]
#![no_main]
#![allow(dead_code)]
#![allow(unused_imports)]

mod cursor;
mod filters;
mod maps;
mod parsers;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::xdp,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use common::{eth_types, ip_proto, Action, DropReason, FlowPacketMeta};

use cursor::Cursor;
use filters::{check_rate_limit, is_port_blocked, validate_rfc_invariants};
use maps::{CONFIG_MAP, EVENTS, LOG_RATE_LIMIT_MAP, REPUTATION_MAP};
use parsers::{parse_arp, parse_ethernet, parse_ipv4, parse_tcp, parse_udp, ParsedPacket};

const LOG_NANOS_PER_TOKEN: u64 = 100_000; // 1 token per 100 µs (10,000 logs/sec sustained)
const LOG_BURST_CAPACITY: u64 = 1_000;    // Up to 1,000 logs burst

#[inline(always)]
fn check_log_rate_limit(now_ns: u64) -> bool {
    if let Some(state_ptr) = LOG_RATE_LIMIT_MAP.get_ptr_mut(0) {
        let state = unsafe { &mut *state_ptr };

        let elapsed = now_ns.saturating_sub(state.last_update_ns);
        let new_tokens = elapsed / LOG_NANOS_PER_TOKEN;

        if new_tokens > 0 {
            state.tokens = (state.tokens + new_tokens).min(LOG_BURST_CAPACITY);
            state.last_update_ns = now_ns;
        }

        if state.tokens >= 1 {
            state.tokens -= 1;
            true
        } else {
            false
        }
    } else {
        true
    }
}

#[inline(always)]
fn emit_and_return(
    action: u32,
    drop_reason: DropReason,
    mut meta: FlowPacketMeta,
    now_ns: u64,
) -> Result<u32, ()> {
    // 0. Dry-Run staging override: CONFIG_MAP[1] (0 = Enforce, 1 = Dry-Run).
    // Any would-be XDP_DROP verdict is downgraded to XDP_PASS at the wire,
    // but telemetry still records Action::WouldDrop with the real
    // drop_reason, so a new ruleset can be validated against live traffic
    // with zero blast radius before flipping back to Enforce. This does NOT
    // change which check fires first or short-circuit the single-exit
    // pipeline — it only changes the verdict emitted at the point a verdict
    // was already about to be returned.
    let dry_run = matches!(CONFIG_MAP.get(1), Some(val) if *val == 1);

    let (effective_action, telemetry_action) = if action == xdp_action::XDP_DROP {
        if dry_run {
            (xdp_action::XDP_PASS, Action::WouldDrop)
        } else {
            (xdp_action::XDP_DROP, Action::Drop)
        }
    } else {
        (action, Action::Pass)
    };

    // 1. Fast-path check: CONFIG_MAP threshold
    let threshold = match CONFIG_MAP.get(0) {
        Some(val) => *val,
        None => 0,
    };

    // If threshold is 0 (OFF), bypass immediately without telemetry
    if threshold == 0 {
        return Ok(effective_action);
    }

    let severity = drop_reason.severity() as u32;
    // If event severity is below the threshold, skip logging
    if severity < threshold {
        return Ok(effective_action);
    }

    // 2. RingBuffer drop-storm protection: log rate-limiter
    if !check_log_rate_limit(now_ns) {
        return Ok(effective_action);
    }

    // 3. Finalize metadata fields
    meta.action = telemetry_action as u8;
    meta.drop_reason = drop_reason as u8;
    meta.timestamp_ns = now_ns;

    // 4. Single centralized emission to RingBuffer
    let _ = EVENTS.output::<FlowPacketMeta>(&meta, 0);

    Ok(effective_action)
}

#[xdp]
pub fn ai_ida_firewall(ctx: XdpContext) -> u32 {
    match try_ai_ida_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_DROP,
    }
}

#[inline(always)]
fn try_ai_ida_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let mut cursor = Cursor::new(ctx);
    let now_ns = unsafe { bpf_ktime_get_ns() };

    let mut meta = FlowPacketMeta {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        tcp_flags: 0,
        action: Action::Pass as u8,
        drop_reason: DropReason::None as u8,
        timestamp_ns: now_ns,
    };

    // 1. Parsing Ethernet header and optional VLAN tags
    let l2 = match parse_ethernet(&mut cursor) {
        Ok(l2) => l2,
        Err(_) => {
            return emit_and_return(xdp_action::XDP_DROP, DropReason::EthParseFailed, meta, now_ns);
        }
    };

    match l2.eth_type {
        eth_types::IPV4 => {
            // 2. Parsing IPv4 header
            let l3 = match parse_ipv4(&mut cursor) {
                Ok(l3) => l3,
                Err(_) => {
                    return emit_and_return(xdp_action::XDP_DROP, DropReason::Ipv4ParseFailed, meta, now_ns);
                }
            };

            meta.src_ip = l3.src_ip;
            meta.dst_ip = l3.dst_ip;
            meta.protocol = l3.proto;

            // Handle fragments: rate limit check then pass to stack
            if l3.is_fragment {
                if check_rate_limit(l3.src_ip, now_ns).is_err() {
                    return emit_and_return(xdp_action::XDP_DROP, DropReason::RateLimited, meta, now_ns);
                }
                return emit_and_return(xdp_action::XDP_PASS, DropReason::None, meta, now_ns);
            }

            // 3. Parsing Layer 4 header
            match l3.proto {
                ip_proto::TCP => {
                    let tcp = match parse_tcp(&mut cursor) {
                        Ok(tcp) => tcp,
                        Err(_) => {
                            return emit_and_return(xdp_action::XDP_DROP, DropReason::TcpParseFailed, meta, now_ns);
                        }
                    };
                    meta.src_port = tcp.src_port;
                    meta.dst_port = tcp.dst_port;
                    meta.tcp_flags = tcp.flags;
                }
                ip_proto::UDP => {
                    let udp = match parse_udp(&mut cursor) {
                        Ok(udp) => udp,
                        Err(_) => {
                            return emit_and_return(xdp_action::XDP_DROP, DropReason::UdpParseFailed, meta, now_ns);
                        }
                    };
                    meta.src_port = udp.src_port;
                    meta.dst_port = udp.dst_port;
                }
                _ => {}
            }

            // 4. Checking RFC structural rules (Land attack, NULL, Xmas, SYN-FIN)
            if let Err(rfc_reason) = validate_rfc_invariants(meta.src_ip, meta.dst_ip, meta.protocol, meta.tcp_flags) {
                return emit_and_return(xdp_action::XDP_DROP, rfc_reason, meta, now_ns);
            }

            // 5. Checking blacklist in LPM_TRIE
            let lpm_key = Key::new(32, meta.src_ip);
            if let Some(action) = REPUTATION_MAP.get(&lpm_key) {
                if *action == 1 {
                    return emit_and_return(xdp_action::XDP_DROP, DropReason::BlacklistHit, meta, now_ns);
                }
            }

            // 6. Checking Port Gate (direction-aware: only new inbound SYN
            // requests / non-ephemeral UDP are subject to gating — see
            // filters::port_gate for the ACK/ephemeral-port exemptions)
            if is_port_blocked(meta.protocol, meta.dst_port, meta.tcp_flags) {
                return emit_and_return(xdp_action::XDP_DROP, DropReason::PortBlocked, meta, now_ns);
            }

            // 7. Applying lockless rate-limiting using LRU_PERCPU_HASH map
            if check_rate_limit(meta.src_ip, now_ns).is_err() {
                return emit_and_return(xdp_action::XDP_DROP, DropReason::RateLimited, meta, now_ns);
            }

            // 8. Normal clean pass
            emit_and_return(xdp_action::XDP_PASS, DropReason::None, meta, now_ns)
        }
        eth_types::ARP => {
            // Check health ARP
            match parse_arp(&mut cursor) {
                Ok(_) => emit_and_return(xdp_action::XDP_PASS, DropReason::None, meta, now_ns),
                Err(_) => emit_and_return(xdp_action::XDP_DROP, DropReason::ArpParseFailed, meta, now_ns),
            }
        }
        _ => {
            // Other packets are passed to kernel stack
            emit_and_return(xdp_action::XDP_PASS, DropReason::None, meta, now_ns)
        }
    }
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
