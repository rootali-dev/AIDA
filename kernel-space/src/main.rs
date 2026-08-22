//! kernel-space/src/main.rs

#![no_std]
#![no_main]
#![allow(dead_code)]
#![allow(unused_imports)]

mod cursor;
mod filters;
mod maps;
mod parsers;

use common::{eth_types, ip_proto, FlowPacketMeta};
use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::xdp,
    maps::lpm_trie::Key,
    programs::XdpContext,
};

use cursor::Cursor;
use filters::{check_rate_limit, is_port_blocked, validate_rfc_invariants};
use maps::{EVENTS, REPUTATION_MAP};
use parsers::{parse_arp, parse_ethernet, parse_ipv4, parse_tcp, parse_udp, ParsedPacket};

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

    // 1. parsing Ethernet header and optional VLAN tags (up to 2)
    let l2 = parse_ethernet(&mut cursor)?;

    match l2.eth_type {
        eth_types::IPV4 => {
            // 2. parsing IPv4 header and checking for fragmentation
            let l3 = parse_ipv4(&mut cursor)?;

            // if the packet is a fragment, we only check the rate limit and pass it to the kernel stack
            if l3.is_fragment {
                check_rate_limit(l3.src_ip, now_ns)?;
                return Ok(xdp_action::XDP_PASS);
            }

            let mut packet = ParsedPacket {
                src_ip: l3.src_ip,
                dst_ip: l3.dst_ip,
                src_port: 0,
                dst_port: 0,
                protocol: l3.proto,
                tcp_flags: 0,
                length: l3.total_len,
                is_fragment: false,
            };

            // 3. parsing Layer 4 header
            match l3.proto {
                ip_proto::TCP => {
                    let tcp = parse_tcp(&mut cursor)?;
                    packet.src_port = tcp.src_port;
                    packet.dst_port = tcp.dst_port;
                    packet.tcp_flags = tcp.flags;
                }
                ip_proto::UDP => {
                    let udp = parse_udp(&mut cursor)?;
                    packet.src_port = udp.src_port;
                    packet.dst_port = udp.dst_port;
                }
                _ => {}
            }

            // 4. checking RFC structural rules (Land attack, Null, Xmas, SYN-FIN)
            validate_rfc_invariants(packet.src_ip, packet.dst_ip, packet.protocol, packet.tcp_flags)?;

            // 5. checking blacklist in LPM_TRIE using the standard Aya Key structure
            let lpm_key = LpmIpv4Key::new(packet.src_ip, 32);
            if let Some(action) = REPUTATION_MAP.get(&lpm_key) {
                if *action == 1 {
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // 5. Checking Port Gate
            if is_port_blocked(packet.dst_port) {
                return Ok(xdp_action::XDP_DROP);
            }

            // 7. aplaying lockless rate-limiting using LRU_PERCPU_HASH map
            check_rate_limit(packet.src_ip, now_ns)?;

            // 8. sending telemetry data (24 bytes) to the ring buffer (with explicit generic type specification)
            let meta = FlowPacketMeta {
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                length: packet.length,
                protocol: packet.protocol,
                tcp_flags: packet.tcp_flags,
                timestamp_ns: now_ns,
            };

            let _ = EVENTS.output::<FlowPacketMeta>(&meta, 0);
        }
        eth_types::ARP => {
            // Check health ARP
            parse_arp(&mut cursor)?;
        }
        _ => {
            // other packets are passed to the kernel stack for further processing
            return Ok(xdp_action::XDP_PASS);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}