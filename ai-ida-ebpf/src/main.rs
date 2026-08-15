//! ai-ida-ebpf/src/main.rs
//! ارکستراتور نهایی فایروال خط شبکه AI-IDA.

#![no_std]
#![no_main]
#![allow(dead_code)]
#![allow(unused_imports)]

mod cursor;
mod filters;
mod maps;
mod parsers;
// ادامه کدها دست‌نخورده باقی می‌ماند...

use ai_ida_common::{eth_types, ip_proto, FlowPacketMeta};
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
        Err(_) => xdp_action::XDP_DROP, // خطاهای مرزی یا پکت‌های مخرب فوراً دور ریخته می‌شوند
    }
}

#[inline(always)]
fn try_ai_ida_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let mut cursor = Cursor::new(ctx);
    let now_ns = unsafe { bpf_ktime_get_ns() };

    // ۱. پارس لایه ۲
    let l2 = parse_ethernet(&mut cursor)?;

    match l2.eth_type {
        eth_types::IPV4 => {
            // ۲. پارس لایه ۳ IPv4
            let l3 = parse_ipv4(&mut cursor)?;

            // اگر پکت قطعه دوم به بعد بود، فقط ریت‌لیمیت می‌شود
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

            // ۳. پارس لایه ۴
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

            // ۴. بررسی قوانین ساختاری RFC (Land attack, Null, Xmas, SYN-FIN)
            validate_rfc_invariants(packet.src_ip, packet.dst_ip, packet.protocol, packet.tcp_flags)?;

            // ۵. بررسی لیست سیاه در LPM_TRIE با استفاده از ساختار Key استاندارد Aya
            let lpm_key = Key::new(32, packet.src_ip);
            if let Some(action) = REPUTATION_MAP.get(&lpm_key) {
                if *action == 1 {
                    return Ok(xdp_action::XDP_DROP);
                }
            }

            // ۶. بررسی وضعیت Port Gate
            if is_port_blocked(packet.dst_port) {
                return Ok(xdp_action::XDP_DROP);
            }

            // ۷. اعمال ریت‌لیمیتر بدون قفل
            check_rate_limit(packet.src_ip, now_ns)?;

            // ۸. ارسال تله‌متری ۲۴ بایتی به رینگ‌بافر (با مشخص‌سازی صریح تایپ جنریک)
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
            // تایید سلامت ARP
            parse_arp(&mut cursor)?;
        }
        _ => {
            // سایر پروتکل‌ها با امنیت عبور داده می‌شوند
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