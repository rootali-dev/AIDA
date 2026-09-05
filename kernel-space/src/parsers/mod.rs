// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/parsers/mod.rs

#![allow(unused_imports)]

pub mod arp;
pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

pub use arp::*;
pub use ethernet::*;
pub use ipv4::*;
pub use ipv6::*;
pub use tcp::*;
pub use udp::*;

pub struct ParsedPacket {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub length: u16,
    pub is_fragment: bool,
}
