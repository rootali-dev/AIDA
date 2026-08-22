//! common/src/rules.rs

pub mod eth_types {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP: u16 = 0x0806;
    pub const VLAN_8021Q: u16 = 0x8100;
    pub const QINQ_8021AD: u16 = 0x88A8;
}

pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmIpv4Key {
    pub prefix_len: u32,
    pub addr: [u8; 4],
}

impl LpmIpv4Key {
    pub const fn new(addr: [u8; 4], prefix_len: u32) -> Self {
        Self { prefix_len, addr }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitState {
    pub last_update_ns: u64,
    pub tokens: u64,
}