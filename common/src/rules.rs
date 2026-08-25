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

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Drop = 1,
    Pass = 2,
    Tx = 3,
    Redirect = 4,
    /// Dry-Run staging verdict: the enforcing policy would have issued
    /// XDP_DROP, but CONFIG_MAP[1] (DRY_RUN_MODE) was active, so the packet
    /// was actually passed. Telemetry carries this instead of `Drop` so
    /// operators can validate a new ruleset against live traffic with zero
    /// blast radius before flipping DRY_RUN_MODE back to 0 (Enforce).
    WouldDrop = 5,
}

pub type RuleAction = Action;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogSeverity {
    Off = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogSeverity {
    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => LogSeverity::Debug,
            2 => LogSeverity::Info,
            3 => LogSeverity::Warn,
            4 => LogSeverity::Error,
            _ => LogSeverity::Off,
        }
    }

    pub const fn from_u32(val: u32) -> Self {
        Self::from_u8(val as u8)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    None = 0,
    // 1-9 (ERROR): Malformed header, parse failures
    EthParseFailed = 1,
    Ipv4ParseFailed = 2,
    TcpParseFailed = 3,
    UdpParseFailed = 4,
    ArpParseFailed = 5,
    MalformedPacket = 6,

    // 10-19 (WARN): RFC violations & Blacklist
    RfcLandAttack = 10,
    RfcNullScan = 11,
    RfcSynFin = 12,
    RfcXmasScan = 13,
    BlacklistHit = 14,

    // 20-29 (INFO): Port Gate blocks, Token-bucket rate-limit drops
    PortBlocked = 20,
    RateLimited = 21,
}

impl DropReason {
    pub const fn severity(&self) -> LogSeverity {
        match *self as u8 {
            1..=9 => LogSeverity::Error,
            10..=19 => LogSeverity::Warn,
            20..=29 => LogSeverity::Info,
            _ => LogSeverity::Debug,
        }
    }

    pub const fn from_u8(val: u8) -> Self {
        match val {
            1 => DropReason::EthParseFailed,
            2 => DropReason::Ipv4ParseFailed,
            3 => DropReason::TcpParseFailed,
            4 => DropReason::UdpParseFailed,
            5 => DropReason::ArpParseFailed,
            6 => DropReason::MalformedPacket,
            10 => DropReason::RfcLandAttack,
            11 => DropReason::RfcNullScan,
            12 => DropReason::RfcSynFin,
            13 => DropReason::RfcXmasScan,
            14 => DropReason::BlacklistHit,
            20 => DropReason::PortBlocked,
            21 => DropReason::RateLimited,
            _ => DropReason::None,
        }
    }
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