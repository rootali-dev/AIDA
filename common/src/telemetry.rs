//! common/src/telemetry.rs

pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowPacketMeta {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub protocol: u8,
    pub tcp_flags: u8,
    pub timestamp_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_telemetry_size_and_alignment() {
        assert_eq!(mem::size_of::<FlowPacketMeta>(), 24);
        assert_eq!(mem::align_of::<FlowPacketMeta>(), 8);
    }
}