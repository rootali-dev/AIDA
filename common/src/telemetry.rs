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
    pub protocol: u8,
    pub tcp_flags: u8,
    pub action: u8,
    pub drop_reason: u8,
    pub timestamp_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Action, DropReason, LogSeverity};
    use core::mem;

    #[test]
    fn test_telemetry_size_and_alignment() {
        assert_eq!(mem::size_of::<FlowPacketMeta>(), 24);
        assert_eq!(mem::align_of::<FlowPacketMeta>(), 8);

        // Verify exact byte offsets and zero padding
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, src_ip), 0);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, dst_ip), 4);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, src_port), 8);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, dst_port), 10);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, protocol), 12);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, tcp_flags), 13);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, action), 14);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, drop_reason), 15);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, timestamp_ns), 16);
    }

    #[test]
    fn test_drop_reason_severity_mapping() {
        // Pass / Clean
        assert_eq!(DropReason::None.severity(), LogSeverity::Debug);

        // 1-9: Errors
        assert_eq!(DropReason::EthParseFailed.severity(), LogSeverity::Error);
        assert_eq!(DropReason::Ipv4ParseFailed.severity(), LogSeverity::Error);
        assert_eq!(DropReason::TcpParseFailed.severity(), LogSeverity::Error);
        assert_eq!(DropReason::UdpParseFailed.severity(), LogSeverity::Error);
        assert_eq!(DropReason::ArpParseFailed.severity(), LogSeverity::Error);
        assert_eq!(DropReason::MalformedPacket.severity(), LogSeverity::Error);

        // 10-19: Warnings
        assert_eq!(DropReason::RfcLandAttack.severity(), LogSeverity::Warn);
        assert_eq!(DropReason::RfcNullScan.severity(), LogSeverity::Warn);
        assert_eq!(DropReason::RfcSynFin.severity(), LogSeverity::Warn);
        assert_eq!(DropReason::RfcXmasScan.severity(), LogSeverity::Warn);
        assert_eq!(DropReason::BlacklistHit.severity(), LogSeverity::Warn);

        // 20-29: Info
        assert_eq!(DropReason::PortBlocked.severity(), LogSeverity::Info);
        assert_eq!(DropReason::RateLimited.severity(), LogSeverity::Info);
    }

    #[test]
    fn test_action_values() {
        assert_eq!(Action::Drop as u8, 1);
        assert_eq!(Action::Pass as u8, 2);
        assert_eq!(Action::Tx as u8, 3);
        assert_eq!(Action::Redirect as u8, 4);
        assert_eq!(Action::WouldDrop as u8, 5);
    }

    #[test]
    fn test_would_drop_does_not_alter_wire_layout() {
        // Action::WouldDrop is stored in the existing 1-byte `action` field —
        // adding the variant must never perturb FlowPacketMeta's 24-byte,
        // 8-byte-aligned, zero-padding layout that the Go side's
        // UnmarshalBinary depends on byte-for-byte.
        assert_eq!(mem::size_of::<FlowPacketMeta>(), 24);
        assert_eq!(mem::align_of::<FlowPacketMeta>(), 8);
        assert_eq!(core::mem::offset_of!(FlowPacketMeta, action), 14);
    }
}