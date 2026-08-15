//! ai-ida-common/src/telemetry.rs
//! ساختار فشرده تله‌متری ارسالی به کنترل‌پلن Go از طریق BPF Ring Buffer.

/// ثابت‌های بیت‌ماسک برای فلگ‌های هدر TCP
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

/// متادیتای فوق فشرده ۲۴ بایتی جریان پکت (Flow Telemetry Metadata)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowPacketMeta {
    /// آدرس IPv4 مبدا در حالت Network Byte Order
    pub src_ip: u32,
    /// آدرس IPv4 مقصد در حالت Network Byte Order
    pub dst_ip: u32,
    /// پورت مبدا لایه ۴ (TCP/UDP)
    pub src_port: u16,
    /// پورت مقصد لایه ۴ (TCP/UDP)
    pub dst_port: u16,
    /// طول کل پکت (بر حسب بایت)
    pub length: u16,
    /// پروتکل لایه ۳ (IPPROTO_TCP = 6, IPPROTO_UDP = 17, ...)
    pub protocol: u8,
    /// فلگ‌های TCP (در صورت پروتکل TCP، در غیر این صورت 0)
    pub tcp_flags: u8,
    /// برچسب زمانی کرنل با دقت نانوثانیه (از bpf_ktime_get_ns)
    pub timestamp_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_telemetry_size_and_alignment() {
        // تضمین ریاضی اینکه اندازه استراکت دقیقا ۲۴ بایت است
        assert_eq!(mem::size_of::<FlowPacketMeta>(), 24);
        // تضمین تراز ۸ بایتی برای انتقال بدون سربار در معماری‌های x86_64 و ARM64
        assert_eq!(mem::align_of::<FlowPacketMeta>(), 8);
    }
}