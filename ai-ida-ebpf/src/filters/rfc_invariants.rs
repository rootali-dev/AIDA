//! ai-ida-ebpf/src/filters/rfc_invariants.rs

use ai_ida_common::tcp_flags;

#[inline(always)]
pub fn validate_rfc_invariants(
    src_ip: u32,
    dst_ip: u32,
    proto: u8,
    tcp_flags_val: u8,
) -> Result<(), ()> {
    // ۱. مقابله با Land Attack
    if src_ip != 0 && src_ip == dst_ip {
        return Err(());
    }

    // ۲. بررسی ناهنجاری‌های فلگ‌های TCP (فقط در صورت پروتکل TCP)
    if proto == 6 {
        // الف) حمله NULL Scan: تمام فلگ‌ها صفر است
        if tcp_flags_val == 0 {
            return Err(());
        }

        // ب) تناقض SYN + FIN: شروع و پایان همزمان اتصال
        if (tcp_flags_val & tcp_flags::SYN != 0) && (tcp_flags_val & tcp_flags::FIN != 0) {
            return Err(());
        }

        // ج) حمله XMAS Scan: فعال بودن همزمان FIN, PSH, URG
        let xmas_mask = tcp_flags::FIN | tcp_flags::PSH | tcp_flags::URG;
        if (tcp_flags_val & xmas_mask) == xmas_mask {
            return Err(());
        }
    }

    Ok(())
}