//! ai-ida-ebpf/src/filters/port_gate.rs

use crate::maps::PORT_GATE_MAP;

#[inline(always)]
pub fn is_port_blocked(dst_port: u16) -> bool {
    if dst_port == 0 {
        return false;
    }

    if let Some(status) = PORT_GATE_MAP.get(dst_port as u32) {
        // مقدار 2 یعنی پورت به طور قطعی مسدود شده است
        if *status == 2 {
            return true;
        }
    }

    false
}