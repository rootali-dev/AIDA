//! ai-ida-ebpf/src/parsers/arp.rs

use crate::cursor::Cursor;

#[repr(C)]
pub struct ArpHdr {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: u32,
    pub target_mac: [u8; 6],
    pub target_ip: u32,
}

#[inline(always)]
pub fn parse_arp(cursor: &mut Cursor) -> Result<&ArpHdr, ()> {
    let arp = cursor.read::<ArpHdr>()?;
    let htype = u16::from_be(unsafe { (*arp).htype });
    let ptype = u16::from_be(unsafe { (*arp).ptype });
    let hlen = unsafe { (*arp).hlen };
    let plen = unsafe { (*arp).plen };

    // بررسی سلامت فرمت اترنت و IPv4
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
        return Err(());
    }

    Ok(unsafe { &*arp })
}