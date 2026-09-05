// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/parsers/arp.rs

use crate::cursor::Cursor;

#[repr(C, packed)]
pub struct ArpHdr {
    pub htype: u16, // Hardware Type (Ethernet = 1)
    pub ptype: u16, // Protocol Type (IPv4 = 0x0800)
    pub hlen: u8,   // Hardware Addr Length = 6
    pub plen: u8,   // Protocol Addr Length = 4
    pub oper: u16,  // Operation (1 = Request, 2 = Reply)
}

#[inline(always)]
pub fn parse_arp(cursor: &mut Cursor) -> Result<(), ()> {
    let arp_hdr = match cursor.read::<ArpHdr>() {
        Ok(ptr) => unsafe { &*ptr },
        Err(_) => return Err(()),
    };

    // تبدیل صریح از Network Byte Order (Big Endian) به پردازنده
    let htype = u16::from_be(arp_hdr.htype);
    let ptype = u16::from_be(arp_hdr.ptype);

    // بررسی سلامت طبق RFC 826
    if htype != 1 || ptype != 0x0800 || arp_hdr.hlen != 6 || arp_hdr.plen != 4 {
        return Err(());
    }

    // عبور از بایت‌های آدرس‌های مک و آی‌پی فرستنده و گیرنده (20 بایت باقی‌مانده)
    cursor.advance(20)?;

    Ok(())
}
