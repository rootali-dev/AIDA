//! ai-ida-ebpf/src/parsers/udp.rs

use crate::cursor::Cursor;

#[repr(C)]
pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub check: u16,
}

pub struct L4UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
}

#[inline(always)]
pub fn parse_udp(cursor: &mut Cursor) -> Result<L4UdpInfo, ()> {
    let udp = cursor.read::<UdpHdr>()?;
    let length = u16::from_be(unsafe { (*udp).len });

    if length < 8 {
        return Err(());
    }

    Ok(L4UdpInfo {
        src_port: u16::from_be(unsafe { (*udp).src_port }),
        dst_port: u16::from_be(unsafe { (*udp).dst_port }),
        length,
    })
}