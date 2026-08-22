//! kernel-space/src/parsers/tcp.rs

use crate::cursor::Cursor;

#[repr(C)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub offset_reserved_flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

pub struct L4TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub data_offset: usize,
}

#[inline(always)]
pub fn parse_tcp(cursor: &mut Cursor) -> Result<L4TcpInfo, ()> {
    let tcp = cursor.read::<TcpHdr>()?;
    let flags_raw = u16::from_be(unsafe { (*tcp).offset_reserved_flags });
    
    let doff = ((flags_raw >> 12) & 0x0F) as usize;
    if doff < 5 {
        return Err(());
    }

    let flags = (flags_raw & 0x00FF) as u8;

    if doff > 5 {
        let options_len = (doff - 5) * 4;
        cursor.advance(options_len)?;
    }

    Ok(L4TcpInfo {
        src_port: u16::from_be(unsafe { (*tcp).src_port }),
        dst_port: u16::from_be(unsafe { (*tcp).dst_port }),
        flags,
        data_offset: doff * 4,
    })
}