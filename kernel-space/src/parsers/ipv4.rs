//! kernel-space/src/parsers/ipv4.rs

use crate::cursor::Cursor;

#[repr(C)]
pub struct Ipv4Hdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

pub struct L3Ipv4Info {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub proto: u8,
    pub total_len: u16,
    pub is_fragment: bool,
}

#[inline(always)]
pub fn parse_ipv4(cursor: &mut Cursor) -> Result<L3Ipv4Info, ()> {
    let ip = cursor.read::<Ipv4Hdr>()?;
    let version_ihl = unsafe { (*ip).version_ihl };
    let version = version_ihl >> 4;
    let ihl = (version_ihl & 0x0F) as usize;

    
    if version != 4 || ihl < 5 {
        return Err(());
    }

    let frag_off_raw = u16::from_be(unsafe { (*ip).frag_off });
    let is_fragment = (frag_off_raw & 0x3FFF) != 0;

    if ihl > 5 {
        let options_len = (ihl - 5) * 4;
        cursor.advance(options_len)?;
    }

    Ok(L3Ipv4Info {
        src_ip: unsafe { (*ip).src_addr },
        dst_ip: unsafe { (*ip).dst_addr },
        proto: unsafe { (*ip).proto },
        total_len: u16::from_be(unsafe { (*ip).tot_len }),
        is_fragment,
    })
}