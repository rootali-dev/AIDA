//! kernel-space/src/parsers/ipv6.rs

use crate::cursor::Cursor;

#[repr(C)]
pub struct Ipv6Hdr {
    pub v_tc_fl: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C)]
pub struct Ipv6ExtHdr {
    pub next_header: u8,
    pub hdr_ext_len: u8,
}

pub struct L3Ipv6Info {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub next_proto: u8,
    pub payload_len: u16,
}

#[inline(always)]
pub fn parse_ipv6(cursor: &mut Cursor) -> Result<L3Ipv6Info, ()> {
    let ip6 = cursor.read::<Ipv6Hdr>()?;
    let mut next_proto = unsafe { (*ip6).next_header };

    for _ in 0..4 {
        match next_proto {
            0 | 43 | 60 => {
                let ext = cursor.read::<Ipv6ExtHdr>()?;
                next_proto = unsafe { (*ext).next_header };
                let ext_len = ((unsafe { (*ext).hdr_ext_len } as usize) + 1) * 8;
                if ext_len > 2 {
                    cursor.advance(ext_len - 2)?;
                }
            }
            44 => {
                let ext = cursor.read::<Ipv6ExtHdr>()?;
                next_proto = unsafe { (*ext).next_header };
                cursor.advance(6)?;
            }
            _ => break,
        }
    }

    Ok(L3Ipv6Info {
        src_ip: unsafe { (*ip6).src_addr },
        dst_ip: unsafe { (*ip6).dst_addr },
        next_proto,
        payload_len: u16::from_be(unsafe { (*ip6).payload_len }),
    })
}