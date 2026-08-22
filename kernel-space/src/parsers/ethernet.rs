//! kernel-space/src/parsers/ethernet.rs

use crate::cursor::Cursor;
use common::eth_types;

#[repr(C)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub proto: u16,
}

#[repr(C)]
pub struct VlanHdr {
    pub tci: u16,
    pub next_proto: u16,
}

pub struct L2Info {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub eth_type: u16,
}

#[inline(always)]
pub fn parse_ethernet(cursor: &mut Cursor) -> Result<L2Info, ()> {
    let eth = cursor.read::<EthHdr>()?;
    let mut eth_type = u16::from_be(unsafe { (*eth).proto });

    for _ in 0..2 {
        if eth_type == eth_types::VLAN_8021Q || eth_type == eth_types::QINQ_8021AD {
            let vlan = cursor.read::<VlanHdr>()?;
            eth_type = u16::from_be(unsafe { (*vlan).next_proto });
        } else {
            break;
        }
    }

    Ok(L2Info {
        src_mac: unsafe { (*eth).src_mac },
        dst_mac: unsafe { (*eth).dst_mac },
        eth_type,
    })
}