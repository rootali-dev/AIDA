# Module MOD-01: Safe Packet Parser

- **Subsystem:** Ingress Fast-Path
- **Language:** Rust (Aya eBPF)
- **Priority:** `#p0`
- **Status:** In Development

---

## 1. Functional Overview

Performs zero-copy, direct packet access parsing of Ethernet, IPv4, TCP, and UDP headers directly from the network interface card (NIC) packet buffer without copying data.

---

## 2. Strict eBPF Verifier Requirements

To guarantee safety and pass the Linux kernel eBPF verifier, all memory accesses must include explicit boundary checks against `data_end`:

```rust
#[inline(always)]
unsafe fn parse_ip_hdr(ctx: &XdpContext, l3_offset: usize) -> Result<*const Ipv4Hdr, ()> {
    let data = ctx.data() as *const u8;
    let data_end = ctx.data_end() as *const u8;
    let ip_ptr = data.add(l3_offset) as *const Ipv4Hdr;

    if (ip_ptr as *const u8).add(core::mem::size_of::<Ipv4Hdr>()) > data_end {
        return Err(()); // Triggers XDP_DROP
    }
    Ok(ip_ptr)
}
```
