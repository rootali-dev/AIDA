# ماژول MOD-01: پارسر امن هدرهای شبکه (Safe Packet Parser)

- **زیرسیستم:** Ingress Fast-Path
- **زبان:** Rust (Aya eBPF)
- **اولویت:** #p0
- **وضعیت:** در حال توسعه

## شرح عملکرد
پارس کردن بدون کپی هدرهای Ethernet، IPv4، TCP و UDP به صورت مستقیم از بافر پکت کارت شبکه (Direct Packet Access).

## نیازمندی‌های سخت‌گیرانه Verifier

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
