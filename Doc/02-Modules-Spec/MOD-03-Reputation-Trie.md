# ماژول MOD-03: جدول بلک‌لیست IP/Subnet (Reputation Trie)

- **زیرسیستم:** Ingress Fast-Path
- **ساختار داده:** `BPF_MAP_TYPE_LPM_TRIE`
- **اولویت:** #p0

## ساختار کلید مپ

```rust
#[repr(C)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub data: u32, // IPv4 Network Byte Order
}
```
