# Module MOD-03: IP/Subnet Blacklist (Reputation Trie)

- **Subsystem:** Ingress Fast-Path
- **Data Structure:** `BPF_MAP_TYPE_LPM_TRIE`
- **Priority:** `#p0`

---

## 1. Map Key Structure

```rust
#[repr(C)]
pub struct LpmKey {
    pub prefixlen: u32,
    pub data: u32, // IPv4 Network Byte Order
}
```

---

## 2. Functional Description

Provides fast Longest Prefix Match (LPM) filtering against reputation-based blocklists, allowing exact IP matches as well as arbitrary CIDR subnet blocks to be dropped immediately in the kernel XDP layer.
