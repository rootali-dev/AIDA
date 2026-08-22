# Module MOD-02: Static ACL Port Gate

- **Subsystem:** Ingress Fast-Path
- **Data Structure:** `BPF_MAP_TYPE_ARRAY`
- **Priority:** `#p0`

---

## 1. Map Specifications

- **Size / Capacity:** 65,536 entries (covers the entire 16-bit L4 port space).
- **Value Type:** `u8` (`0` = DROP, `1` = PASS / ALLOW).
- **Lookup Complexity:** $O(1)$ direct array index lookup with zero hashing overhead.
