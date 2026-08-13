# 🏛️ معماری کلان خط لوله پردازش پکت (Core Pipeline Architecture)

معماری هسته AI-IDA بر اساس اصل **Fail-Fast** و جداسازی کامل مسیر داده (Fast Data Path) از مسیر کنترل (Control Plane) طراحی شده است.

## ۱. دیاگرام جریان پردازش بسته در کرنل (XDP Ingress)

```mermaid
graph TD
    NIC["🏁 PACKET INGRESS"] --> P["1. Safe Bounds & Header Parser (Rust)"]

    P -->|Malformed / Invalid| D1["❌ XDP_DROP"]
    P -->|Valid L3/L4| SG["2. Static Port & Protocol Gate (Array Map)"]

    SG -->|Blocked Port/Proto| D2["❌ XDP_DROP"]
    SG -->|Allowed Port| RM["3. IP/CIDR Blacklist Match (LPM_TRIE)"]

    RM -->|Match in Blacklist| D3["❌ XDP_DROP"]
    RM -->|Miss (Clean Traffic)| SMP{"4. Adaptive Sampler (1-of-N)"}

    SMP -->|Sampled| RB["📤 Push 24B to bpf_ringbuf"]
    SMP -->|Pass-through| PASS["✅ XDP_PASS (To Linux Stack)"]
    RB --> PASS
```

## ۲. مشخصات مپ‌های کرنل (eBPF Maps Spec)

### `static_port_gate`
- نوع: `BPF_MAP_TYPE_ARRAY`
- ظرفیت: ۶۵۵۳۶ مدخل (ایندکس = شماره پورت L4)
- عملکرد: ارزیابی $O(1)$ با چند نانوثانیه تاخیر.

### `reputation_trie`
- نوع: `BPF_MAP_TYPE_LPM_TRIE`
- ساختار کلید: `{ u32 prefix_len, u32 ipv4_addr }`
- عملکرد: مسدودسازی آدرس‌های IP و رنج‌های CIDR.

### `telemetry_ringbuf`
- نوع: `BPF_MAP_TYPE_RINGBUF`
- ظرفیت: چند مگابایت (تنظیم بر اساس RAM)
- عملکرد: صف بدون قفل (Lockless) برای انتقال متادیتا به یوزراسپیس.

## ۳. لینک‌های مرتبط
- مستندات ماژول‌ها: [[MOD-01-Safe-Parser]] | [[MOD-02-Static-ACL]]
- قرارداد ساختار حافظه: [[Memory-Layout-24B]]
- تصمیم معماری پایپ‌لاین: [[ADR-0001-Pipeline-Order]]
