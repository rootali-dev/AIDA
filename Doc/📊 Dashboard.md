# 🛡️ AI-IDA — Intelligent Defense Architecture Dashboard

> **وضعیت پروژه:** فاز ۲ (توسعه هسته کمینه و فیلترینگ استاتیک)  
> **محیط هدف:** Linux Kernel 5.15+ | 10Gbps Line-Rate (14.88 Mpps)

---

## 🧭 دسترسی سریع به بخش‌های معماری (Navigation)
- 🏛️ **معماری پایه سیستم:** [[Core-Architecture]]
- 💾 **قرارداد باینری ۲۴ بایتی:** [[Memory-Layout-24B]]
- 🔌 **معماری Daemon و CLI:** [[Daemon-CLI-IPC]]
- 📜 **تصمیمات مهندسی (ADRs):** [[ADR-0001-Pipeline-Order]] | [[ADR-0002-LRU-Map-Type]] | [[ADR-0003-Daemon-Client]]

---

## 🎯 پیشرفت تسک‌های فاز جاری (Phase 2 MVP)

### 🔥 اولویت بحرانی (P0)
- [ ] پیاده‌سازی پارسر امن L2/L3/L4 با رعایت مرزهای Verifier در Rust ([[MOD-01-Safe-Parser]])
- [ ] ساخت مپ استاتیک پورت‌ها با `BPF_MAP_TYPE_ARRAY` ([[MOD-02-Static-ACL]])
- [ ] ساخت مپ بلک‌لیست CIDR با `BPF_MAP_TYPE_LPM_TRIE` ([[MOD-03-Reputation-Trie]])
- [ ] پیاده‌سازی استراکت ۲۴ بایتی و ارسال به `bpf_ringbuf` ([[MOD-04-RingBuf-Telemetry]])
- [ ] راه‌اندازی Daemon پس‌زمینه با قابلیت Pin کردن مپ‌ها در `/sys/fs/bpf/ai_ida` ([[MOD-05-Daemon-Core]])

### ⚡ اولویت بالا (P1)
- [ ] پیاده‌سازی CLI برای اضافه/حذف قوانین استاتیک از طریق UDS ([[MOD-06-CLI-Client]])
- [ ] ایجاد مپ `BPF_MAP_TYPE_PERCPU_ARRAY` برای آمارگیری زنده بدون سربار Lock

---

## 📊 مشخصات فنی و اهداف عملکردی (SLAs)
| شاخص | مقدار هدف | وضعیت فعلی |
| :--- | :--- | :--- |
| پردازش به ازای هر بسته در کرنل | $< 67\text{ ns}$ | تست نشده |
| نرخ فیلترینگ بسته‌های 64 بایتی | $14.88\text{ Mpps}$ | تست نشده |
| افت ترافیک RingBuffer در لایه Go | $0.0\%$ | تست نشده |