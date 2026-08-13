# 🎯 مدیریت و رهگیری تسک‌های توسعه (Task Tracker)

## 🔴 اولویت P0 — هسته و خط داده پایه (Data Path MVP)
- [ ] [DP-01] پیاده‌سازی پارسر امن در `core-xdp/src/main.rs` (هدرهای Eth, IPv4, TCP, UDP).
- [ ] [DP-02] ایجاد مپ `static_port_gate` در کرنل و پیاده‌سازی گیت بررسی پورت.
- [ ] [DP-03] ایجاد مپ `reputation_trie` برای فیلترینگ IPهای بلاک شده.
- [ ] [IPC-01] پیاده‌سازی ارسال متادیتای ۲۴ بایتی به `telemetry_ringbuf`.
- [ ] [CP-01] توسعه لودر پایه در Go با کتابخانه `cilium/ebpf` برای الحاق به اینترفیس شبکه و Pin کردن مپ‌ها در `/sys/fs/bpf/ai_ida`.

## 🟡 اولویت P1 — کنترل‌پلین و رابط CLI
- [ ] [CLI-01] طراحی و پیاده‌سازی سوکت یونیکس `/run/ai-ida/control.sock` بین دیمن و CLI.
- [ ] [CLI-02] پیاده‌سازی دستور `ai-idactl rule add port <port>` با کتابخانه Cobra.
- [ ] [CLI-03] پیاده‌سازی دستور `ai-idactl rule block ip <cidr>`.
- [ ] [STAT-01] ایجاد مپ `BPF_MAP_TYPE_PERCPU_ARRAY` برای شمارش پکت‌های Drop و Pass.

## 🟢 اولویت P2 — بهینه‌سازی و هوش مصنوعی
- [ ] [ML-01] تست خروجی پایپ‌لاین `m2cgen` از مدل LightGBM به توابع شرطی Go.
- [ ] [BENCH-01] نوشتن اسکریپت تست تزریق ترافیک با `pktgen` یا `TRex` و اندازه‌گیری PPS.
