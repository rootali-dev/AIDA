# ماژول MOD-05: سرویس هسته کنترل‌پلین (ai-idad Daemon)

- **زیرسیستم:** Control Plane
- **زبان:** Go
- **اولویت:** #p0

## وظایف اصلی
- لود کردن فایل ELF مربوط به eBPF در حافظه کرنل.
- مدیریت BPF Pinning در مسیر `/sys/fs/bpf/ai_ida`.
- مصرف داده‌های RingBuffer با Goroutineهای موازی.
