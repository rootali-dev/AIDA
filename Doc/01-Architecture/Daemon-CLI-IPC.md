# 🔌 معماری ارتباطی Daemon و CLI بر پایه Unix Domain Socket

معماری کنترل‌پلین AI-IDA بر اساس جداسازی Daemon پس‌زمینه (`ai-idad`) از ابزار خط فرمان کلاینت (`ai-idactl`) طراحی شده است.

## ۱. دیاگرام معماری لایه کنترل

```text
┌────────────────────────────────────────────────────────┐
│               ai-idactl (Go CLI Client)                │
└───────────────────────────┬────────────────────────────┘
                            │ Unix Domain Socket
                            │ (/run/ai-ida/control.sock)
                            ▼
┌────────────────────────────────────────────────────────┐
│               ai-idad (Go Core Daemon)                 │
│  ├── IPC Command Server                                │
│  ├── RingBuffer Reader Worker Pool                     │
│  └── m2cgen Compiled ML Engine                         │
└───────────────────────────┬────────────────────────────┘
                            │ Syscall / Pinned Maps
                            ▼
┌────────────────────────────────────────────────────────┐
│             /sys/fs/bpf/ai_ida/ (bpffs)                │
│  ├── static_port_gate  (BPF_MAP_TYPE_ARRAY)            │
│  ├── reputation_trie   (BPF_MAP_TYPE_LPM_TRIE)         │
│  └── telemetry_stats   (BPF_MAP_TYPE_PERCPU_ARRAY)     │
└────────────────────────────────────────────────────────┘
```

## ۲. ملاحظات امنیتی و پایداری
- **پایداری وضعیت (Persistence):** تمام مپ‌ها در BPF Virtual File System پین می‌شوند تا در صورت ریستارت دیمن، قوانین از بین نروند.
- **ایزولاسیون دسترسی:** کلاینت CLI با سطح دسترسی کاربر عادی به سوکت وصل شده و احراز هویت از طریق مجوزهای فایل لینوکس (`chown`/`chmod 0660`) روی فایل سوکت انجام می‌شود.
