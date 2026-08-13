# ماژول MOD-04: خط تله‌متری و نمونه‌برداری (RingBuffer Telemetry)

- **زیرسیستم:** Telemetry Pipeline
- **ساختار داده:** `BPF_MAP_TYPE_RINGBUF`
- **اولویت:** #p0

## سیاست ارسال
- استفاده از `bpf_ringbuf_reserve` و `bpf_ringbuf_submit`.
- نرخ نمونه‌برداری تطبیقی: ارسال ۱ پکت از هر $N$ پکت نرمال برای جلوگیری از اشباع پهنای باند حافظه.
