//! ai-ida-ebpf/src/cursor.rs
//! انتزاع بدون هزینه برای بررسی مرزهای حافظه و پیمایش خطی بافر پکت.

use aya_ebpf::programs::XdpContext;
use core::mem;

pub struct Cursor {
    start: usize,
    end: usize,
    offset: usize,
}

impl Cursor {
    /// ایجاد یک اشاره‌گر جدید از کانتکست بسته XDP
    #[inline(always)]
    pub fn new(ctx: &XdpContext) -> Self {
        Self {
            start: ctx.data(),
            end: ctx.data_end(),
            offset: 0,
        }
    }

    /// خواندن یک ساختار هدر و جلو بردن آفست در صورت احراز امنیت مرز حافظه
    #[inline(always)]
    pub fn read<T>(&mut self) -> Result<*const T, ()> {
        let size = mem::size_of::<T>();
        let target = self.start + self.offset;

        // شرط حیاتی برای جلب رضایت قطعی eBPF Verifier
        if target + size > self.end {
            return Err(());
        }

        self.offset += size;
        Ok(target as *const T)
    }

    /// پرش امن روی بایت‌ها بدون تبدیل به ساختار (مثلاً برای رد کردن تگ VLAN یا گزینه‌های IP)
    #[inline(always)]
    pub fn advance(&mut self, bytes: usize) -> Result<(), ()> {
        if self.start + self.offset + bytes > self.end {
            return Err(());
        }
        self.offset += bytes;
        Ok(())
    }

    /// آفست فعلی درون بسته (بر حسب بایت)
    #[inline(always)]
    pub fn current_offset(&self) -> usize {
        self.offset
    }
}