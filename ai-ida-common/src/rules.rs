//! ai-ida-common/src/rules.rs
//! تعاریف کدهای پروتکل، کلید مپ‌ها و اکشن‌های فیلترینگ هسته.

/// کدهای استاندارد EtherType در لایه ۲ اترنت
pub mod eth_types {
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const ARP: u16 = 0x0806;
    pub const VLAN_8021Q: u16 = 0x8100;
    pub const QINQ_8021AD: u16 = 0x88A8;
}

/// کدهای استاندارد پروتکل‌های لایه ۳ در فیلد Protocol هدر IP
pub mod ip_proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMPV6: u8 = 58;
}

/// تصمیمات و اکشن‌های فایروال در سطح XDP (Verdict)
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    /// نابودی بسته بدون تخصیص حافظه
    Drop = 1,
    /// عبور بسته به سمت استک هسته لینوکس
    Pass = 2,
    /// ارسال مجدد بسته به همان کارت شبکه (مثلاً پاسخ Stateless RST)
    Tx = 3,
    /// هدایت بسته به اینترفیس یا صف دیگر پردازنده
    Redirect = 4,
}

/// کلید استاندارد مپ LPM_TRIE برای فیلتر کردن رنج‌های CIDR و آی‌پی‌ها
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmIpv4Key {
    /// طول پیشوند شبکه (مثلاً 32 برای تک IP یا 24 برای یک Subnet)
    pub prefix_len: u32,
    /// آدرس IPv4 بر حسب ۴ بایت مجزا
    pub addr: [u8; 4],
}

impl LpmIpv4Key {
    pub const fn new(addr: [u8; 4], prefix_len: u32) -> Self {
        Self { prefix_len, addr }
    }
}

/// ساختار داده ذخیره‌شده در مپ LRU_PERCPU_HASH برای ریت‌لیمیتر بدون قفل (Token Bucket)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitState {
    /// آخرین برچسب زمانی شارژ توکن‌ها (نانوثانیه)
    pub last_update_ns: u64,
    /// موجودی توکن‌های باقیمانده (تعداد پکت مجاز)
    pub tokens: u64,
}