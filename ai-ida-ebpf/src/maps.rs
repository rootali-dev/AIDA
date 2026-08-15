//! ai-ida-ebpf/src/maps.rs
//! تعاریف eBPF Mapها جهت اعمال سیاست‌های استاتیک و تله‌متری.

use ai_ida_common::RateLimitState;
use aya_ebpf::{
    macros::map,
    maps::{lpm_trie::LpmTrie, Array, LruPerCpuHashMap, RingBuf},
};

/// مپ لیست سیاه آی‌پی (LPM Trie بر پایه داده 32 بیتی IPv4)
/// مقدار 1 به معنای بلاک و 0 به معنای مجاز است
#[map]
pub static REPUTATION_MAP: LpmTrie<u32, u32> = LpmTrie::with_max_entries(16384, 0);

/// گیت پورت‌های مجاز (65536 پورت L4)
/// ایندکس: شماره پورت | مقدار: 1 یعنی باز، 2 یعنی مسدود
#[map]
pub static PORT_GATE_MAP: Array<u8> = Array::with_max_entries(65536, 0);

/// مپ ریت‌لیمیتینگ بدون قفل بر پایه LRU برای جلوگیری از پر شدن حافظه
#[map]
pub static RATE_LIMIT_MAP: LruPerCpuHashMap<u32, RateLimitState> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// رینگ بافر بدون قفل جهت ارسال تله‌متری ۲۴ بایتی به کنترل‌پلن Go
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0); // بافر ۱ مگابایتی