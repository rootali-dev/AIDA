//! ai-ida-ebpf/src/filters/rate_limiter.rs

use crate::maps::RATE_LIMIT_MAP;
use ai_ida_common::RateLimitState;

// ۱ توکن به ازای هر ۱۰۰,۰۰۰ نانوثانیه (معادل ۱۰,۰۰۰ پکت در ثانیه)
const NANOS_PER_TOKEN: u64 = 100_000;
const BURST_CAPACITY: u64 = 20_000;

#[inline(always)]
pub fn check_rate_limit(src_ip: u32, now_ns: u64) -> Result<(), ()> {
    if let Some(state_ptr) = RATE_LIMIT_MAP.get_ptr_mut(&src_ip) {
        let state = unsafe { &mut *state_ptr };

        let elapsed = now_ns.saturating_sub(state.last_update_ns);
        // محاسبه خالص ۶۴ بیتی بدون سرریز و بدون وابستگی به __multi3
        let new_tokens = elapsed / NANOS_PER_TOKEN;

        if new_tokens > 0 {
            state.tokens = (state.tokens + new_tokens).min(BURST_CAPACITY);
            state.last_update_ns = now_ns;
        }

        if state.tokens >= 1 {
            state.tokens -= 1;
            Ok(())
        } else {
            Err(()) // Drop به دلیل پر شدن باکت
        }
    } else {
        // ایجاد ورودی اولیه برای جریان جدید
        let new_state = RateLimitState {
            last_update_ns: now_ns,
            tokens: BURST_CAPACITY.saturating_sub(1),
        };
        let _ = RATE_LIMIT_MAP.insert(&src_ip, &new_state, 0);
        Ok(())
    }
}