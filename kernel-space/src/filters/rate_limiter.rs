// SPDX-License-Identifier: GPL-2.0-only\n//! kernel-space/src/filters/rate_limiter.rs

use crate::maps::RATE_LIMIT_MAP;
use common::RateLimitState;

const NANOS_PER_TOKEN: u64 = 100_000;
const BURST_CAPACITY: u64 = 20_000;

#[inline(always)]
pub fn check_rate_limit(src_ip: u32, now_ns: u64) -> Result<(), ()> {
    if let Some(state_ptr) = RATE_LIMIT_MAP.get_ptr_mut(&src_ip) {
        let state = unsafe { &mut *state_ptr };

        let elapsed = now_ns.saturating_sub(state.last_update_ns);
        let new_tokens = elapsed / NANOS_PER_TOKEN;

        if new_tokens > 0 {
            state.tokens = (state.tokens + new_tokens).min(BURST_CAPACITY);
            state.last_update_ns = now_ns;
        }

        if state.tokens >= 1 {
            state.tokens -= 1;
            Ok(())
        } else {
            Err(()) // Drop the packet due to rate limiting
        }
    } else {
        let new_state = RateLimitState {
            last_update_ns: now_ns,
            tokens: BURST_CAPACITY.saturating_sub(1),
        };
        let _ = RATE_LIMIT_MAP.insert(&src_ip, &new_state, 0);
        Ok(())
    }
}
