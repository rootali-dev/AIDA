// === ai-ida-ebpf/src/rate_limit.rs ===
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::PerCpuArray,
    programs::XdpContext,
};
use ai_ida_common::RateBucket;

const BUCKET_COUNT: u32 = 1 << 16;
const BUCKET_MASK: u32 = BUCKET_COUNT - 1;      // power-of-2 -> AND, never MOD/DIV on a variable
const BURST_CAPACITY: u32 = 128;
const REFILL_INTERVAL_NS: u64 = 976_562;        // compile-time constant divisor, folds to mul-shift

#[map]
static RATE_BUCKETS: PerCpuArray<RateBucket> = PerCpuArray::with_max_entries(BUCKET_COUNT, 0);

#[inline(always)]
fn fnv1a_u32(v: u32) -> u32 {
    // Unrolled 4-byte FNV-1a: fixed, branchless, no loop trip-count for verifier to reason about.
    let mut h: u32 = 0x811c9dc5;
    h ^= v & 0xff;         h = h.wrapping_mul(0x0100_0193);
    h ^= (v >> 8) & 0xff;  h = h.wrapping_mul(0x0100_0193);
    h ^= (v >> 16) & 0xff; h = h.wrapping_mul(0x0100_0193);
    h ^= (v >> 24) & 0xff; h = h.wrapping_mul(0x0100_0193);
    h
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    // Verifier trap: bounds check MUST precede every deref, on separate unsigned adds
    // (start + offset + size), not a folded expression the compiler could hoist/reorder.
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[xdp]
pub fn ai_ida_rate_limit(ctx: XdpContext) -> u32 {
    match try_rate_limit(&ctx) {
        Ok(a) => a,
        Err(_) => xdp_action::XDP_PASS, // fail-open on truncated/malformed packet
    }
}

fn try_rate_limit(ctx: &XdpContext) -> Result<u32, ()> {
    // Ethertype check first: statistically dominant branch (IPv4), cheapest reject for non-IP.
    let ethertype_ptr: *const u16 = ptr_at(ctx, 12)?;
    // SAFETY: ptr_at proved start+12+2 <= data_end.
    if u16::from_be(unsafe { *ethertype_ptr }) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    // saddr is at a fixed offset (14 + 12) regardless of IHL/options — no need to parse IHL here.
    let src_ip_ptr: *const u32 = ptr_at(ctx, 14 + 12)?;
    // SAFETY: ptr_at proved start+26+4 <= data_end.
    let src_ip = u32::from_be(unsafe { *src_ip_ptr });

    let idx = fnv1a_u32(src_ip) & BUCKET_MASK;

    let bucket_ptr = match RATE_BUCKETS.get_ptr_mut(idx) {
        Some(p) => p,
        None => return Ok(xdp_action::XDP_PASS), // unreachable given mask, kept for verifier/defensive parity
    };

    let now = unsafe { bpf_ktime_get_ns() };
    // SAFETY: bucket_ptr is this-CPU's slot for `idx` (< BUCKET_COUNT via mask), non-null,
    // borrowed only for this invocation — never stored, returned, or passed to another map/helper.
    let bucket = unsafe { &mut *bucket_ptr };

    let elapsed = now.saturating_sub(bucket.last_refill_ns);
    let refill = (elapsed / REFILL_INTERVAL_NS) as u32;
    if refill > 0 {
        bucket.tokens = core::cmp::min(bucket.tokens.saturating_add(refill), BURST_CAPACITY);
        bucket.last_refill_ns = now;
    }

    if bucket.tokens == 0 {
        return Ok(xdp_action::XDP_DROP);
    }
    bucket.tokens -= 1;
    Ok(xdp_action::XDP_PASS)
}‍‍‍