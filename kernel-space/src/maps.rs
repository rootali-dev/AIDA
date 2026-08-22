//! kernel-space/src/maps.rs
//! eBPF map definitions for static enforcement policies and telemetry ring buffers.

use ai_ida_common::RateLimitState;
use aya_ebpf::{
    macros::map,
    maps::{lpm_trie::LpmTrie, Array, LruPerCpuHashMap, RingBuf},
};

/// IPv4 Blacklist Table (32-bit IPv4 LPM Trie).
/// Map Value: 1 = DROP, 0 = PASS.
#[map]
pub static REPUTATION_MAP: LpmTrie<u32, u32> = LpmTrie::with_max_entries(16_384, 0);

/// Layer 4 Port Enforcement Gate (65,536 total L4 ports).
/// Map Index: L4 Port Number | Map Value: 1 = OPEN, 2 = BLOCKED.
#[map]
pub static PORT_GATE_MAP: Array<u8> = Array::with_max_entries(65_536, 0);

/// Lockless Rate-Limiter State Tracking Map.
/// Uses LRU Per-CPU Hash Map to prevent memory exhaustion under DDoS scale.
#[map]
pub static RATE_LIMIT_MAP: LruPerCpuHashMap<u32, RateLimitState> =
    LruPerCpuHashMap::with_max_entries(65_536, 0);

/// Lockless Ring Buffer for high-speed telemetry streaming to the Go control plane.
/// Allocated Buffer Capacity: 1 MB (1 << 20 bytes).
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);