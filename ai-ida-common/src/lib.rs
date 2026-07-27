#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RateBucket {
    pub tokens: u32,
    pub _pad: u32,          // pads to 16B -> 4 buckets/cache-line, no false sharing across slots
    pub last_refill_ns: u64,
}