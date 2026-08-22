//! kernel-space/src/cursor.rs
//! Zero-cost, verifier-safe packet memory cursor for dynamic byte-stream parsing.

use aya_ebpf::programs::XdpContext;
use core::mem;

/// Tracks packet memory boundaries (`[data, data_end]`) to satisfy BPF verifier bounds checks.
pub struct Cursor {
    start: usize,
    end: usize,
    offset: usize,
}

impl Cursor {
    /// Initializes a packet cursor at offset 0 using XDP context pointers.
    #[inline(always)]
    pub fn new(ctx: &XdpContext) -> Self {
        Self {
            start: ctx.data(),
            end: ctx.data_end(),
            offset: 0,
        }
    }

    /// Reads type `T` at the current offset after validating packet memory bounds.
    /// Advances internal offset by `sizeof(T)` on success.
    #[inline(always)]
    pub fn read<T>(&mut self) -> Result<*const T, ()> {
        let size = mem::size_of::<T>();
        let target = self.start + self.offset;

        // Verifier invariant check: prevent out-of-bounds packet memory access
        if target + size > self.end {
            return Err(());
        }

        self.offset += size;
        Ok(target as *const T)
    }

    /// Safely advances the offset by a specified byte length without casting to a struct.
    /// Useful for skipping variable header fields (e.g., VLAN tags, IP options).
    #[inline(always)]
    pub fn advance(&mut self, bytes: usize) -> Result<(), ()> {
        // Enforce verifier bound validation before advancing cursor offset
        if self.start + self.offset + bytes > self.end {
            return Err(());
        }
        self.offset += bytes;
        Ok(())
    }

    /// Returns the current relative byte offset from the packet payload start.
    #[inline(always)]
    pub fn current_offset(&self) -> usize {
        self.offset
    }
}