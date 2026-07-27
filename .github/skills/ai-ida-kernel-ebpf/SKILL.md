---
name: ai-ida-kernel-ebpf
description: Use this skill when writing, reviewing, or debugging Linux eBPF/XDP kernel-space code in Rust using the Aya framework. Enforces #![no_std], bounds checking proofs for eBPF verifier, endianness conversion, and zero-allocation memory constraints. Trigger for any task touching the ai-ida-ebpf crate, XDP programs, BPF maps, or Aya API usage — including code review and debugging, not just new code.
---

# eBPF/XDP Kernel Rules (Aya)

Crate: `ai-ida-ebpf`. Shared types: `ai-ida-common`.

## Invariants (non-negotiable)

1. **no_std**: `#![no_std]`. No std lib.
2. **Bounds proof**: before any context pointer deref:
   `if start + offset > end { return Ok(xdp_action::XDP_PASS); }`
   Apply to every layer (Ethernet → IP → transport). No unchecked offset math.
3. **Zero alloc**: no `alloc`, `Vec`, `String`, `Box`. Fixed-size arrays or BPF Maps only (`HashMap`, `Array`, `PerCpuArray`, `RingBuf`).
4. **Endianness**: network fields via `u16::from_be()` / `u32::from_be()`. Never compare raw network-order values against host-order constants.
5. **repr(C)**: all structs shared with userspace (`ai-ida-common`) → `#[repr(C)]`.
6. **Verdicts**: return only `XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT`.
7. **unsafe**: every `unsafe` block gets a `// SAFETY:` comment stating the invariant relied on.

## Review/debug mode

Same 7 checks apply when reviewing or debugging existing code, not just generating new code. Flag violations by rule number.

## Output format

- Code first. No preamble ("Here is...", "Sure!").
- Comments inline in code only. No trailing prose explanation.
- If a verifier risk exists and isn't already resolved in the code: one line at the end, `// Safety Note: <risk>`. Omit if no risk.
- Exception: pure conceptual questions (no code requested) get a direct answer, still terse — no filler, no re-explaining the question.
