# 🏃‍♂️ Phase 2 Sprint Planning

---

## Sprint 1: Core Static Filtering Pipeline (Weeks 1 & 2)
- Complete **MOD-01 (Safe Parser)** and satisfy all eBPF verifier safety constraints.
- Complete **MOD-02 (Array Port Gate)** for $O(1)$ port filtering.
- Validate packet drop and pass execution paths using `xdp-loader`.

---

## Sprint 2: Telemetry Pipeline & Go Loader (Weeks 3 & 4)
- Implement **MOD-04 (RingBuffer 24B Export)** for kernel-to-user space streaming.
- Implement the initial **MOD-05 (`ai-idad`) daemon** and configure BPF map pinning in `bpffs`.

---

## Sprint 3: CLI Interface & IPC Integration (Weeks 5 & 6)
- Implement the Unix domain socket IPC layer and `ai-idactl` CLI command suite.
- Perform end-to-end latency benchmarking and measure line-rate packet drop/pass performance.
