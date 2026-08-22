# 🛡️ AI-IDA — Intelligent Defense Architecture Dashboard

> **Project Status:** Phase 2 (Minimal Core Development & Static Filtering Pipeline)  
> **Target Environment:** Linux Kernel 5.15+ | 10Gbps Line-Rate (14.88 Mpps)

---

## 🧭 Architecture Quick Navigation
- 🏛️ **Core System Architecture:** [[Core-Architecture]]
- 💾 **24-Byte Binary Contract:** [[Memory-Layout-24B]]
- 🔌 **Daemon & CLI IPC Architecture:** [[Daemon-CLI-IPC]]
- 📜 **Architecture Decision Records (ADRs):** [[ADR-0001-Pipeline-Order]] | [[ADR-0002-LRU-Map-Type]] | [[ADR-0003-Daemon-Client]]

---

## 🎯 Current Phase Task Progress (Phase 2 MVP)

### 🔥 Critical Priority (P0)
- [ ] Implement safe L2/L3/L4 parser adhering to Rust/eBPF Verifier boundaries ([[MOD-01-Safe-Parser]])
- [ ] Create static port filtering map with `BPF_MAP_TYPE_ARRAY` ([[MOD-02-Static-ACL]])
- [ ] Create CIDR blocklist map with `BPF_MAP_TYPE_LPM_TRIE` ([[MOD-03-Reputation-Trie]])
- [ ] Implement 24-byte telemetry struct emission to `bpf_ringbuf` ([[MOD-04-RingBuf-Telemetry]])
- [ ] Initialize background daemon with BPF map pinning under `/sys/fs/bpf/ai_ida` ([[MOD-05-Daemon-Core]])

### ⚡ High Priority (P1)
- [ ] Implement CLI client for adding/removing static rules via Unix Domain Sockets ([[MOD-06-CLI-Client]])
- [ ] Create `BPF_MAP_TYPE_PERCPU_ARRAY` map for lockless real-time traffic statistics

---

## 📊 Technical Specifications & Performance Targets (SLOs/SLAs)

| Metric | Target Value | Current Status |
| :--- | :--- | :--- |
| **In-Kernel Per-Packet Latency** | $< 67\text{ ns}$ | Pending Benchmark |
| **64-Byte Packet Filtering Throughput** | $14.88\text{ Mpps}$ | Pending Benchmark |
| **RingBuffer Telemetry Packet Loss (Go Layer)** | $0.0\%$ | Pending Benchmark |
