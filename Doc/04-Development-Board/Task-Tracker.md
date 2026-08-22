# 🎯 Development Task Tracker

---

## 🔴 Priority P0 — Core & Base Data Path (MVP)
- [ ] `[DP-01]` Implement safe packet parser in `core-xdp/src/main.rs` (Ethernet, IPv4, TCP, UDP headers).
- [ ] `[DP-02]` Define `static_port_gate` eBPF array map and implement $O(1)$ port evaluation gate.
- [ ] `[DP-03]` Define `reputation_trie` LPM trie map for blacklist IP/CIDR prefix filtering.
- [ ] `[IPC-01]` Implement 24-byte telemetry metadata serialization and emission to `telemetry_ringbuf`.
- [ ] `[CP-01]` Develop Go-based base loader using `cilium/ebpf` to attach programs to network interfaces and pin maps under `/sys/fs/bpf/ai_ida`.

---

## 🟡 Priority P1 — Control Plane & CLI Interface
- [ ] `[CLI-01]` Design and implement Unix domain socket (`/run/ai-ida/control.sock`) IPC between daemon and CLI client.
- [ ] `[CLI-02]` Implement `ai-idactl rule add port <port>` command via Cobra CLI framework.
- [ ] `[CLI-03]` Implement `ai-idactl rule block ip <cidr>` command.
- [ ] `[STAT-01]` Create `BPF_MAP_TYPE_PERCPU_ARRAY` map to track real-time Drop and Pass packet metrics.

---

## 🟢 Priority P2 — Optimization & Machine Learning
- [ ] `[ML-01]` Test output of `m2cgen` pipeline converting trained LightGBM models into pure Go conditional evaluation functions.
- [ ] `[BENCH-01]` Develop automated traffic injection benchmarking scripts using `pktgen` or `TRex` to measure PPS and latency under load.
