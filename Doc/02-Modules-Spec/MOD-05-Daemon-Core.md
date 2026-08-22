# Module MOD-05: Control Plane Core Service (`ai-idad` Daemon)

- **Subsystem:** Control Plane
- **Language:** Go
- **Priority:** `#p0`

---

## 1. Core Responsibilities

- **eBPF Lifecycle Management:** Loads the compiled eBPF ELF binary into kernel memory and attaches it to target network interfaces via XDP hooks.
- **Map Pinning:** Manages BPF Virtual File System (`bpffs`) pinning under `/sys/fs/bpf/ai_ida` for persistent rule state.
- **Telemetry Consumption:** Consumes high-rate RingBuffer data streams using a scalable pool of parallel Go worker goroutines.
- **AI/ML Inference:** Feeds extracted flow features into compiled lightweight machine learning models (via `m2cgen`) to identify real-time anomalies.
