# 🔌 Daemon & CLI IPC Architecture via Unix Domain Socket

The control plane architecture of **AI-IDA** is designed around a clear separation between the background daemon (`ai-idad`) and the command-line interface client (`ai-idactl`).

---

## 1. Control Plane Architecture Diagram

```text
┌────────────────────────────────────────────────────────┐
│               ai-idactl (Go CLI Client)                │
└───────────────────────────┬────────────────────────────┘
                            │ Unix Domain Socket
                            │ (/run/ai-ida/control.sock)
                            ▼
┌────────────────────────────────────────────────────────┐
│               ai-idad (Go Core Daemon)                 │
│  ├── IPC Command Server                                │
│  ├── RingBuffer Reader Worker Pool                     │
│  └── m2cgen Compiled ML Engine                         │
└───────────────────────────┬────────────────────────────┘
                            │ Syscall / Pinned Maps
                            ▼
┌────────────────────────────────────────────────────────┐
│             /sys/fs/bpf/ai_ida/ (bpffs)                │
│  ├── static_port_gate  (BPF_MAP_TYPE_ARRAY)            │
│  ├── reputation_trie   (BPF_MAP_TYPE_LPM_TRIE)         │
│  └── telemetry_stats   (BPF_MAP_TYPE_PERCPU_ARRAY)     │
└────────────────────────────────────────────────────────┘
```

---

## 2. Security & Reliability Considerations

- **State Persistence:** All eBPF maps are pinned in the BPF Virtual File System (`bpffs` at `/sys/fs/bpf/ai_ida`). This guarantees that active firewall rules and stats persist even across daemon restarts.
- **Access Control & Isolation:** The CLI client connects to the Unix domain socket with standard user permissions. Authorization and security isolation are enforced via Linux filesystem permissions (`chown` / `chmod 0660`) on the socket file.
