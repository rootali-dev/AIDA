# 💾 24-Byte Telemetry Binary Memory Layout Contract

To prevent unintended compiler padding and guarantee byte-for-byte binary compatibility between **Rust** (kernel/eBPF space) and **Go** (user space/control plane), this explicit data structure serves as the fundamental contract for all packet telemetry streams.

---

## 1. Rust Definition (`#[repr(C, packed)]`)

```rust
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct PacketTelemetry {
    pub src_ip: u32,       // 4 Bytes: IPv4 Source Address (Network Byte Order)
    pub dst_ip: u32,       // 4 Bytes: IPv4 Destination Address (Network Byte Order)
    pub src_port: u16,     // 2 Bytes: L4 Source Port
    pub dst_port: u16,     // 2 Bytes: L4 Destination Port
    pub protocol: u8,      // 1 Byte : Protocol (TCP=6, UDP=17, ICMP=1)
    pub tcp_flags: u8,     // 1 Byte : TCP Flags (SYN, ACK, FIN, RST, etc.)
    pub payload_len: u16,  // 2 Bytes: Size of payload following L4 header
    pub timestamp: u64,    // 8 Bytes: Kernel monotonic timestamp (bpf_ktime_get_ns)
}                          // Total  : Exactly 24 Bytes (Zero alignment padding)
```

---

## 2. Go Equivalent (Control Plane / User Space)

```go
type PacketTelemetry struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	TCPFlags   uint8
	PayloadLen uint16
	Timestamp  uint64
} // Size: Exactly 24 Bytes
```

---

## 3. Engineering Invariants & Constraints

- **Fixed Size:** The struct size must strictly remain a multiple of 4 and 8 bytes (totaling exactly 24 bytes).
- **No Pointers:** The struct must contain only primitive fixed-width value types—pointers or dynamically sized types are strictly prohibited.
- **Static Verification:** During compilation, the Rust static assertion `assert_eq!(core::mem::size_of::<PacketTelemetry>(), 24);` must pass without warnings.
