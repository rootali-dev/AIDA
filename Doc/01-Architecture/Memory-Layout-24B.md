# 💾 قرارداد باینری تله‌متری (24-Byte Memory Layout Contract)

برای جلوگیری از Padding‌های ناخواسته کامپایلر و تضمین همخوانی کامل بین Rust (کرنل) و Go (یوزراسپیس)، این ساختار داده مبنای تمام تبادلات قرار می‌گیرد.

## ساختار Rust (`#[repr(C, packed)]`)

```rust
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct PacketTelemetry {
    pub src_ip: u32,       // 4 Bytes: IPv4 Source (Network Order)
    pub dst_ip: u32,       // 4 Bytes: IPv4 Destination (Network Order)
    pub src_port: u16,     // 2 Bytes: L4 Source Port
    pub dst_port: u16,     // 2 Bytes: L4 Destination Port
    pub protocol: u8,      // 1 Byte : Protocol (TCP=6, UDP=17, ICMP=1)
    pub tcp_flags: u8,     // 1 Byte : TCP Flags (SYN, ACK, FIN, RST, etc.)
    pub payload_len: u16,  // 2 Bytes: Size of payload after L4 Header
    pub timestamp: u64,    // 8 Bytes: Kernel Nanoseconds (bpf_ktime_get_ns)
}                          // Total = Exactly 24 Bytes (No alignment padding)
```

## معادل در زبان Go (Control Plane)

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
} // Size: 24 Bytes
```

## قوانین مهندسی (Invariants)
- ساختار باید همواره ضریبی از ۸ یا ۴ بایت باشد.
- هیچ اشاره‌گری (Pointer) نباید در ساختار قرار گیرد.
- در زمان کامپایل، تست `assert_eq!(core::mem::size_of::<PacketTelemetry>(), 24);` باید در Rust پاس شود.
