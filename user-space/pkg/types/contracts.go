package types

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// LogSeverity defines the hierarchical runtime log severity levels.
type LogSeverity uint8

const (
	LogLevelOff   LogSeverity = 0
	LogLevelDebug LogSeverity = 1
	LogLevelInfo  LogSeverity = 2
	LogLevelWarn  LogSeverity = 3
	LogLevelError LogSeverity = 4
)

func ParseLogLevel(level string) (LogSeverity, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return LogLevelDebug, nil
	case "info":
		return LogLevelInfo, nil
	case "warn", "warning":
		return LogLevelWarn, nil
	case "error":
		return LogLevelError, nil
	case "off", "none", "disabled":
		return LogLevelOff, nil
	default:
		return LogLevelOff, fmt.Errorf("unknown log level %q (valid options: debug, info, warn, error)", level)
	}
}

func (s LogSeverity) String() string {
	switch s {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "OFF"
	}
}

func (s LogSeverity) ColoredPrefix() string {
	switch s {
	case LogLevelDebug:
		return "\033[36m[DEBUG]\033[0m" // Cyan
	case LogLevelInfo:
		return "\033[32m[INFO]\033[0m " // Green
	case LogLevelWarn:
		return "\033[33m[WARN]\033[0m " // Yellow
	case LogLevelError:
		return "\033[31m[ERROR]\033[0m" // Red
	default:
		return "[OFF]  "
	}
}

// DropReason represents the 1-byte raw numerical reason code emitted from kernel space.
type DropReason uint8

const (
	DropReasonNone DropReason = 0

	// 1-9 (ERROR): Malformed header, parse failures
	DropReasonEthParseFailed  DropReason = 1
	DropReasonIpv4ParseFailed DropReason = 2
	DropReasonTcpParseFailed  DropReason = 3
	DropReasonUdpParseFailed  DropReason = 4
	DropReasonArpParseFailed  DropReason = 5
	DropReasonMalformedPacket DropReason = 6

	// 10-19 (WARN): RFC violations & LPM Blacklist hits
	DropReasonRfcLandAttack DropReason = 10
	DropReasonRfcNullScan   DropReason = 11
	DropReasonRfcSynFin     DropReason = 12
	DropReasonRfcXmasScan   DropReason = 13
	DropReasonBlacklistHit  DropReason = 14

	// 20-29 (INFO): Port Gate blocks, Token-bucket rate-limit drops
	DropReasonPortBlocked DropReason = 20
	DropReasonRateLimited DropReason = 21
)

func (r DropReason) Severity() LogSeverity {
	switch {
	case r >= 1 && r <= 9:
		return LogLevelError
	case r >= 10 && r <= 19:
		return LogLevelWarn
	case r >= 20 && r <= 29:
		return LogLevelInfo
	default:
		return LogLevelDebug
	}
}

func (r DropReason) String() string {
	switch r {
	case DropReasonNone:
		return "PASS_CLEAN"
	case DropReasonEthParseFailed:
		return "ERR_ETH_PARSE_FAILED"
	case DropReasonIpv4ParseFailed:
		return "ERR_IPV4_PARSE_FAILED"
	case DropReasonTcpParseFailed:
		return "ERR_TCP_PARSE_FAILED"
	case DropReasonUdpParseFailed:
		return "ERR_UDP_PARSE_FAILED"
	case DropReasonArpParseFailed:
		return "ERR_ARP_PARSE_FAILED"
	case DropReasonMalformedPacket:
		return "ERR_MALFORMED_PACKET"
	case DropReasonRfcLandAttack:
		return "WARN_RFC_LAND_ATTACK"
	case DropReasonRfcNullScan:
		return "WARN_RFC_NULL_SCAN"
	case DropReasonRfcSynFin:
		return "WARN_RFC_SYN_FIN_CONFLICT"
	case DropReasonRfcXmasScan:
		return "WARN_RFC_XMAS_SCAN"
	case DropReasonBlacklistHit:
		return "WARN_LPM_BLACKLIST_HIT"
	case DropReasonPortBlocked:
		return "INFO_PORT_GATE_BLOCKED"
	case DropReasonRateLimited:
		return "INFO_RATE_LIMIT_EXCEEDED"
	default:
		return fmt.Sprintf("UNKNOWN_REASON_%d", r)
	}
}

// Action represents the 1-byte XDP pipeline action.
type Action uint8

const (
	ActionDrop     Action = 1
	ActionPass     Action = 2
	ActionTx       Action = 3
	ActionRedirect Action = 4
)

func (a Action) String() string {
	switch a {
	case ActionDrop:
		return "DROP"
	case ActionPass:
		return "PASS"
	case ActionTx:
		return "TX"
	case ActionRedirect:
		return "REDIRECT"
	default:
		return fmt.Sprintf("ACTION_%d", a)
	}
}

func (a Action) ColoredBadge() string {
	switch a {
	case ActionDrop:
		return "\033[41;97m DROP \033[0m" // Red background
	case ActionPass:
		return "\033[42;97m PASS \033[0m" // Green background
	case ActionTx:
		return "\033[44;97m  TX  \033[0m"
	case ActionRedirect:
		return "\033[45;97m RDRT \033[0m"
	default:
		return fmt.Sprintf("[%s]", a.String())
	}
}

// FlowPacketMeta defines the 24-byte shared telemetry data structure.
// Layout:
// - SrcIP:       4 bytes (0..4)
// - DstIP:       4 bytes (4..8)
// - SrcPort:     2 bytes (8..10)
// - DstPort:     2 bytes (10..12)
// - Protocol:    1 byte  (12..13)
// - TCPFlags:    1 byte  (13..14)
// - Action:      1 byte  (14..15)
// - DropReason:  1 byte  (15..16)
// - TimestampNS: 8 bytes (16..24)
// Total Size: Exactly 24 bytes (8-byte aligned, zero padding).
type FlowPacketMeta struct {
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Protocol    uint8
	TCPFlags    uint8
	Action      uint8
	DropReason  uint8
	TimestampNS uint64
}

func (m *FlowPacketMeta) UnmarshalBinary(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("invalid telemetry payload size: expected 24 bytes, got %d", len(data))
	}

	m.SrcIP = binary.BigEndian.Uint32(data[0:4])
	m.DstIP = binary.BigEndian.Uint32(data[4:8])
	m.SrcPort = binary.LittleEndian.Uint16(data[8:10])
	m.DstPort = binary.LittleEndian.Uint16(data[10:12])
	m.Protocol = data[12]
	m.TCPFlags = data[13]
	m.Action = data[14]
	m.DropReason = data[15]
	m.TimestampNS = binary.LittleEndian.Uint64(data[16:24])

	return nil
}

func (m *FlowPacketMeta) SrcIPNet() net.IP {
	return net.IPv4(byte(m.SrcIP>>24), byte(m.SrcIP>>16), byte(m.SrcIP>>8), byte(m.SrcIP))
}

func (m *FlowPacketMeta) DstIPNet() net.IP {
	return net.IPv4(byte(m.DstIP>>24), byte(m.DstIP>>16), byte(m.DstIP>>8), byte(m.DstIP))
}

func (m *FlowPacketMeta) ProtocolName() string {
	switch m.Protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("IP_%d", m.Protocol)
	}
}

func (m *FlowPacketMeta) TCPFlagsString() string {
	if m.Protocol != 6 {
		return "-"
	}
	var flags []string
	if m.TCPFlags&0x01 != 0 {
		flags = append(flags, "FIN")
	}
	if m.TCPFlags&0x02 != 0 {
		flags = append(flags, "SYN")
	}
	if m.TCPFlags&0x04 != 0 {
		flags = append(flags, "RST")
	}
	if m.TCPFlags&0x08 != 0 {
		flags = append(flags, "PSH")
	}
	if m.TCPFlags&0x10 != 0 {
		flags = append(flags, "ACK")
	}
	if m.TCPFlags&0x20 != 0 {
		flags = append(flags, "URG")
	}
	if len(flags) == 0 {
		return "NONE"
	}
	return strings.Join(flags, "|")
}

func (m *FlowPacketMeta) FormattedTime() string {
	return time.Now().Format("15:04:05.000000")
}

type LpmIpv4Key struct {
	PrefixLen uint32
	Addr      [4]byte
}

type RateLimitState struct {
	LastUpdateNS uint64
	Tokens       uint64
}

func NewLpmKey(cidrStr string) (LpmIpv4Key, error) {
	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		parsedIP := net.ParseIP(cidrStr).To4()
		if parsedIP == nil {
			return LpmIpv4Key{}, fmt.Errorf("invalid IPv4 address: %s", cidrStr)
		}
		var addr [4]byte
		copy(addr[:], parsedIP)
		return LpmIpv4Key{PrefixLen: 32, Addr: addr}, nil
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return LpmIpv4Key{}, fmt.Errorf("only IPv4 is supported in Phase 2")
	}

	ones, _ := ipNet.Mask.Size()
	var addr [4]byte
	copy(addr[:], ipv4)

	return LpmIpv4Key{
		PrefixLen: uint32(ones),
		Addr:      addr,
	}, nil
}