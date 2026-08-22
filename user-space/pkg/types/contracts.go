package types

import (
	"encoding/binary"
	"fmt"
	"net"
)

type FlowPacketMeta struct {
	SrcIP       uint32   // 4 بایت
	DstIP       uint32   // 4 بایت
	SrcPort     uint16   // 2 بایت
	DstPort     uint16   // 2 بایت
	Length      uint16   // 2 بایت
	Protocol    uint8    // 1 بایت
	TCPFlags    uint8    // 1 بایت
	TimestampNS uint64   // 8 بایت
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

func (m *FlowPacketMeta) UnmarshalBinary(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("invalid telemetry payload size: expected 24 bytes, got %d", len(data))
	}

	m.SrcIP = binary.BigEndian.Uint32(data[0:4])
	m.DstIP = binary.BigEndian.Uint32(data[4:8])
	m.SrcPort = binary.BigEndian.Uint16(data[8:10])
	m.DstPort = binary.BigEndian.Uint16(data[10:12])
	m.Length = binary.LittleEndian.Uint16(data[12:14])
	m.Protocol = data[14]
	m.TCPFlags = data[15]
	m.TimestampNS = binary.LittleEndian.Uint64(data[16:24])

	return nil
}