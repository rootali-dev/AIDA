package types

import (
	"encoding/binary"
	"testing"
)

func TestFlowPacketMetaBinaryUnmarshal(t *testing.T) {
	raw := make([]byte, 24)
	// SrcIP: 192.168.1.100 -> 0xC0A80164
	binary.BigEndian.PutUint32(raw[0:4], 0xC0A80164)
	// DstIP: 10.0.0.1 -> 0x0A000001
	binary.BigEndian.PutUint32(raw[4:8], 0x0A000001)
	// SrcPort: 443 (0x01BB)
	binary.LittleEndian.PutUint16(raw[8:10], 443)
	// DstPort: 80 (0x0050)
	binary.LittleEndian.PutUint16(raw[10:12], 80)
	// Protocol: TCP (6)
	raw[12] = 6
	// TCPFlags: SYN | ACK (0x12)
	raw[13] = 0x12
	// Action: Drop (1)
	raw[14] = 1
	// DropReason: BlacklistHit (14)
	raw[15] = 14
	// TimestampNS: 1234567890
	binary.LittleEndian.PutUint64(raw[16:24], 1234567890)

	var meta FlowPacketMeta
	if err := meta.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if meta.SrcIPNet().String() != "192.168.1.100" {
		t.Errorf("expected SrcIP 192.168.1.100, got %s", meta.SrcIPNet().String())
	}
	if meta.DstIPNet().String() != "10.0.0.1" {
		t.Errorf("expected DstIP 10.0.0.1, got %s", meta.DstIPNet().String())
	}
	if meta.SrcPort != 443 {
		t.Errorf("expected SrcPort 443, got %d", meta.SrcPort)
	}
	if meta.DstPort != 80 {
		t.Errorf("expected DstPort 80, got %d", meta.DstPort)
	}
	if meta.ProtocolName() != "TCP" {
		t.Errorf("expected protocol TCP, got %s", meta.ProtocolName())
	}
	if meta.TCPFlagsString() != "SYN|ACK" {
		t.Errorf("expected flags SYN|ACK, got %s", meta.TCPFlagsString())
	}
	if Action(meta.Action) != ActionDrop {
		t.Errorf("expected ActionDrop, got %v", meta.Action)
	}
	if DropReason(meta.DropReason) != DropReasonBlacklistHit {
		t.Errorf("expected DropReasonBlacklistHit, got %v", meta.DropReason)
	}
	if DropReason(meta.DropReason).Severity() != LogLevelWarn {
		t.Errorf("expected LogLevelWarn, got %v", DropReason(meta.DropReason).Severity())
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogSeverity
		wantErr  bool
	}{
		{"debug", LogLevelDebug, false},
		{"DEBUG", LogLevelDebug, false},
		{"info", LogLevelInfo, false},
		{"warn", LogLevelWarn, false},
		{"warning", LogLevelWarn, false},
		{"error", LogLevelError, false},
		{"off", LogLevelOff, false},
		{"disabled", LogLevelOff, false},
		{"invalid", LogLevelOff, true},
	}

	for _, tt := range tests {
		lvl, err := ParseLogLevel(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseLogLevel(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if lvl != tt.expected {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, lvl, tt.expected)
		}
	}
}
