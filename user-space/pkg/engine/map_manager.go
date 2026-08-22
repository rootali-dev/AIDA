package engine

import (
	"fmt"
	"path/filepath"
	"user-space/pkg/types"

	"github.com/cilium/ebpf"
)

const BpfFsPath = "/sys/fs/bpf/ai_ida"

type MapManager struct {
	reputationMap *ebpf.Map
	portGateMap   *ebpf.Map
	rateLimitMap  *ebpf.Map
}

func LoadPinnedMaps() (*MapManager, error) {
	repMap, err := ebpf.LoadPinnedMap(filepath.Join(BpfFsPath, "reputation_map"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open reputation_map (is AI-IDA running?): %w", err)
	}

	portMap, err := ebpf.LoadPinnedMap(filepath.Join(BpfFsPath, "port_gate_map"), nil)
	if err != nil {
		repMap.Close()
		return nil, fmt.Errorf("failed to open port_gate_map: %w", err)
	}

	rateMap, err := ebpf.LoadPinnedMap(filepath.Join(BpfFsPath, "rate_limit_map"), nil)
	if err != nil {
		repMap.Close()
		portMap.Close()
		return nil, fmt.Errorf("failed to open rate_limit_map: %w", err)
	}

	return &MapManager{
		reputationMap: repMap,
		portGateMap:   portMap,
		rateLimitMap:  rateMap,
	}, nil
}

func (m *MapManager) Close() {
	if m.reputationMap != nil { m.reputationMap.Close() }
	if m.portGateMap != nil { m.portGateMap.Close() }
	if m.rateLimitMap != nil { m.rateLimitMap.Close() }
}

func (m *MapManager) BlockIP(cidr string) error {
	key, err := types.NewLpmKey(cidr)
	if err != nil {
		return err
	}

	var value uint32 = 1
	if err := m.reputationMap.Put(key, value); err != nil {
		return fmt.Errorf("failed to insert IP into BPF LPM_TRIE: %w", err)
	}

	return nil
}

func (m *MapManager) SetPortStatus(port uint16, allow bool) error {
	var val uint8 = 0
	if allow {
		val = 1
	}

	if err := m.portGateMap.Put(port, val); err != nil {
		return fmt.Errorf("failed to update port %d status: %w", port, err)
	}

	return nil
}

func (m *MapManager) BlockPort(port uint16) error {
	var val uint8 = 2
	var key uint32 = uint32(port)
	if err := m.portGateMap.Put(key, val); err != nil {
		return fmt.Errorf("failed to block port %d: %w", port, err)
	}
	return nil
}

func (m *MapManager) UnblockPort(port uint16) error {
	var val uint8 = 0
	var key uint32 = uint32(port)
	if err := m.portGateMap.Put(key, val); err != nil {
		return fmt.Errorf("failed to unblock port %d: %w", port, err)
	}
	return nil
}