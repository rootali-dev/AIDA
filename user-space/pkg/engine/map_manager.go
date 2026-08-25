package engine

import (
	"errors"
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
	configMap     *ebpf.Map
	eventsMap     *ebpf.Map
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

	cfgMap, err := ebpf.LoadPinnedMap(filepath.Join(BpfFsPath, "config_map"), nil)
	if err != nil {
		repMap.Close()
		portMap.Close()
		rateMap.Close()
		return nil, fmt.Errorf("failed to open config_map: %w", err)
	}

	eventsMap, err := ebpf.LoadPinnedMap(filepath.Join(BpfFsPath, "events"), nil)
	if err != nil {
		repMap.Close()
		portMap.Close()
		rateMap.Close()
		cfgMap.Close()
		return nil, fmt.Errorf("failed to open events ringbuf map: %w", err)
	}

	return &MapManager{
		reputationMap: repMap,
		portGateMap:   portMap,
		rateLimitMap:  rateMap,
		configMap:     cfgMap,
		eventsMap:     eventsMap,
	}, nil
}

func (m *MapManager) Close() {
	if m.reputationMap != nil {
		m.reputationMap.Close()
	}
	if m.portGateMap != nil {
		m.portGateMap.Close()
	}
	if m.rateLimitMap != nil {
		m.rateLimitMap.Close()
	}
	if m.configMap != nil {
		m.configMap.Close()
	}
	if m.eventsMap != nil {
		m.eventsMap.Close()
	}
}

func (m *MapManager) GetEventsMap() *ebpf.Map {
	return m.eventsMap
}

func (m *MapManager) SetLogLevel(level types.LogSeverity) error {
	var key uint32 = 0
	var val uint32 = uint32(level)
	if err := m.configMap.Put(key, val); err != nil {
		return fmt.Errorf("failed to update config_map log level to %s (%d): %w", level, val, err)
	}
	return nil
}

func (m *MapManager) GetLogLevel() (types.LogSeverity, error) {
	var key uint32 = 0
	var val uint32
	if err := m.configMap.Lookup(key, &val); err != nil {
		return types.LogLevelOff, fmt.Errorf("failed to lookup config_map log level: %w", err)
	}
	return types.LogSeverity(val), nil
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

// UnblockIP removes a previously-blocked CIDR/host from REPUTATION_MAP. This
// is the counterpart the TTL Janitor (engine/feedback.go) calls when a
// dynamic auto-block expires — without it, every ML-triggered block would be
// permanent, which is exactly the lockout risk the Janitor exists to close.
//
// Deleting an already-absent key is treated as success (idempotent): the
// Janitor and an operator's manual `ai-ida-control unblock` could race
// harmlessly on the same expiring entry, and neither should surface as an
// error.
func (m *MapManager) UnblockIP(cidr string) error {
	key, err := types.NewLpmKey(cidr)
	if err != nil {
		return err
	}

	if err := m.reputationMap.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("failed to remove IP from BPF LPM_TRIE: %w", err)
	}

	return nil
}

// SetDryRun toggles CONFIG_MAP[1] (DRY_RUN_MODE). true = Dry-Run (every
// would-be XDP_DROP is downgraded to XDP_PASS at the wire, with
// Action::WouldDrop telemetry); false = Enforce (real drops).
func (m *MapManager) SetDryRun(enabled bool) error {
	var key uint32 = 1
	var val uint32
	if enabled {
		val = 1
	}
	if err := m.configMap.Put(key, val); err != nil {
		return fmt.Errorf("failed to update config_map dry-run flag: %w", err)
	}
	return nil
}

// GetDryRun reads CONFIG_MAP[1]. Kernels built before this map was expanded
// to max_entries=2 will return ebpf.ErrKeyNotExist here; callers should treat
// that the same as "dry-run unsupported / disabled" (false, nil) rather than
// a hard failure, since it's a legitimate pre-upgrade kernel state, not a
// runtime error.
func (m *MapManager) GetDryRun() (bool, error) {
	var key uint32 = 1
	var val uint32
	if err := m.configMap.Lookup(key, &val); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("failed to lookup config_map dry-run flag: %w", err)
	}
	return val == 1, nil
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
