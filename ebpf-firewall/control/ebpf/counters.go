package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"

	"ebpf-firewall/control/server"
)

// Counter indices must match enum counter_index in bpf/maps.h.
const (
	counterTotal = 0
	counterDrop  = 1
	counterPass  = 2
	counterMax   = 3
)

// counterValue matches struct counter_value in bpf/maps.h (16 bytes).
type counterValue struct {
	Packets uint64
	Bytes   uint64
}

// CounterManager reads the global counters BPF map.
type CounterManager struct {
	counters *ebpf.Map
}

// NewCounterManager wraps the counters map for reading.
func NewCounterManager(m *ebpf.Map) *CounterManager {
	return &CounterManager{counters: m}
}

// GetCounters reads all three counter slots (total, drop, pass) and returns
// them as a server.Stats struct.
func (cm *CounterManager) GetCounters() (server.Stats, error) {
	var stats server.Stats
	for i := uint32(0); i < counterMax; i++ {
		var val counterValue
		if err := cm.counters.Lookup(i, &val); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return server.Stats{}, err
		}
		switch i {
		case counterTotal:
			stats.TotalPackets = val.Packets
			stats.TotalBytes = val.Bytes
		case counterDrop:
			stats.DropPackets = val.Packets
			stats.DropBytes = val.Bytes
		case counterPass:
			stats.PassPackets = val.Packets
			stats.PassBytes = val.Bytes
		}
	}
	return stats, nil
}
