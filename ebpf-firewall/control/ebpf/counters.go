package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"

	"ebpf-firewall/control/server"
)

// Counter indices must match enum counter_index in bpf/maps.h. Indices 0-2 are
// the ingress counters consumed by the XDP datapath; 3-5 are the egress
// counters consumed by the TC egress datapath, in the same total/drop/pass
// arrangement so GetCounters-like reads can share the loop bounds.
const (
	counterTotal  = 0
	counterDrop   = 1
	counterPass   = 2
	counterMax    = 3

	egressCounterTotal = 3
	egressCounterDrop  = 4
	egressCounterPass  = 5
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

// GetCounters reads the three ingress counter slots (total, drop, pass) and
// returns them as a server.Stats struct.
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

// GetEgressCounters reads the three egress counter slots (3-5) and returns
// them as a server.Stats struct, mirroring GetCounters.
func (cm *CounterManager) GetEgressCounters() (server.Stats, error) {
	var stats server.Stats
	for i := uint32(egressCounterTotal); i <= egressCounterPass; i++ {
		var val counterValue
		if err := cm.counters.Lookup(i, &val); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return server.Stats{}, err
		}
		switch i {
		case egressCounterTotal:
			stats.TotalPackets = val.Packets
			stats.TotalBytes = val.Bytes
		case egressCounterDrop:
			stats.DropPackets = val.Packets
			stats.DropBytes = val.Bytes
		case egressCounterPass:
			stats.PassPackets = val.Packets
			stats.PassBytes = val.Bytes
		}
	}
	return stats, nil
}
