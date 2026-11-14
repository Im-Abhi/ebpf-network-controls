package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"

	"ebpf-firewall/control/server"
)

// Counter indices must match enum counter_index in bpf/maps.h. Indices 0-2
// are the ingress counters consumed by the XDP datapath; 3-5 are the egress
// counters consumed by the TC egress datapath, in the same total/drop/pass
// arrangement so a single countersAt(base) read serves both directions.
const (
	counterIngressBase = 0 // ingress base index
	counterEgressBase  = 3 // egress base index

	slotTotal = 0 // offset within a direction's block: total
	slotDrop  = 1 //                                               drop
	slotPass  = 2 //                                               pass

	countersPerDir = 3
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

// countersAt reads the three counter slots starting at base (total, drop,
// pass) and returns them as a server.Stats struct. The ingress counters live
// at base 0, the egress counters at base 3, in the same arrangement.
func (cm *CounterManager) countersAt(base uint32) (server.Stats, error) {
	var stats server.Stats
	for i := uint32(0); i < countersPerDir; i++ {
		var val counterValue
		if err := cm.counters.Lookup(base+i, &val); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return server.Stats{}, err
		}
		switch i {
		case slotTotal:
			stats.TotalPackets = val.Packets
			stats.TotalBytes = val.Bytes
		case slotDrop:
			stats.DropPackets = val.Packets
			stats.DropBytes = val.Bytes
		case slotPass:
			stats.PassPackets = val.Packets
			stats.PassBytes = val.Bytes
		}
	}
	return stats, nil
}

// GetCounters reads the three ingress counter slots (total, drop, pass) and
// returns them as a server.Stats struct.
func (cm *CounterManager) GetCounters() (server.Stats, error) {
	return cm.countersAt(counterIngressBase)
}

// GetEgressCounters reads the three egress counter slots (3-5) and returns
// them as a server.Stats struct.
func (cm *CounterManager) GetEgressCounters() (server.Stats, error) {
	return cm.countersAt(counterEgressBase)
}
