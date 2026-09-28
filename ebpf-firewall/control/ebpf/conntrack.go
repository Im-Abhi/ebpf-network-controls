package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// ConntrackManager provides an abstraction over the conntrack eBPF map. The
// datapath writes entries only for accepted TCP flows under a default-deny
// policy; the manager lets the control plane list them, clear them, and age
// stale ones out.
type ConntrackManager struct {
	conntrack *ebpf.Map
}

// NewConntrackManager wraps the conntrack map.
func NewConntrackManager(m *ebpf.Map) *ConntrackManager {
	return &ConntrackManager{conntrack: m}
}

// monotonicNanos reads CLOCK_MONOTONIC in nanoseconds, the same clock the
// datapath reads via bpf_ktime_get_ns(), so stored last_seen values can be
// aged accurately.
func monotonicNanos() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("reading monotonic clock: %w", err)
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec), nil
}

// ctEntry converts a raw map key/value into the control-plane representation,
// computing the age relative to nowNs.
func ctEntry(key ctKey, value ctValue, nowNs uint64) server.ConntrackEntry {
	src := make(net.IP, 4)
	binary.LittleEndian.PutUint32(src, key.Saddr)
	dst := make(net.IP, 4)
	binary.LittleEndian.PutUint32(dst, key.Daddr)

	var age float64
	if nowNs > value.LastSeen {
		age = float64(nowNs-value.LastSeen) / float64(time.Second)
	}

	return server.ConntrackEntry{
		Src:        src.String(),
		Dst:        dst.String(),
		Sport:      wireToPort(key.Sport),
		Dport:      wireToPort(key.Dport),
		Protocol:   codeToProto(key.Protocol),
		State:      ctStateString(value.State),
		AgeSeconds: age,
	}
}

// keys collects every key currently in the map. Deletions are performed using
// a snapshot rather than during iteration, which would otherwise invalidate
// the iterator.
func (cm *ConntrackManager) keys() ([]ctKey, error) {
	var (
		keys  []ctKey
		key   ctKey
		value ctValue
	)
	iter := cm.conntrack.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// List returns all current conntrack entries, youngest first is not
// guaranteed. Ages are computed against a single clock reading.
func (cm *ConntrackManager) List() ([]server.ConntrackEntry, error) {
	nowNs, err := monotonicNanos()
	if err != nil {
		return nil, err
	}

	entries := make([]server.ConntrackEntry, 0, 8)
	var (
		key   ctKey
		value ctValue
	)
	iter := cm.conntrack.Iterate()
	for iter.Next(&key, &value) {
		entries = append(entries, ctEntry(key, value, nowNs))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// Clear removes every conntrack entry.
func (cm *ConntrackManager) Clear() error {
	keys, err := cm.keys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := cm.conntrack.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// Reap deletes entries idle for at least idle and returns how many were
// removed. A non-positive idle removes every entry. It collects stale keys
// before deleting so the iterator is not invalidated mid-scan.
func (cm *ConntrackManager) Reap(idle time.Duration) (int, error) {
	nowNs, err := monotonicNanos()
	if err != nil {
		return 0, err
	}

	reapAll := idle <= 0
	var cutoff uint64
	if !reapAll {
		ns := uint64(idle)
		if ns < nowNs {
			cutoff = nowNs - ns
		}
	}

	var (
		stale []ctKey
		key   ctKey
		value ctValue
	)
	iter := cm.conntrack.Iterate()
	for iter.Next(&key, &value) {
		if reapAll || value.LastSeen <= cutoff {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, err
	}

	reaped := 0
	for _, k := range stale {
		if err := cm.conntrack.Delete(k); err != nil {
			return reaped, err
		}
		reaped++
	}
	return reaped, nil
}
