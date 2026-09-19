//go:build integration

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// newTestConntrackMap creates a standalone hash map matching the conntrack map
// layout (16-byte key, 16-byte value) without attaching any XDP program.
func newTestConntrackMap(t *testing.T) *ebpf.Map {
	t.Helper()

	tm, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    16, // ctKey
		ValueSize:  16, // ctValue
		MaxEntries: 64,
	})
	if err != nil {
		t.Fatalf("creating test conntrack map: %v", err)
	}
	t.Cleanup(func() { tm.Close() })

	return tm
}

// putCt inserts a flow directly into the given map, mirroring what the
// datapath's ct_update would write after accepting a packet.
func putCt(t *testing.T, m *ebpf.Map, src, dst string, sport, dport uint16, state uint32, lastSeen uint64) {
	t.Helper()
	key := ctKey{
		Saddr:    binary.LittleEndian.Uint32(net.ParseIP(src).To4()),
		Daddr:    binary.LittleEndian.Uint32(net.ParseIP(dst).To4()),
		Sport:    portToWire(sport),
		Dport:    portToWire(dport),
		Protocol: protoTCP,
	}
	if err := m.Put(key, ctValue{LastSeen: lastSeen, State: state}); err != nil {
		t.Fatalf("Put %s:%d->%s:%d: %v", src, sport, dst, dport, err)
	}
}

func TestConntrackManager_ListAndClear(t *testing.T) {
	cm := NewConntrackManager(newTestConntrackMap(t))
	now, err := monotonicNanos()
	if err != nil {
		t.Fatalf("monotonicNanos: %v", err)
	}

	putCt(t, cm.conntrack, "10.0.0.1", "1.2.3.4", 50000, 22, ctStateEstablished, now-2_000_000_000)
	putCt(t, cm.conntrack, "10.0.0.2", "1.2.3.5", 50001, 80, ctStateNew, now)

	entries, err := cm.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List len = %d, want 2 (%+v)", len(entries), entries)
	}

	bySport := make(map[uint16]string, len(entries))
	for _, e := range entries {
		if e.Protocol != "tcp" {
			t.Errorf("protocol = %q, want tcp", e.Protocol)
		}
		stateOK := e.State == "established" || e.State == "new"
		if !stateOK {
			t.Errorf("state = %q, want new or established", e.State)
		}
		bySport[e.Sport] = e.State
		if e.Sport == 50000 && e.AgeSeconds >= 3 {
			t.Errorf("age = %.1fs, want ~2s", e.AgeSeconds)
		}
	}
	if bySport[50000] != "established" || bySport[50001] != "new" {
		t.Errorf("states by sport = %v, want {50000: established, 50001: new}", bySport)
	}

	if err := cm.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if entries, err = cm.List(); err != nil {
		t.Fatalf("List after clear: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("List after clear len = %d, want 0", len(entries))
	}
}

func TestConntrackManager_Reap(t *testing.T) {
	cm := NewConntrackManager(newTestConntrackMap(t))
	now, err := monotonicNanos()
	if err != nil {
		t.Fatalf("monotonicNanos: %v", err)
	}
	idle := 2 * time.Minute

	// Two stale entries (one established, one closed) and one fresh one.
	putCt(t, cm.conntrack, "10.0.0.1", "1.2.3.4", 50000, 22, ctStateEstablished, now-uint64(4*time.Minute))
	putCt(t, cm.conntrack, "10.0.0.2", "1.2.3.5", 50001, 80, ctStateClosed, now-uint64(3*time.Minute))
	putCt(t, cm.conntrack, "10.0.0.3", "1.2.3.6", 50002, 443, ctStateNew, now-uint64(10*time.Second))

	n, err := cm.Reap(idle)
	if err != nil {
		t.Fatalf("Reap: %v", err)
	}
	if n != 2 {
		t.Fatalf("Reap removed %d, want 2", n)
	}

	entries, err := cm.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Sport != 50002 {
		t.Fatalf("remaining entries = %+v, want only sport 50002", entries)
	}
}
