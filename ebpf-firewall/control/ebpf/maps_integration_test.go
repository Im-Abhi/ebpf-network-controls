//go:build linux

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// These integration tests exercise the full map lifecycle against the real
// kernel and require:
//   - a Linux kernel with eBPF support
//   - the generated firewall_bpf.o (run `make generate` first)
//   - root (or CAP_BPF): run with `sudo go test ./control/ebpf/`
//
// The tests use a standalone in-memory LPM_TRIE map so they do not attach the
// XDP program to an interface.

func newTestLpmMap(t *testing.T) *ebpf.Map {
	t.Helper()

	tm, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 64,
		Flags:      uint32(bpfMapFlagNoPrealloc),
	})
	if err != nil {
		t.Fatalf("creating test LPM trie map: %v", err)
	}
	t.Cleanup(func() { tm.Close() })

	return tm
}

// bpfMapFlagNoPrealloc mirrors BPF_F_NO_PREALLOC (1 << 0) from bpf/maps.h.
const bpfMapFlagNoPrealloc = 1 << 0

func TestMapManager_ExactIP(t *testing.T) {
	pm := NewMapManager(newTestLpmMap(t))

	if err := pm.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	ok, err := pm.IsBlocked("1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("IsBlocked(1.2.3.4) = %v, %v; want true", ok, err)
	}

	if err := pm.UnblockIP("1.2.3.4"); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}

	ok, err = pm.IsBlocked("1.2.3.4")
	if err != nil || ok {
		t.Fatalf("IsBlocked(1.2.3.4) after unblock = %v, %v; want false", ok, err)
	}
}

func TestMapManager_LPMMatch(t *testing.T) {
	pm := NewMapManager(newTestLpmMap(t))

	if err := pm.BlockIP("10.0.0.0/8"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	// Covered by 10.0.0.0/8.
	for _, ip := range []string{"10.0.0.1", "10.20.30.40", "10.255.1.1"} {
		if ok, err := pm.IsBlocked(ip); err != nil || !ok {
			t.Errorf("IsBlocked(%s) = %v, %v; want true", ip, ok, err)
		}
	}

	// Not covered.
	for _, ip := range []string{"11.0.0.1", "9.255.255.255", "172.16.0.1"} {
		if ok, err := pm.IsBlocked(ip); err != nil || ok {
			t.Errorf("IsBlocked(%s) = %v, %v; want false", ip, ok, err)
		}
	}
}

func TestMapManager_OverlappingPrefixes(t *testing.T) {
	pm := NewMapManager(newTestLpmMap(t))

	if err := pm.BlockIP("10.0.0.0/8"); err != nil {
		t.Fatalf("BlockIP /8: %v", err)
	}
	if err := pm.BlockIP("10.1.2.3/32"); err != nil {
		t.Fatalf("BlockIP /32: %v", err)
	}

	// Unblocking the /32 must not unblock the /8 that also covers 10.1.2.3.
	if err := pm.UnblockIP("10.1.2.3"); err != nil {
		t.Fatalf("UnblockIP /32: %v", err)
	}

	ok, err := pm.IsBlocked("10.1.2.3")
	if err != nil || !ok {
		t.Errorf("IsBlocked(10.1.2.3) after unblocking /32 = %v, %v; want true (still /8)", ok, err)
	}

	ok, err = pm.IsBlocked("10.5.5.5")
	if err != nil || !ok {
		t.Errorf("IsBlocked(10.5.5.5) = %v, %v; want true", ok, err)
	}
}

func TestMapManager_ListAndClear(t *testing.T) {
	pm := NewMapManager(newTestLpmMap(t))

	if err := pm.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := pm.BlockIP("10.0.0.0/8"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	list, err := pm.ListBlockedIPs()
	if err != nil {
		t.Fatalf("ListBlockedIPs: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("ListBlockedIPs len = %d, want 2 (got %v)", len(list), list)
	}

	if err := pm.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	list, err = pm.ListBlockedIPs()
	if err != nil {
		t.Fatalf("ListBlockedIPs after clear: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("ListBlockedIPs after clear len = %d, want 0", len(list))
	}

	ok, err := pm.IsBlocked("1.2.3.4")
	if err != nil || ok {
		t.Errorf("IsBlocked(1.2.3.4) after clear = %v, %v; want false", ok, err)
	}
}

func TestMapManager_InvalidInputs(t *testing.T) {
	pm := NewMapManager(newTestLpmMap(t))

	for _, bad := range []string{"", "not-an-ip", "::1", "fe80::1"} {
		if err := pm.BlockIP(bad); err == nil {
			t.Errorf("BlockIP(%q) expected error, got nil", bad)
		}
		if err := pm.UnblockIP(bad); err == nil {
			t.Errorf("UnblockIP(%q) expected error, got nil", bad)
		}
		if _, err := pm.IsBlocked(bad); err == nil {
			t.Errorf("IsBlocked(%q) expected error, got nil", bad)
		}
	}
}
