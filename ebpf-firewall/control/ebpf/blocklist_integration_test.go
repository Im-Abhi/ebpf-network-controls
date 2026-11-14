//go:build integration

package ebpf

import (
	"testing"

	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf"
)

// These integration tests exercise the cidrTable (tables.go) against the real
// kernel and require:
//   - a Linux kernel with eBPF support
//   - the generated firewall_bpf.o (run `make generate` first)
//   - root (or CAP_BPF): run with `sudo go test ./control/ebpf/`
//
// The tests use a standalone in-memory LPM_TRIE map so they do not attach the
// XDP program to an interface. A nil presence map disables the fast-path flag
// maintenance, which the datapath tests cover separately.

func newTestLpmMap(t *testing.T) *ebpf.Map {
	t.Helper()

	tm, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		KeySize:    8,
		ValueSize:  8, // struct rule_value (action + priority)
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

func TestCidrTable_ExactIP(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	if err := tbl.Add("1.2.3.4", ActionDrop, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ok, err := tbl.Contains("1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("Contains(1.2.3.4) = %v, %v; want true", ok, err)
	}

	if err := tbl.Remove("1.2.3.4"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	ok, err = tbl.Contains("1.2.3.4")
	if err != nil || ok {
		t.Fatalf("Contains(1.2.3.4) after remove = %v, %v; want false", ok, err)
	}
}

func TestCidrTable_LPMMatch(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	if err := tbl.Add("10.0.0.0/8", ActionDrop, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Covered by 10.0.0.0/8.
	for _, ip := range []string{"10.0.0.1", "10.20.30.40", "10.255.1.1"} {
		if ok, err := tbl.Contains(ip); err != nil || !ok {
			t.Errorf("Contains(%s) = %v, %v; want true", ip, ok, err)
		}
	}

	// Not covered.
	for _, ip := range []string{"11.0.0.1", "9.255.255.255", "172.16.0.1"} {
		if ok, err := tbl.Contains(ip); err != nil || ok {
			t.Errorf("Contains(%s) = %v, %v; want false", ip, ok, err)
		}
	}
}

func TestCidrTable_OverlappingPrefixes(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	if err := tbl.Add("10.0.0.0/8", ActionDrop, 0); err != nil {
		t.Fatalf("Add /8: %v", err)
	}
	if err := tbl.Add("10.1.2.3/32", ActionDrop, 0); err != nil {
		t.Fatalf("Add /32: %v", err)
	}

	// Removing the /32 must not remove the /8 that also covers 10.1.2.3.
	if err := tbl.Remove("10.1.2.3"); err != nil {
		t.Fatalf("Remove /32: %v", err)
	}

	ok, err := tbl.Contains("10.1.2.3")
	if err != nil || !ok {
		t.Errorf("Contains(10.1.2.3) after removing /32 = %v, %v; want true (still /8)", ok, err)
	}

	ok, err = tbl.Contains("10.5.5.5")
	if err != nil || !ok {
		t.Errorf("Contains(10.5.5.5) = %v, %v; want true", ok, err)
	}
}

func TestCidrTable_ListAndClear(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	for _, cidr := range []string{"1.2.3.4", "10.0.0.0/8", "192.168.0.0/16"} {
		if err := tbl.Add(cidr, ActionDrop, 0); err != nil {
			t.Fatalf("Add(%s): %v", cidr, err)
		}
	}

	list, err := tbl.CIDRs()
	if err != nil {
		t.Fatalf("CIDRs: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("CIDRs len = %d, want 3 (got %v)", len(list), list)
	}

	if err := tbl.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	list, err = tbl.CIDRs()
	if err != nil {
		t.Fatalf("CIDRs after clear: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("CIDRs after clear len = %d, want 0", len(list))
	}

	ok, err := tbl.Contains("1.2.3.4")
	if err != nil || ok {
		t.Errorf("Contains(1.2.3.4) after clear = %v, %v; want false", ok, err)
	}
}

func TestCidrTable_PriorityRoundTrip(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	if err := tbl.Add("1.2.3.4", ActionDrop, 100); err != nil {
		t.Fatalf("Add(drop,100): %v", err)
	}
	if err := tbl.Add("10.0.0.0/8", ActionPass, 7); err != nil {
		t.Fatalf("Add(pass,7): %v", err)
	}

	rules, err := tbl.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("List len = %d, want 2 (%+v)", len(rules), rules)
	}

	byCidr := make(map[string]server.BlockedRule, len(rules))
	for _, r := range rules {
		byCidr[r.Cidr] = r
	}
	if r := byCidr["1.2.3.4/32"]; r.Action != "drop" || r.Priority != 100 {
		t.Errorf("1.2.3.4/32 = %+v, want action drop priority 100", r)
	}
	if r := byCidr["10.0.0.0/8"]; r.Action != "pass" || r.Priority != 7 {
		t.Errorf("10.0.0.0/8 = %+v, want action pass priority 7", r)
	}
}

func TestCidrTable_InvalidInputs(t *testing.T) {
	tbl := newCidrTable(newTestLpmMap(t), nil, 0)

	for _, bad := range []string{"", "not-an-ip", "::1", "fe80::1"} {
		if err := tbl.Add(bad, ActionDrop, 0); err == nil {
			t.Errorf("Add(%q) expected error, got nil", bad)
		}
		if err := tbl.Remove(bad); err == nil {
			t.Errorf("Remove(%q) expected error, got nil", bad)
		}
		if _, err := tbl.Contains(bad); err == nil {
			t.Errorf("Contains(%q) expected error, got nil", bad)
		}
	}
}
