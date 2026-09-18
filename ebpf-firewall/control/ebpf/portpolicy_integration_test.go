//go:build integration

package ebpf

import (
	"strconv"
	"testing"

	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf"
)

// newTestPortPolicyMap creates a standalone hash map matching the port_policy
// map layout (12-byte key, 8-byte value) without attaching any XDP program.
func newTestPortPolicyMap(t *testing.T) *ebpf.Map {
	t.Helper()

	tm, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    12, // firewallPortRuleKey
		ValueSize:  8,  // struct rule_value (action + priority)
		MaxEntries: 65535,
	})
	if err != nil {
		t.Fatalf("creating test port-policy map: %v", err)
	}
	t.Cleanup(func() { tm.Close() })

	return tm
}

func TestPortPolicyManager_RoundTrip(t *testing.T) {
	pm := NewPortPolicyManager(newTestPortPolicyMap(t))

	if err := pm.Block("10.153.245.175", "tcp", 22); err != nil {
		t.Fatalf("Block tcp/22: %v", err)
	}
	if err := pm.Block("8.8.8.8", "udp", 53); err != nil {
		t.Fatalf("Block udp/53: %v", err)
	}

	rules, err := pm.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("List len = %d, want 2 (%v)", len(rules), rules)
	}

	want := map[string]bool{
		"tcp/22->10.153.245.175": true,
		"udp/53->8.8.8.8":        true,
	}
	for _, r := range rules {
		key := r.Protocol + "/" + strconv.Itoa(int(r.Port)) + "->" + r.Dst
		if !want[key] {
			t.Errorf("unexpected rule %q (dport %d)", key, r.Port)
		}
	}

	if err := pm.Unblock("8.8.8.8", "udp", 53); err != nil {
		t.Fatalf("Unblock udp/53: %v", err)
	}
	rules, err = pm.List()
	if err != nil {
		t.Fatalf("List after unblock: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("List after unblock len = %d, want 1", len(rules))
	}

	if err := pm.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	rules, err = pm.List()
	if err != nil {
		t.Fatalf("List after clear: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("List after clear len = %d, want 0", len(rules))
	}
}

func TestPortPolicyManager_PriorityRoundTrip(t *testing.T) {
	pm := NewPortPolicyManager(newTestPortPolicyMap(t))

	if err := pm.BlockWithActionPriority("1.2.3.4", "tcp", 22, 0, ActionPass, 100); err != nil {
		t.Fatalf("BlockWithActionPriority(pass,100): %v", err)
	}
	if err := pm.BlockWithActionPriority("5.6.7.8", "udp", 53, 0, ActionDrop, 3); err != nil {
		t.Fatalf("BlockWithActionPriority(drop,3): %v", err)
	}

	rules, err := pm.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("List len = %d, want 2 (%+v)", len(rules), rules)
	}

	byDst := make(map[string]server.PortRule, len(rules))
	for _, r := range rules {
		byDst[r.Dst] = r
	}
	if r := byDst["1.2.3.4"]; r.Action != "pass" || r.Priority != 100 {
		t.Errorf("1.2.3.4 = %+v, want action pass priority 100", r)
	}
	if r := byDst["5.6.7.8"]; r.Action != "drop" || r.Priority != 3 {
		t.Errorf("5.6.7.8 = %+v, want action drop priority 3", r)
	}
}

func TestPortPolicyManager_InvalidInputs(t *testing.T) {
	pm := NewPortPolicyManager(newTestPortPolicyMap(t))

	for _, bad := range []string{"", "not-an-ip", "::1", "10.0.0.0/8"} {
		if err := pm.Block(bad, "tcp", 22); err == nil {
			t.Errorf("Block(%q): expected error, got nil", bad)
		}
	}
	if err := pm.Block("1.2.3.4", "icmp", 0); err == nil {
		t.Error("Block with unsupported protocol: expected error, got nil")
	}
	if err := pm.Block("1.2.3.4", "tcp", 22); err != nil {
		t.Errorf("Block valid rule: %v", err)
	}
}
