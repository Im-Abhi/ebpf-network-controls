package ebpf

import (
	"encoding/binary"
	"testing"
)

// Pure tests for the key builders shared by the ingress PortPolicyManager and
// the egress EgressPolicyManager. They verify the on-wire byte layout matches
// struct port_rule_key in bpf/maps.h (no kernel required).

func TestBuildPortRuleKey_BytesPreserved(t *testing.T) {
	key, err := buildPortRuleKey("1.2.3.4", 6, 443, 50000)
	if err != nil {
		t.Fatalf("buildPortRuleKey: %v", err)
	}

	if key.Protocol != 6 {
		t.Errorf("Protocol = %d, want tcp (6)", key.Protocol)
	}

	// Dst must reproduce the network-order bytes [1 2 3 4] in memory.
	var mem [4]byte
	binary.LittleEndian.PutUint32(mem[:], key.Dst)
	if mem != [4]byte{1, 2, 3, 4} {
		t.Errorf("Dst bytes = %v, want [1 2 3 4]", mem)
	}

	// Ports must be stored htons (network byte order): the datapath compares
	// them against tcp->source / tcp->dest raw bytes. On a little-endian host
	// the stored word is the swapped wire bytes, e.g. port 443 (0x01BB) is
	// stored as 0xBB01 so its memory bytes read back [0x01, 0xBB].
	if key.Dport != portToWire(443) || key.Dport != 0xBB01 {
		t.Errorf("Dport wire value = %#x, want 0xBB01 (htons(443))", key.Dport)
	}
	if key.Sport != portToWire(50000) || key.Sport != 0x50C3 {
		t.Errorf("Sport wire value = %#x, want 0x50C3 (htons(50000))", key.Sport)
	}
	if got := wireToPort(key.Dport); got != 443 {
		t.Errorf("wireToPort(Dport) = %d, want 443", got)
	}
	if got := wireToPort(key.Sport); got != 50000 {
		t.Errorf("wireToPort(Sport) = %d, want 50000", got)
	}
}

func TestBuildPortRuleKey_InvalidDst(t *testing.T) {
	if _, err := buildPortRuleKey("not-an-ip", 6, 80, 0); err == nil {
		t.Errorf("buildPortRuleKey with invalid dst: expected error, got nil")
	}
	// IPv6 is not supported by the map layout, so it must be rejected.
	if _, err := buildPortRuleKey("2001:db8::1", 6, 80, 0); err == nil {
		t.Errorf("buildPortRuleKey with IPv6 dst: expected error, got nil")
	}
}

func TestEgressPresenceBitsAreDisjoint(t *testing.T) {
	// The ingress managers own bits 0-1; the egress managers bits 2-3. Verify
	// the constants never overlap so one hook's fast-path flag cannot clear
	// the other's.
	if rulePresenceEgressIP&(rulePresenceIP|rulePresencePort) != 0 {
		t.Errorf("egress IP bit %#x overlaps an ingress bit", rulePresenceEgressIP)
	}
	if rulePresenceEgressPort&(rulePresenceIP|rulePresencePort) != 0 {
		t.Errorf("egress port bit %#x overlaps an ingress bit", rulePresenceEgressPort)
	}
	if rulePresenceEgressIP == rulePresenceEgressPort {
		t.Errorf("egress IP and port bits must differ, both %#x", rulePresenceEgressIP)
	}
}