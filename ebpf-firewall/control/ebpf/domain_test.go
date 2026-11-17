package ebpf

import "testing"

// Pure tests for the domain blocklist key normalization (no kernel
// required). The contract being pinned: the loader's keys must be
// byte-identical to what the datapath's domain_block_action probes —
// lowercase, truncated at 63 bytes (DOMAIN_NAME_MAX), zero-padded.

func TestDomainKeyOf_NormalizesCase(t *testing.T) {
	key, err := domainKeyOf("BADSITE.Com")
	if err != nil {
		t.Fatalf("domainKeyOf: %v", err)
	}
	want := "badsite.com"
	for i := 0; i < len(want); i++ {
		if key.Name[i] != int8(want[i]) {
			t.Errorf("Name[%d] = %q, want %q", i, rune(key.Name[i]), rune(want[i]))
		}
	}
	// everything past the name must be zero-padded
	for i := len(want); i < domainNameMax+1; i++ {
		if key.Name[i] != 0 {
			t.Fatalf("Name[%d] = %d, want 0 (zero padding)", i, key.Name[i])
		}
	}
}

func TestDomainKeyOf_TruncatesAt63(t *testing.T) {
	// 70 bytes: only the first 63 may survive, matching the datapath's
	// DOMAIN_NAME_MAX truncation.
	long := ""
	for len(long) < 70 {
		long += "abcdefghij"
	}
	key, err := domainKeyOf(long)
	if err != nil {
		t.Fatalf("domainKeyOf: %v", err)
	}
	for i := 0; i < domainNameMax; i++ {
		if key.Name[i] != int8(long[i]) {
			t.Errorf("Name[%d] = %q, want %q (truncated name keeps the first 63 bytes)",
				i, rune(key.Name[i]), rune(long[i]))
		}
	}
	if key.Name[domainNameMax] != 0 {
		t.Errorf("Name[63] = %d, want 0 (key holds exactly 63 name bytes)", key.Name[63])
	}
}

func TestDomainKeyOf_RejectsEmpty(t *testing.T) {
	for _, bad := range []string{"", "   "} {
		if _, err := domainKeyOf(bad); err == nil {
			t.Errorf("domainKeyOf(%q): expected error, got nil", bad)
		}
	}
}

func TestDomainPresenceBitIsDisjoint(t *testing.T) {
	// The domain bit (egress-only) must not collide with any other table's
	// bit, or one hook's fast-path flag could gate another's lookups.
	other := rulePresenceIP | rulePresencePort |
		rulePresenceEgressIP | rulePresenceEgressPort
	if rulePresenceDomain&other != 0 {
		t.Errorf("domain bit %#x overlaps another table's bit", rulePresenceDomain)
	}
}
