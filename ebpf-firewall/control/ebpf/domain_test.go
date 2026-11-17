package ebpf

import "testing"

// Pure tests for the domain blocklist key normalization (no kernel
// required). The contract being pinned: the loader's keys must be
// byte-identical to what the datapath's domain_block_action probes —
// lowercase, truncated at 63 bytes (DOMAIN_NAME_MAX), REVERSED, with the
// effective length in Prefixlen (bits). The reversal is what makes a
// parent suffix a byte prefix of the reversed name, so the LPM trie
// covers subdomains with one lookup.

func TestDomainKeyOf_NormalizesAndReverses(t *testing.T) {
	key, err := domainKeyOf("BADSITE.Com")
	if err != nil {
		t.Fatalf("domainKeyOf: %v", err)
	}
	want := "badsite.com" // lowercased
	if key.Prefixlen != uint32(len(want)*8) {
		t.Errorf("Prefixlen = %d, want %d", key.Prefixlen, len(want)*8)
	}
	for i := 0; i < len(want); i++ {
		if key.Name[i] != want[len(want)-1-i] {
			t.Errorf("Name[%d] = %q, want %q (reversed)", i, rune(key.Name[i]), rune(want[len(want)-1-i]))
		}
	}
	// everything past the name must be zero-padded
	for i := len(want); i < domainNameMax+1; i++ {
		if key.Name[i] != 0 {
			t.Fatalf("Name[%d] = %d, want 0 (zero padding)", i, key.Name[i])
		}
	}
}

func TestDomainKeyOf_SuffixIsBytePrefix(t *testing.T) {
	// The property the LPM design depends on: a parent suffix, reversed,
	// is a byte prefix of the reversed full name. "sub.badsite.com"
	// reversed starts with "moc.etis dab" — precisely the reversed
	// "badsite.com".
	full, err := domainKeyOf("sub.badsite.com")
	if err != nil {
		t.Fatalf("domainKeyOf(sub): %v", err)
	}
	parent, err := domainKeyOf("badsite.com")
	if err != nil {
		t.Fatalf("domainKeyOf(parent): %v", err)
	}
	pn := int(parent.Prefixlen / 8)
	for i := 0; i < pn; i++ {
		if full.Name[i] != parent.Name[i] {
			t.Fatalf("reversed parent suffix is not a prefix at byte %d", i)
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
	if key.Prefixlen != uint32(domainNameMax*8) {
		t.Errorf("Prefixlen = %d, want %d", key.Prefixlen, domainNameMax*8)
	}
	for i := 0; i < domainNameMax; i++ {
		if key.Name[i] != long[domainNameMax-1-i] {
			t.Errorf("Name[%d] = %q, want %q (truncated name keeps the first 63 bytes, reversed)",
				i, rune(key.Name[i]), rune(long[domainNameMax-1-i]))
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
