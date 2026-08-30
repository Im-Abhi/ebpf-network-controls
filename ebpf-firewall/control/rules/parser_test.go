package rules

import (
	"reflect"
	"testing"
)

func TestParseIPOrCIDR_Valid(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantMask int // prefix length
	}{
		{"1.2.3.4", "1.2.3.4", 32},
		{"1.2.3.0/24", "1.2.3.0", 24},
		{"10.0.0.0/8", "10.0.0.0", 8},
		{"0.0.0.0/0", "0.0.0.0", 0},
		{" 192.168.1.5 ", "192.168.1.5", 32},
		{"10.1.2.3/16", "10.1.0.0", 16},
	}

	for _, c := range cases {
		got, err := ParseIPOrCIDR(c.in)
		if err != nil {
			t.Errorf("ParseIPOrCIDR(%q) unexpected error: %v", c.in, err)
			continue
		}

		ip := got.IP.String()
		if ip != c.wantIP {
			t.Errorf("ParseIPOrCIDR(%q) IP = %q, want %q", c.in, ip, c.wantIP)
		}

		ones, _ := got.Mask.Size()
		if ones != c.wantMask {
			t.Errorf("ParseIPOrCIDR(%q) mask = %d, want %d", c.in, ones, c.wantMask)
		}

		if len(got.IP) != 4 {
			t.Errorf("ParseIPOrCIDR(%q) len(IP) = %d, want 4", c.in, len(got.IP))
		}
	}
}

func TestParseIPOrCIDR_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"   ",
		"invalid IP",
		"1.2.3",
		"1.2.3.4.5",
		"1.2.3.999",
		"1.2.3.4/33",  // prefix out of range
		"1.2.3.4/8",   // host bits set (still parses and masks, valid)
		"300.1.1.1",
		"::1",          // IPv6
		"fe80::1",      // IPv6
		"1.2.3.4/abc",  // non-numeric prefix
		"net/24",       // non-IP host
	}

	for _, s := range invalid {
		if s == "1.2.3.4/8" {
			// net.ParseCIDR accepts host bits and masks them; that's fine.
			continue
		}
		if _, err := ParseIPOrCIDR(s); err == nil {
			t.Errorf("ParseIPOrCIDR(%q) expected error, got nil", s)
		}
	}
}

func TestParseIPOrCIDR_NormalizesHostBits(t *testing.T) {
	// "10.1.2.3/16" should normalize to the network address 10.1.0.0/16.
	got, err := ParseIPOrCIDR("10.1.2.3/16")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "10.1.0.0"
	if got.IP.String() != want {
		t.Errorf("normalized IP = %q, want %q", got.IP.String(), want)
	}
}

func TestParseIPOrCIDR_ReturnsFourByteForm(t *testing.T) {
	got, err := ParseIPOrCIDR("1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{1, 2, 3, 4}
	if !reflect.DeepEqual([]byte(got.IP), want) {
		t.Errorf("IP bytes = %v, want %v", []byte(got.IP), want)
	}
}
