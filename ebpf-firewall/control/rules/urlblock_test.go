package rules

import (
	"strings"
	"testing"
)

func TestNormalizeBlocklistHost(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"badsite.com", "badsite.com"},
		{"BADSITE.COM", "badsite.com"},
		{"https://badsite.com", "badsite.com"},
		{"http://badsite.com/track?x=1", "badsite.com"},
		{"https://user:pass@badsite.com:8443/p/a?b=c#f", "badsite.com"},
		{"badsite.com:8443", "badsite.com"},
		{"badsite.com.", "badsite.com"},    // fully-qualified trailing dot
		{"  badsite.com  ", "badsite.com"}, // surrounding whitespace
		{"localhost", "localhost"},         // single label is legitimate
		{"# comment", ""},                  // comment → not content
		{"", ""},                           // blank → not content
		{"https://", ""},                   // nothing left after stripping
	} {
		if got := normalizeBlocklistHost(tc.raw); got != tc.want {
			t.Errorf("normalizeBlocklistHost(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestParseBlocklist_MixedFile(t *testing.T) {
	in := strings.Join([]string{
		"# ads and trackers",
		"badsite.com",
		"",                              // blank
		"https://ads.example.com/pixel", // URL → host only
		"203.0.113.9",                   // bare IP → egress IP table
		"BADSITE.Com",                   // duplicate after normalization
		"::1",                           // IPv6 → warning
		"*.example.net",                 // wildcard → warning
		"bücher.de",                     // non-ASCII → warning (use punycode)
		"under_scores.example",          // invalid label char → warning
	}, "\r\n") // CRLF endings must be tolerated

	res, err := ParseBlocklist(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseBlocklist: %v", err)
	}

	wantDomains := []string{"badsite.com", "ads.example.com", "badsite.com"}
	if len(res.Domains) != len(wantDomains) {
		t.Fatalf("Domains = %v, want %v", res.Domains, wantDomains)
	}
	for i, d := range wantDomains {
		if res.Domains[i] != d {
			t.Errorf("Domains[%d] = %q, want %q", i, res.Domains[i], d)
		}
	}
	if len(res.IPs) != 1 || res.IPs[0] != "203.0.113.9" {
		t.Errorf("IPs = %v, want [203.0.113.9]", res.IPs)
	}
	if len(res.Warnings) != 4 {
		t.Fatalf("Warnings = %d entries, want 4:\n%s", len(res.Warnings),
			strings.Join(res.Warnings, "\n"))
	}
	for _, w := range res.Warnings {
		if !strings.HasPrefix(w, "line ") {
			t.Errorf("warning %q missing line prefix", w)
		}
	}
}

func TestParseBlocklist_EmptyFile(t *testing.T) {
	res, err := ParseBlocklist(strings.NewReader("# only comments\n\n"))
	if err != nil {
		t.Fatalf("ParseBlocklist: %v", err)
	}
	if len(res.Domains) != 0 || len(res.IPs) != 0 || len(res.Warnings) != 0 {
		t.Errorf("empty file should yield nothing: %+v", res)
	}
}
