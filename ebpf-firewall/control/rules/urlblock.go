package rules

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// URL blocklist file parsing. The file is one entry per line:
//
//   - a bare hostname              badsite.com
//   - a URL (only its host counts) https://badsite.com/track?x=1
//   - a bare IPv4 address          203.0.113.9   (routed to the egress IP table)
//
// Blank lines and #-comments are ignored. Entries that normalize to
// nothing, contain unsupported characters (non-ASCII — use punycode), are
// wildcards, or are IPv6 are skipped with a warning rather than failing the
// whole file: one bad line must not disable the other ten thousand.

// BlocklistResult holds the parsed content of a URL blocklist file.
type BlocklistResult struct {
	Domains  []string // hostnames for the egress domain blocklist
	IPs      []string // bare IPv4 addresses for the egress IP table
	Warnings []string // "line N: reason" — skipped entries
}

// ParseBlocklist reads and normalizes a URL blocklist file. A read error is
// returned; bad lines are warnings, not errors.
func ParseBlocklist(r io.Reader) (BlocklistResult, error) {
	var res BlocklistResult
	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		host := normalizeBlocklistHost(raw)
		if host == "" {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("line %d: nothing left after stripping scheme/path/port: %q", lineNo, raw))
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil {
				res.Warnings = append(res.Warnings,
					fmt.Sprintf("line %d: only IPv4 is supported: %q", lineNo, host))
				continue
			}
			res.IPs = append(res.IPs, host) // hybrid file: bare IPs feed the IP table
			continue
		}
		if reason := validateBlocklistHost(host); reason != "" {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("line %d: %s: %q", lineNo, reason, host))
			continue
		}
		res.Domains = append(res.Domains, host)
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("reading blocklist: %w", err)
	}
	return res, nil
}

// normalizeBlocklistHost reduces one file line to the host it designates:
// lowercase, scheme/userinfo/path/query/fragment/port/trailing-dot stripped.
// Returns "" when nothing remains. Blank lines and comments are the
// caller's business.
func normalizeBlocklistHost(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, scheme) {
			s = s[len(scheme):]
			break
		}
	}
	if i := strings.LastIndex(s, "@"); i >= 0 { // userinfo@host
		s = s[i+1:]
	}
	for _, sep := range []string{"/", "?", "#"} { // path/query/fragment
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	if i := strings.LastIndex(s, ":"); i >= 0 { // :port
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".") // fully-qualified trailing dot
	return strings.TrimSpace(s)
}

// validateBlocklistHost returns "" when the (already lowercased) host is a
// syntactically valid hostname, else the reason it is not.
func validateBlocklistHost(s string) string {
	if s == "" {
		return "empty host"
	}
	if len(s) > 253 {
		return "host too long"
	}
	if strings.HasPrefix(s, "*.") {
		return "wildcards not supported (subdomains are blocked automatically)"
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return "empty label (double dot?)"
		}
		if len(label) > 63 {
			return "label too long"
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "label starts or ends with '-'"
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "unsupported characters (use punycode for IDN)"
			}
		}
	}
	return ""
}
