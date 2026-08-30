package rules

import (
	"fmt"
	"net"
	"strings"
)

// ParseIPOrCIDR converts a single IPv4 address or an IPv4 CIDR into a
// normalized *net.IPNet.
//
// Accepted input:
//
//	"1.2.3.4"       -> 1.2.3.4/32
//	"1.2.3.0/24"    -> 1.2.3.0/24
//	" 10.0.0.0/8 "  -> 10.0.0.0/8  (surrounding whitespace is tolerated)
//
// Rejected input: invalid IPs, invalid CIDRs, IPv6, and any malformed string.
func ParseIPOrCIDR(cidrStr string) (*net.IPNet, error) {
	s := strings.TrimSpace(cidrStr)
	if s == "" {
		return nil, fmt.Errorf("empty address")
	}

	if !strings.Contains(s, "/") {
		// Treat a bare address as a /32 host. ParseIP first so a bare IPv6
		// address is rejected before we fabricate a "/32" suffix on it.
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", s)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("only IPv4 is supported: %q", s)
		}
		_, ipNet, err := net.ParseCIDR(s + "/32")
		if err != nil {
			return nil, fmt.Errorf("invalid IP/CIDR %q: %w", s, err)
		}
		return &net.IPNet{IP: ipv4, Mask: ipNet.Mask}, nil
	}

	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 is supported: %q", s)
	}

	// Keep the 4-byte representation so callers can rely on len(IP) == 4.
	ipNet.IP = ipv4
	return ipNet, nil
}
