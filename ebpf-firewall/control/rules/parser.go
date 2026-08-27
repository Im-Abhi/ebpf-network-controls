package rules

import (
	"fmt"
	"net"
	"strings"
)

// ParseIPOrCIDR converts "192.168.1.1" or "10.0.0.0/24" into a *net.IPNet
func ParseIPOrCIDR(cidrStr string) (*net.IPNet, error) {
	if !strings.Contains(cidrStr, "/") {
		cidrStr += "/32" // default single IP to /32
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR/IP %q: %w", cidrStr, err)
	}

	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 is supported: %q", cidrStr)
	}

	// Ensure we return the 4-byte representation
	ipNet.IP = ipv4

	return ipNet, nil
}
