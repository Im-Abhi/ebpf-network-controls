package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/xdp/firewall.bpf.c -- -I../../bpf/common

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type FirewallInstance struct {
	Link       link.Link
	BlockedIps *ebpf.Map
	objs       firewallObjects
}

// LoadXDP loads the XDP firewall program, creates the maps, and attaches to the interface.
func LoadXDP(ifaceName string) (*FirewallInstance, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up network interface %q: %v", ifaceName, err)
	}

	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FirewallProg,
		Interface: iface.Index,
	})
	if err != nil {
		objs.Close() // clean up objects if attachment fails
		return nil, fmt.Errorf("could not attach XDP program: %w", err)
	}

	return &FirewallInstance{
		Link:       l,
		BlockedIps: objs.BlockedIps,
		objs:       objs,
	}, nil
}

type Ipv4LpmKey struct {
	PrefixLen uint32
	Data      uint32
}

func (f *FirewallInstance) BlockIP(cidrStr string) error {
	key, err := ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	var value uint32 = 1
	return f.BlockedIps.Put(key, value)
}

func (f *FirewallInstance) UnBlockIP(cidrStr string) error {
	key, err := ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	return f.BlockedIps.Delete(key)
}

func (f *FirewallInstance) Close() {
	if f.Link != nil {
		f.Link.Close()
	}
	f.objs.Close()
}

// ParseIPOrCIDR converts "192.168.1.1" or "10.0.0.0/24" into an Ipv4LpmKey
func ParseIPOrCIDR(cidrStr string) (Ipv4LpmKey, error) {
	if !strings.Contains(cidrStr, "/") {
		cidrStr += "/32" // default single IP to /32
	}

	ip, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return Ipv4LpmKey{}, fmt.Errorf("invalid CIDR/IP %q: %w", cidrStr, err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return Ipv4LpmKey{}, fmt.Errorf("Only IPv4 is supported: %q", cidrStr)
	}

	ones, _ := ipNet.Mask.Size()

	return Ipv4LpmKey{
		PrefixLen: uint32(ones),
		Data:      binary.BigEndian.Uint32(ipv4),
	}, nil
}
