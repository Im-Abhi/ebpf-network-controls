package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/xdp/firewall.bpf.c -- -I../../bpf/common

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf/link"
)

// LoadXDP loads the XDP firewall program and attaches it to the specified interface.
func LoadXDP(ifaceName string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up network interface %q: %v", ifaceName, err)
	}

	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}
	defer objs.Close()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FirewallProg,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("could not attach XDP program: %v", err)
	}

	return l, nil
}
