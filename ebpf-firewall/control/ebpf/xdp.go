package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/firewall.c -- -I../../bpf

import (
	"fmt"
	"net"

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

func (f *FirewallInstance) Close() {
	if f.Link != nil {
		f.Link.Close()
	}
	f.objs.Close()
}
