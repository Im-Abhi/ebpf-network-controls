package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/firewall.c -- -I../../bpf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// XDPProgram owns the full lifecycle (load, attach, detach, close) of the XDP
// firewall program and its maps. It intentionally knows nothing about firewall
// policy; policy operations live in MapManager (see blocklist.go).
type XDPProgram struct {
	ifaceName  string
	ifaceIndex int
	prog       *ebpf.Program
	link       link.Link
	objs       firewallObjects
}

// LoadXDP loads the compiled XDP firewall ELF and its maps for the given
// interface, but does NOT attach the program. Call Start to attach.
func LoadXDP(ifaceName string) (*XDPProgram, error) {
	// Attach to the interface only after Start, so validate the name upfront.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("looking up network interface %q: %v", ifaceName, err)
	}

	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %v", err)
	}

	return &XDPProgram{
		ifaceName:  ifaceName,
		ifaceIndex: iface.Index,
		prog:       objs.FirewallProg,
		objs:       objs,
	}, nil
}

// Start attaches the loaded XDP program to the interface. It is safe to call
// only once; subsequent calls are a no-op.
func (x *XDPProgram) Start() error {
	if x.link != nil {
		return nil
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   x.prog,
		Interface: x.ifaceIndex,
	})
	if err != nil {
		x.objs.Close()
		return fmt.Errorf("could not attach XDP program to %q: %w", x.ifaceName, err)
	}

	x.link = l
	return nil
}

// BlockedIps returns the eBPF map backing the IP blocklist.
func (x *XDPProgram) BlockedIps() *ebpf.Map {
	return x.objs.BlockedIps
}

// Counters returns the eBPF map holding global packet/byte counters.
func (x *XDPProgram) Counters() *ebpf.Map {
	return x.objs.Counters
}

// PortPolicy returns the eBPF map holding protocol/port rules.
func (x *XDPProgram) PortPolicy() *ebpf.Map {
	return x.objs.PortPolicy
}

// Close detaches the program (if attached) and closes all loaded objects.
func (x *XDPProgram) Close() error {
	var firstErr error
	if x.link != nil {
		if err := x.link.Close(); err != nil {
			firstErr = err
		}
		x.link = nil
	}
	if err := x.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
