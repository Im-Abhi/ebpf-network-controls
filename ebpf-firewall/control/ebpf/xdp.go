package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf firewall ../../bpf/firewall.c -- -I../../bpf

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// XDP attach modes as reported by XDPProgram.AttachMode. Consumers (daemon
// status, benchmark meta.txt) use these to qualify per-packet cost exponents.
const (
	// AttachModeDriver is native XDP: the program runs in the driver's RX
	// path before any skb allocation.
	AttachModeDriver = "xdpDriver"
	// AttachModeGeneric is generic (SKB) XDP: the driver has no native XDP
	// support, so packets are copied into an skb and the hook is more costly.
	AttachModeGeneric = "xdpGeneric"
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
	attachMode string
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

// Start attaches the loaded XDP program to the interface, preferring driver
// (native) mode and falling back to generic (SKB) mode when the driver does
// not support native XDP (e.g. veth). It is safe to call only once;
// subsequent calls are a no-op.
func (x *XDPProgram) Start() error {
	if x.link != nil {
		return nil
	}

	mode, l, err := x.attach(link.XDPDriverMode)
	if err != nil {
		log.Printf("xdp: native (driver) attach on %q failed (%v); retrying in generic (SKB) mode", x.ifaceName, err)
		mode, l, err = x.attach(link.XDPGenericMode)
	}
	if err != nil {
		x.objs.Close()
		return fmt.Errorf("could not attach XDP program to %q: %w", x.ifaceName, err)
	}

	x.attachMode = mode
	x.link = l
	return nil
}

// attach attempts an XDP attach with the given mode flags, returning the mode
// string to record on success.
func (x *XDPProgram) attach(flags link.XDPAttachFlags) (string, link.Link, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   x.prog,
		Interface: x.ifaceIndex,
		Flags:     flags,
	})
	if err != nil {
		return "", nil, err
	}
	mode := AttachModeDriver
	if flags == link.XDPGenericMode {
		mode = AttachModeGeneric
	}
	return mode, l, nil
}

// AttachMode reports the effective XDP attach mode ("xdpDriver" or
// "xdpGeneric"); empty until Start succeeds. Use it to qualify per-packet cost
// attribution: generic mode rides the more expensive SKB path.
func (x *XDPProgram) AttachMode() string {
	return x.attachMode
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

// Config returns the eBPF map holding the default policy configuration.
func (x *XDPProgram) Config() *ebpf.Map {
	return x.objs.FirewallConfig
}

// RulePresence returns the eBPF map advertising which policy maps are
// populated (see bpf/maps.h rule_presence).
func (x *XDPProgram) RulePresence() *ebpf.Map {
	return x.objs.RulePresence
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
