package ebpf

import (
	"fmt"
)

// Firewall is a thin facade coordinating the XDP program lifecycle (XDPProgram)
// with policy map operations (MapManager). It is the single handle used by
// cmd/firewall and, later, the runtime control plane.
type Firewall struct {
	prog *XDPProgram
	mgr  *MapManager
}

// NewFirewall loads the XDP program and its maps for the given interface but
// does not attach. Call Start to attach the program to the interface.
func NewFirewall(ifaceName string) (*Firewall, error) {
	prog, err := LoadXDP(ifaceName)
	if err != nil {
		return nil, err
	}

	return &Firewall{
		prog: prog,
		mgr:  NewMapManager(prog.BlockedIps()),
	}, nil
}

// Start attaches the loaded XDP program to the interface.
func (f *Firewall) Start() error {
	return f.prog.Start()
}

// Stop detaches the program and closes all kernel resources.
func (f *Firewall) Stop() error {
	return f.prog.Close()
}

// Interface returns the interface name the firewall is bound to.
func (f *Firewall) Interface() string {
	return f.prog.ifaceName
}

// BlockIP adds an IP or CIDR to the blocklist.
func (f *Firewall) BlockIP(cidr string) error {
	if err := f.mgr.BlockIP(cidr); err != nil {
		return fmt.Errorf("blocking %q: %w", cidr, err)
	}
	return nil
}

// UnblockIP removes an IP or CIDR from the blocklist.
func (f *Firewall) UnblockIP(cidr string) error {
	if err := f.mgr.UnblockIP(cidr); err != nil {
		return fmt.Errorf("unblocking %q: %w", cidr, err)
	}
	return nil
}

// IsBlocked reports whether the given IP or CIDR is covered by a blocked prefix.
func (f *Firewall) IsBlocked(ip string) (bool, error) {
	return f.mgr.IsBlocked(ip)
}

// ListBlockedIPs returns the current blocked prefixes as CIDR strings.
func (f *Firewall) ListBlockedIPs() ([]string, error) {
	return f.mgr.ListBlockedIPs()
}

// Clear removes every blocked prefix.
func (f *Firewall) Clear() error {
	return f.mgr.Clear()
}
