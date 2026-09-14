package ebpf

import (
	"fmt"

	"ebpf-firewall/control/server"
)

// Firewall is a thin facade coordinating the XDP program lifecycle (XDPProgram)
// with policy map operations (MapManager), counter reads (CounterManager), and
// the config/default-policy state (ConfigManager). It is the single handle
// used by cmd/firewall and the runtime control plane.
type Firewall struct {
	prog          *XDPProgram
	mgr           *MapManager
	counterMgr    *CounterManager
	portPolicyMgr *PortPolicyManager
	configMgr     *ConfigManager
}

// NewFirewall loads the XDP program and its maps for the given interface but
// does not attach. Call Start to attach the program to the interface.
func NewFirewall(ifaceName string) (*Firewall, error) {
	prog, err := LoadXDP(ifaceName)
	if err != nil {
		return nil, err
	}

	presence := prog.RulePresence()
	mgr := NewMapManager(prog.BlockedIps())
	mgr.SetPresence(presence)
	portPolicyMgr := NewPortPolicyManager(prog.PortPolicy())
	portPolicyMgr.SetPresence(presence)

	return &Firewall{
		prog:          prog,
		mgr:           mgr,
		counterMgr:    NewCounterManager(prog.Counters()),
		portPolicyMgr: portPolicyMgr,
		configMgr:     NewConfigManager(prog.Config()),
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

// BlockIP adds an IP or CIDR to the blocklist with a DROP action.
func (f *Firewall) BlockIP(cidr string) error {
	if err := f.mgr.BlockIP(cidr); err != nil {
		return fmt.Errorf("blocking %q: %w", cidr, err)
	}
	return nil
}

// BlockIPWithAction adds an IP or CIDR rule with an explicit action.
func (f *Firewall) BlockIPWithAction(cidr, actionStr string) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.mgr.BlockIPWithAction(cidr, action); err != nil {
		return fmt.Errorf("adding %q with action %s: %w", cidr, action, err)
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

// Stats returns the global packet and byte counters from the BPF map.
func (f *Firewall) Stats() (server.Stats, error) {
	return f.counterMgr.GetCounters()
}

// BlockPortRule adds a rule that DROPs traffic destined to dst on the given
// protocol/dport (sport 0 = any source port). dport 0 means any port.
func (f *Firewall) BlockPortRule(dst, protocol string, dport, sport uint16) error {
	if err := f.portPolicyMgr.BlockWithAction(dst, protocol, dport, sport, ActionDrop); err != nil {
		return fmt.Errorf("blocking port rule %s/%d (sport %d) to %s: %w", protocol, dport, sport, dst, err)
	}
	return nil
}

// BlockPortRuleWithAction adds a port rule with an explicit action.
func (f *Firewall) BlockPortRuleWithAction(dst, protocol string, dport, sport uint16, actionStr string) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.portPolicyMgr.BlockWithAction(dst, protocol, dport, sport, action); err != nil {
		return fmt.Errorf("adding port rule %s/%d (sport %d) to %s with action %s: %w", protocol, dport, sport, dst, action, err)
	}
	return nil
}

// UnblockPortRule removes a protocol/dport rule for dst (sport 0 = any).
func (f *Firewall) UnblockPortRule(dst, protocol string, dport, sport uint16) error {
	if err := f.portPolicyMgr.UnblockWithAction(dst, protocol, dport, sport); err != nil {
		return fmt.Errorf("unblocking port rule %s/%d (sport %d) to %s: %w", protocol, dport, sport, dst, err)
	}
	return nil
}

// ListPortRules returns all active protocol/port rules.
func (f *Firewall) ListPortRules() ([]server.PortRule, error) {
	return f.portPolicyMgr.List()
}

// ClearPortRules removes every protocol/port rule.
func (f *Firewall) ClearPortRules() error {
	return f.portPolicyMgr.Clear()
}

// SetDefaultPolicy sets the fallback policy ("allow" or "deny") applied when
// no rule matches.
func (f *Firewall) SetDefaultPolicy(s string) error {
	policy, err := ParseDefaultPolicy(s)
	if err != nil {
		return err
	}
	if err := f.configMgr.SetDefaultPolicy(policy); err != nil {
		return fmt.Errorf("setting default policy to %s: %w", policy, err)
	}
	return nil
}

// DefaultPolicy returns the current fallback policy ("allow" or "deny").
func (f *Firewall) DefaultPolicy() (string, error) {
	p, err := f.configMgr.DefaultPolicy()
	if err != nil {
		return "", err
	}
	return p.String(), nil
}
