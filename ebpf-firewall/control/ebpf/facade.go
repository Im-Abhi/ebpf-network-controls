package ebpf

import (
	"fmt"
	"time"

	"ebpf-firewall/control/server"
)

// Firewall is a thin facade coordinating the XDP program lifecycle (XDPProgram)
// with policy map operations (MapManager), counter reads (CounterManager), the
// config/default-policy state (ConfigManager), the conntrack table
// (ConntrackManager), and the TC egress hook (TCProgram + EgressPolicyManager).
// It is the single handle used by cmd/firewall and the runtime control plane.
type Firewall struct {
	prog          *XDPProgram
	mgr           *MapManager
	counterMgr    *CounterManager
	portPolicyMgr *PortPolicyManager
	configMgr     *ConfigManager
	ctMgr         *ConntrackManager
	egressMgr     *EgressPolicyManager
	egressCfgMgr  *ConfigManager
	tc            *TCProgram
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
	egressMgr := NewEgressPolicyManager(prog.EgressBlockedIps(), prog.EgressPortPolicy())
	egressMgr.SetPresence(presence)

	return &Firewall{
		prog:          prog,
		mgr:           mgr,
		counterMgr:    NewCounterManager(prog.Counters()),
		portPolicyMgr: portPolicyMgr,
		configMgr:     NewConfigManager(prog.Config()),
		ctMgr:         NewConntrackManager(prog.Conntrack()),
		egressMgr:     egressMgr,
		egressCfgMgr:  NewConfigManager(prog.EgressConfig()),
		tc:            NewTCProgram(prog.EgressProgram(), prog.ifaceIndex),
	}, nil
}

// Start attaches the loaded XDP program to the interface.
func (f *Firewall) Start() error {
	return f.prog.Start()
}

// Stop detaches the TC egress hook (if attached) and then the XDP program,
// closing all kernel resources. Detaching egress first is required so no
// stale classifier link survives a Stop: a TCX link holds its own
// reference to the loaded program, so closing the XDP objects alone would
// leave the egress hook live.
func (f *Firewall) Stop() error {
	var firstErr error
	if err := f.StopEgress(); err != nil {
		firstErr = err
	}
	if err := f.prog.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Interface returns the interface name the firewall is bound to.
func (f *Firewall) Interface() string {
	return f.prog.ifaceName
}

// AttachMode reports the effective XDP attach mode ("xdpDriver"/"xdpGeneric"),
// empty until the program is attached.
func (f *Firewall) AttachMode() string {
	return f.prog.AttachMode()
}

// BlockIP adds an IP or CIDR to the blocklist with a DROP action.
func (f *Firewall) BlockIP(cidr string) error {
	if err := f.mgr.BlockIP(cidr); err != nil {
		return fmt.Errorf("blocking %q: %w", cidr, err)
	}
	return nil
}

// BlockIPWithAction adds an IP or CIDR rule with an explicit action and the
// default priority (0).
func (f *Firewall) BlockIPWithAction(cidr, actionStr string) error {
	return f.BlockIPWithActionPriority(cidr, actionStr, 0)
}

// BlockIPWithActionPriority adds an IP or CIDR rule with an explicit action
// and priority.
func (f *Firewall) BlockIPWithActionPriority(cidr, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.mgr.BlockIPWithActionPriority(cidr, action, priority); err != nil {
		return fmt.Errorf("adding %q with action %s priority %d: %w", cidr, action, priority, err)
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

// ListBlockedRules returns the current IP rules with their action and priority.
func (f *Firewall) ListBlockedRules() ([]server.BlockedRule, error) {
	return f.mgr.ListBlockedRules()
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

// BlockPortRuleWithAction adds a port rule with an explicit action and the
// default priority (0).
func (f *Firewall) BlockPortRuleWithAction(dst, protocol string, dport, sport uint16, actionStr string) error {
	return f.BlockPortRuleWithActionPriority(dst, protocol, dport, sport, actionStr, 0)
}

// BlockPortRuleWithActionPriority adds a port rule with an explicit action and
// priority.
func (f *Firewall) BlockPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.portPolicyMgr.BlockWithActionPriority(dst, protocol, dport, sport, action, priority); err != nil {
		return fmt.Errorf("adding port rule %s/%d (sport %d) to %s with action %s priority %d: %w", protocol, dport, sport, dst, action, priority, err)
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

// ListConntrack returns the currently tracked TCP flows.
func (f *Firewall) ListConntrack() ([]server.ConntrackEntry, error) {
	return f.ctMgr.List()
}

// ClearConntrack removes all tracked TCP flows.
func (f *Firewall) ClearConntrack() error {
	return f.ctMgr.Clear()
}

// ReapConntrack removes tracked flows idle for at least idle and returns how
// many were removed. The daemon calls it on a timer to bound the table.
func (f *Firewall) ReapConntrack(idle time.Duration) (int, error) {
	return f.ctMgr.Reap(idle)
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

// ── TC egress (direction-aware) ────────────────────────────────────────
// The egress hook filters host-generated outbound traffic with its own maps;
// see EgressPolicyManager for the destination-based semantics.

// StartEgress attaches the TC egress classifier to the interface's egress
// path. It is a no-op when already attached. Requires kernel >= 6.6 (TCX).
func (f *Firewall) StartEgress() error {
	return f.tc.Start()
}

// StopEgress detaches the TC egress classifier, leaving the XDP program (and
// policy state) untouched.
func (f *Firewall) StopEgress() error {
	return f.tc.Close()
}

// EgressAttached reports whether the TC egress classifier is attached.
func (f *Firewall) EgressAttached() bool {
	return f.tc.Attached()
}

// BlockEgressWithActionPriority adds a destination IP/CIDR rule to the egress
// policy with an explicit action and priority.
func (f *Firewall) BlockEgressWithActionPriority(cidr, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.egressMgr.BlockIP(cidr, action, priority); err != nil {
		return fmt.Errorf("adding egress rule %q with action %s priority %d: %w", cidr, action, priority, err)
	}
	return nil
}

// BlockEgressWithAction adds a destination IP/CIDR egress rule with an
// explicit action at the default priority.
func (f *Firewall) BlockEgressWithAction(cidr, actionStr string) error {
	return f.BlockEgressWithActionPriority(cidr, actionStr, 0)
}

// UnblockEgress removes a destination IP/CIDR rule from the egress policy.
func (f *Firewall) UnblockEgress(cidr string) error {
	if err := f.egressMgr.UnblockIP(cidr); err != nil {
		return fmt.Errorf("removing egress rule %q: %w", cidr, err)
	}
	return nil
}

// ListEgressRules returns the current egress IP rules.
func (f *Firewall) ListEgressRules() ([]server.BlockedRule, error) {
	return f.egressMgr.ListIPs()
}

// BlockEgressPortRule adds an egress port rule with an explicit action and
// priority for remote (dst, proto, dport, sport).
func (f *Firewall) BlockEgressPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.egressMgr.BlockPort(dst, protocol, dport, sport, action, priority); err != nil {
		return fmt.Errorf("adding egress port rule %s/%d (sport %d) to %s with action %s priority %d: %w", protocol, dport, sport, dst, action, priority, err)
	}
	return nil
}

// BlockEgressPortRuleWithAction adds an egress port rule with an explicit
// action at the default priority.
func (f *Firewall) BlockEgressPortRuleWithAction(dst, protocol string, dport, sport uint16, actionStr string) error {
	return f.BlockEgressPortRuleWithActionPriority(dst, protocol, dport, sport, actionStr, 0)
}

// BlockEgressPortRule adds a DROP egress port rule (dport 0 = any port).
func (f *Firewall) BlockEgressPortRule(dst, protocol string, dport, sport uint16) error {
	return f.BlockEgressPortRuleWithAction(dst, protocol, dport, sport, "drop")
}

// UnblockEgressPortRule removes an egress port rule.
func (f *Firewall) UnblockEgressPortRule(dst, protocol string, dport, sport uint16) error {
	if err := f.egressMgr.UnblockPort(dst, protocol, dport, sport); err != nil {
		return fmt.Errorf("removing egress port rule %s/%d (sport %d) to %s: %w", protocol, dport, sport, dst, err)
	}
	return nil
}

// ListEgressPortRules returns the current egress port rules.
func (f *Firewall) ListEgressPortRules() ([]server.PortRule, error) {
	return f.egressMgr.ListPorts()
}

// ClearEgress removes every egress IP rule and egress port rule.
func (f *Firewall) ClearEgress() error {
	if err := f.egressMgr.Clear(); err != nil {
		return fmt.Errorf("clearing egress policy: %w", err)
	}
	return nil
}

// SetEgressDefault sets the egress fallback policy ("allow" or "deny") applied
// when no egress rule matches. Independent of the ingress default in
// firewall_config so the two directions can have different postures.
func (f *Firewall) SetEgressDefault(s string) error {
	policy, err := ParseDefaultPolicy(s)
	if err != nil {
		return err
	}
	if err := f.egressCfgMgr.SetDefaultPolicy(policy); err != nil {
		return fmt.Errorf("setting egress default policy to %s: %w", policy, err)
	}
	return nil
}

// EgressDefault returns the current egress fallback policy ("allow" or "deny").
func (f *Firewall) EgressDefault() (string, error) {
	p, err := f.egressCfgMgr.DefaultPolicy()
	if err != nil {
		return "", err
	}
	return p.String(), nil
}

// EgressStats returns the egress packet/byte counters (indices 3-5 of the
// counters map), separate from the ingress Stats.
func (f *Firewall) EgressStats() (server.Stats, error) {
	return f.counterMgr.GetEgressCounters()
}
