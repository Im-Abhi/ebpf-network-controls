package ebpf

import (
	"fmt"
	"time"

	"ebpf-firewall/control/server"
)

// Firewall is the single handle used by cmd/firewall and the runtime control
// plane. It coordinates:
//
//   - the XDP program lifecycle      (prog, XDPProgram)
//   - the TC egress hook lifecycle   (tc, TCProgram)
//   - four rule tables               (ingress/egress × CIDR/port, see tables.go)
//   - the conntrack table            (ctMgr)
//   - counters + default policies    (counterMgr, configMgr, egressCfgMgr)
//
// The four table instances below are the whole policy surface: every Block/
// Unblock/List/Clear operation on either direction goes through exactly one
// of them.
type Firewall struct {
	prog *XDPProgram
	tc   *TCProgram

	ingressIPs   cidrTable // blocked_ips          (XDP)
	ingressPorts portTable // port_policy          (XDP)
	egressIPs    cidrTable // egress_blocked_ips   (TC)
	egressPorts  portTable // egress_port_policy   (TC)

	ctMgr        *ConntrackManager
	counterMgr   *CounterManager
	configMgr    *ConfigManager // ingress default policy
	egressCfgMgr *ConfigManager // egress default policy
}

// NewFirewall loads the XDP program and its maps for the given interface but
// does not attach. Call Start to attach the program to the interface.
func NewFirewall(ifaceName string) (*Firewall, error) {
	prog, err := LoadXDP(ifaceName)
	if err != nil {
		return nil, err
	}

	presence := prog.RulePresence()
	return &Firewall{
		prog:         prog,
		tc:           NewTCProgram(prog.EgressProgram(), prog.ifaceIndex),
		ingressIPs:   newCidrTable(prog.BlockedIps(), presence, rulePresenceIP),
		ingressPorts: newPortTable(prog.PortPolicy(), presence, rulePresencePort),
		egressIPs:    newCidrTable(prog.EgressBlockedIps(), presence, rulePresenceEgressIP),
		egressPorts:  newPortTable(prog.EgressPortPolicy(), presence, rulePresenceEgressPort),
		ctMgr:        NewConntrackManager(prog.Conntrack()),
		counterMgr:   NewCounterManager(prog.Counters()),
		configMgr:    NewConfigManager(prog.Config()),
		egressCfgMgr: NewConfigManager(prog.EgressConfig()),
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

// ── Ingress IP/CIDR rules ────────────────────────────────────────────────

// BlockIP adds an IP or CIDR to the blocklist with a DROP action.
func (f *Firewall) BlockIP(cidr string) error {
	if err := f.ingressIPs.Add(cidr, ActionDrop, 0); err != nil {
		return fmt.Errorf("blocking %q: %w", cidr, err)
	}
	return nil
}

// BlockIPWithActionPriority adds an IP or CIDR rule with an explicit action
// and priority.
func (f *Firewall) BlockIPWithActionPriority(cidr, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.ingressIPs.Add(cidr, action, priority); err != nil {
		return fmt.Errorf("adding %q with action %s priority %d: %w", cidr, action, priority, err)
	}
	return nil
}

// UnblockIP removes an IP or CIDR from the blocklist.
func (f *Firewall) UnblockIP(cidr string) error {
	if err := f.ingressIPs.Remove(cidr); err != nil {
		return fmt.Errorf("unblocking %q: %w", cidr, err)
	}
	return nil
}

// IsBlocked reports whether the given IP or CIDR is covered by a blocked prefix.
func (f *Firewall) IsBlocked(ip string) (bool, error) {
	return f.ingressIPs.Contains(ip)
}

// ListBlockedIPs returns the current blocked prefixes as CIDR strings.
func (f *Firewall) ListBlockedIPs() ([]string, error) {
	return f.ingressIPs.CIDRs()
}

// ListBlockedRules returns the current IP rules with their action and priority.
func (f *Firewall) ListBlockedRules() ([]server.BlockedRule, error) {
	return f.ingressIPs.List()
}

// Clear removes every blocked prefix.
func (f *Firewall) Clear() error {
	return f.ingressIPs.Clear()
}

// ── Ingress port rules ───────────────────────────────────────────────────

// BlockPortRuleWithActionPriority adds a port rule with an explicit action and
// priority.
func (f *Firewall) BlockPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.ingressPorts.Add(dst, protocol, dport, sport, action, priority); err != nil {
		return fmt.Errorf("adding port rule %s/%d (sport %d) to %s with action %s priority %d: %w", protocol, dport, sport, dst, action, priority, err)
	}
	return nil
}

// UnblockPortRule removes a protocol/dport rule for dst (sport 0 = any).
func (f *Firewall) UnblockPortRule(dst, protocol string, dport, sport uint16) error {
	if err := f.ingressPorts.Remove(dst, protocol, dport, sport); err != nil {
		return fmt.Errorf("unblocking port rule %s/%d (sport %d) to %s: %w", protocol, dport, sport, dst, err)
	}
	return nil
}

// ListPortRules returns all active protocol/port rules.
func (f *Firewall) ListPortRules() ([]server.PortRule, error) {
	return f.ingressPorts.List()
}

// ClearPortRules removes every protocol/port rule.
func (f *Firewall) ClearPortRules() error {
	return f.ingressPorts.Clear()
}

// ── Egress (TC) rules ────────────────────────────────────────────────────
// Egress rules operate on the REMOTE destination (see tables.go and the
// egress datapath in bpf/firewall.c for the direction semantics).

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
	if err := f.egressIPs.Add(cidr, action, priority); err != nil {
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
	if err := f.egressIPs.Remove(cidr); err != nil {
		return fmt.Errorf("removing egress rule %q: %w", cidr, err)
	}
	return nil
}

// ListEgressRules returns the current egress IP rules.
func (f *Firewall) ListEgressRules() ([]server.BlockedRule, error) {
	return f.egressIPs.List()
}

// BlockEgressPortRuleWithActionPriority adds an egress port rule with an
// explicit action and priority for remote (dst, proto, dport, sport).
func (f *Firewall) BlockEgressPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, actionStr string, priority uint32) error {
	action, err := ParseAction(actionStr)
	if err != nil {
		return err
	}
	if err := f.egressPorts.Add(dst, protocol, dport, sport, action, priority); err != nil {
		return fmt.Errorf("adding egress port rule %s/%d (sport %d) to %s with action %s priority %d: %w", protocol, dport, sport, dst, action, priority, err)
	}
	return nil
}

// UnblockEgressPortRule removes an egress port rule.
func (f *Firewall) UnblockEgressPortRule(dst, protocol string, dport, sport uint16) error {
	if err := f.egressPorts.Remove(dst, protocol, dport, sport); err != nil {
		return fmt.Errorf("removing egress port rule %s/%d (sport %d) to %s: %w", protocol, dport, sport, dst, err)
	}
	return nil
}

// ListEgressPortRules returns the current egress port rules.
func (f *Firewall) ListEgressPortRules() ([]server.PortRule, error) {
	return f.egressPorts.List()
}

// ClearEgress removes every egress IP rule and egress port rule.
func (f *Firewall) ClearEgress() error {
	if err := f.egressIPs.Clear(); err != nil {
		return fmt.Errorf("clearing egress policy: %w", err)
	}
	return nil
}

// ── Conntrack, counters, default policies ────────────────────────────────

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

// Stats returns the global packet and byte counters from the BPF map.
func (f *Firewall) Stats() (server.Stats, error) {
	return f.counterMgr.GetCounters()
}

// EgressStats returns the egress packet/byte counters (indices 3-5 of the
// counters map), separate from the ingress Stats.
func (f *Firewall) EgressStats() (server.Stats, error) {
	return f.counterMgr.GetEgressCounters()
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
