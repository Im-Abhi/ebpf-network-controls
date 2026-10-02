package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"ebpf-firewall/control/rules"
	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf"
)

// EgressPolicyManager is the control-plane surface for the two egress policy
// maps consumed by the TC egress datapath (bpf/firewall.c firewall_tc_egress):
// the egress_blocked_ips LPM trie and the egress_port_policy hash.
//
// Egress semantics deliberately differ from the ingress maps: an outgoing
// packet's source is always the local host, so both maps key on the REMOTE
// DESTINATION the host is reaching. IP rules match dst only (never the local
// source address, which would self-poison all outbound traffic when a rule
// covers the host's own network); port rules carry dst + proto + ports, where
// dst is the destination being contacted.
//
// Presence bits 2-3 (RULE_EGRESS_IP_PRESENT / RULE_EGRESS_PORT_PRESENT in
// bpf/maps.h) advertise non-emptiness exactly like the ingress managers: set
// before the first insert, cleared only after the last delete, so the
// datapath's empty-map fast path never bypasses a live rule. The egress
// manager touches only those two bits, leaving the ingress bits 0-1 alone.
type EgressPolicyManager struct {
	blockedIps *ebpf.Map
	portPolicy *ebpf.Map
	presence   *ebpf.Map
}

// NewEgressPolicyManager wraps the egress IP and port policy maps.
func NewEgressPolicyManager(blockedIps, portPolicy *ebpf.Map) *EgressPolicyManager {
	return &EgressPolicyManager{blockedIps: blockedIps, portPolicy: portPolicy}
}

// SetPresence attaches the rule_presence map so the manager can advertise to
// the datapath whether each egress map holds any entry. Optional: a nil map
// disables the fast-path flag maintenance (used by standalone test maps).
func (em *EgressPolicyManager) SetPresence(m *ebpf.Map) {
	em.presence = m
}

// syncIPPresence makes RULE_EGRESS_IP_PRESENT match egress_blocked_ips.
func (em *EgressPolicyManager) syncIPPresence() error {
	has, err := mapHasEntries(em.blockedIps)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(em.presence, rulePresenceEgressIP)
	}
	return clearPresenceBit(em.presence, rulePresenceEgressIP)
}

// syncPortPresence makes RULE_EGRESS_PORT_PRESENT match egress_port_policy.
func (em *EgressPolicyManager) syncPortPresence() error {
	has, err := mapHasEntries(em.portPolicy)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(em.presence, rulePresenceEgressPort)
	}
	return clearPresenceBit(em.presence, rulePresenceEgressPort)
}

// BlockIP adds a destination IP/CIDR rule to the egress IP map with the given
// action and priority. The datapath (LPM) matches the packet's destination.
func (em *EgressPolicyManager) BlockIP(cidrStr string, action Action, priority uint32) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	// Advertise before inserting so a pre-existing rule is never skipped by
	// the empty-map fast path (a set-during-insert race only costs lookups).
	if err := setPresenceBit(em.presence, rulePresenceEgressIP); err != nil {
		return err
	}
	return em.blockedIps.Put(key, ruleValue{Action: uint32(action), Priority: priority})
}

// UnblockIP removes a destination IP/CIDR rule from the egress IP map.
func (em *EgressPolicyManager) UnblockIP(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	if err := em.blockedIps.Delete(key); err != nil {
		return err
	}
	return em.syncIPPresence()
}

// IsBlocked reports whether the given IP or CIDR is covered by an egress IP
// rule (an LPM match on the destination address).
func (em *EgressPolicyManager) IsBlocked(s string) (bool, error) {
	key, err := ipToKey(s)
	if err != nil {
		return false, err
	}

	var value ruleValue
	err = em.blockedIps.Lookup(key, &value)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListIPs returns all egress IP rules as CIDR/action/priority.
func (em *EgressPolicyManager) ListIPs() ([]server.BlockedRule, error) {
	var (
		rules []server.BlockedRule
		key   firewallIpv4LpmKey
		value ruleValue
	)
	iter := em.blockedIps.Iterate()
	for iter.Next(&key, &value) {
		ipBytes := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Data)
		rules = append(rules, server.BlockedRule{
			Cidr:     fmt.Sprintf("%s/%d", ipBytes.String(), key.Prefixlen),
			Action:   Action(value.Action).String(),
			Priority: value.Priority,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// BlockPort adds an egress port rule matching a remote (dst, proto, dport,
// sport) with the given action and priority (0 = any like the ingress map).
func (em *EgressPolicyManager) BlockPort(dst, protocol string, dport, sport uint16, action Action, priority uint32) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := buildPortRuleKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	if err := setPresenceBit(em.presence, rulePresenceEgressPort); err != nil {
		return err
	}
	return em.portPolicy.Put(key, ruleValue{Action: uint32(action), Priority: priority})
}

// UnblockPort removes an egress port rule.
func (em *EgressPolicyManager) UnblockPort(dst, protocol string, dport, sport uint16) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := buildPortRuleKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	if err := em.portPolicy.Delete(key); err != nil {
		return err
	}
	return em.syncPortPresence()
}

// ListPorts returns all egress port rules.
func (em *EgressPolicyManager) ListPorts() ([]server.PortRule, error) {
	rules := make([]server.PortRule, 0, 8)
	var (
		key   firewallPortRuleKey
		value ruleValue
	)
	iter := em.portPolicy.Iterate()
	for iter.Next(&key, &value) {
		ipBytes := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Dst)
		rules = append(rules, server.PortRule{
			Protocol: codeToProto(key.Protocol),
			Port:     wireToPort(key.Dport),
			SPort:    wireToPort(key.Sport),
			Dst:      ipBytes.String(),
			Action:   Action(value.Action).String(),
			Priority: value.Priority,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// Clear removes every rule from both egress maps and syncs both presence bits.
func (em *EgressPolicyManager) Clear() error {
	var (
		key   firewallIpv4LpmKey
		value ruleValue
	)
	iter := em.blockedIps.Iterate()
	for iter.Next(&key, &value) {
		if err := em.blockedIps.Delete(key); err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if err := em.syncIPPresence(); err != nil {
		return err
	}

	var (
		pkey   firewallPortRuleKey
		pvalue ruleValue
	)
	piter := em.portPolicy.Iterate()
	for piter.Next(&pkey, &pvalue) {
		if err := em.portPolicy.Delete(pkey); err != nil {
			return err
		}
	}
	if err := piter.Err(); err != nil {
		return err
	}
	return em.syncPortPresence()
}