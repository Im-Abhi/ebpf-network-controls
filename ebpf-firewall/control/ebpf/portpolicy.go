package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"ebpf-firewall/control/server"
	"github.com/cilium/ebpf"
)

// Protocol/port sentinel values. A protocol, destination port or source port
// of zero means "any" (see struct port_rule_key in bpf/maps.h).
const (
	portAnyProtocol uint8  = 0
	portAnyPort     uint16 = 0
	protoTCP        uint8  = 6
	protoUDP        uint8  = 17
)

// firewallPortRuleKey mirrors struct port_rule_key in bpf/maps.h:
//
//	struct port_rule_key {
//	    __u8  protocol;   // IPPROTO_TCP/UDP, 0 = any
//	    __u16 dport;      // destination port, network byte order, 0 = any
//	    __u16 sport;      // source port, network byte order, 0 = any
//	    __u32 dst;        // destination IP, network byte order
//	};
//
// The generated type (after `make generate`) uses structs.HostLayout so its
// on-wire layout exactly matches the C struct, including the alignment
// padding after protocol. Only this layer knows the byte layout.

// PortPolicyManager provides an abstraction over the port_policy eBPF map.
type PortPolicyManager struct {
	portPolicy *ebpf.Map
	presence   *ebpf.Map
}

// NewPortPolicyManager wraps the port_policy map.
func NewPortPolicyManager(m *ebpf.Map) *PortPolicyManager {
	return &PortPolicyManager{portPolicy: m}
}

// SetPresence attaches the rule_presence map so the manager can advertise to
// the datapath whether this rule set holds any entry. Optional: a nil map
// disables the fast-path flag maintenance (used by standalone test maps).
func (pm *PortPolicyManager) SetPresence(m *ebpf.Map) {
	pm.presence = m
}

// syncPresence makes the RULE_PORT_PRESENT bit match reality (map empty or not).
func (pm *PortPolicyManager) syncPresence() error {
	has, err := mapHasEntries(pm.portPolicy)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(pm.presence, rulePresencePort)
	}
	return clearPresenceBit(pm.presence, rulePresencePort)
}

// protoToCode maps a protocol name to its IP protocol number (0 = any).
func protoToCode(proto string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "":
		return portAnyProtocol, nil
	case "tcp":
		return protoTCP, nil
	case "udp":
		return protoUDP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q (use tcp, udp, or leave empty)", proto)
	}
}

func codeToProto(code uint8) string {
	switch code {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return ""
	}
}

// wireToPort converts a network-byte-order port stored in the map key back to
// the logical port number. The key keeps the wire bytes (e.g. port 22 ->
// [0x00, 0x16]); on a little-endian host the stored uint16 is 0x1600, so the
// wire bytes are rebuilt and read back big-endian to recover the port.
func wireToPort(w uint16) uint16 {
	b := [2]byte{byte(w), byte(w >> 8)}
	return binary.BigEndian.Uint16(b[:])
}

// newPortKey builds the map key for a (dst, protocol, dport, sport) rule.
func (pm *PortPolicyManager) newPortKey(dst string, proto uint8, dport, sport uint16) (firewallPortRuleKey, error) {
	var key firewallPortRuleKey

	ip := net.ParseIP(strings.TrimSpace(dst)).To4()
	if ip == nil {
		return key, fmt.Errorf("invalid IPv4 destination %q", dst)
	}

	key.Protocol = proto
	key.Dst = binary.LittleEndian.Uint32(ip)

	// Ports must be in network byte order: the C datapath compares them against
	// tcp->dest / tcp->source, whose in-memory bytes are the wire bytes (high
	// byte first, e.g. port 22 -> [0x00, 0x16]). Store the value whose
	// little-endian bytes reproduce that sequence, i.e. htons(port).
	key.Dport = portToWire(dport)
	key.Sport = portToWire(sport)

	return key, nil
}

// portToWire converts a logical port to its network-byte-order wire encoding
// as stored in the map key (see newPortKey).
func portToWire(p uint16) uint16 {
	netBytes := []byte{byte(p >> 8), byte(p & 0xff)}
	return binary.LittleEndian.Uint16(netBytes)
}

// Block adds a port rule that DROPs traffic to dst on the given protocol/dport
// (any source port). protocol may be "tcp", "udp", or "" (any). dport of 0
// means any destination port.
func (pm *PortPolicyManager) Block(dst, protocol string, dport uint16) error {
	return pm.BlockWithAction(dst, protocol, dport, 0, ActionDrop)
}

// BlockWithAction adds a port rule with an explicit action (PASS or DROP),
// matching dport and sport as given (0 = any for either), at the default
// priority (0).
func (pm *PortPolicyManager) BlockWithAction(dst, protocol string, dport, sport uint16, action Action) error {
	return pm.BlockWithActionPriority(dst, protocol, dport, sport, action, 0)
}

// BlockWithActionPriority adds a port rule with an explicit action and
// priority. The datapath probes all four specificity keys for the packet and
// keeps the matching rule with the highest priority; at equal priority the
// most specific rule wins, so the default priority 0 reproduces the original
// most-specific-first behaviour.
func (pm *PortPolicyManager) BlockWithActionPriority(dst, protocol string, dport, sport uint16, action Action, priority uint32) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := pm.newPortKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	// Advertise before inserting: a set-during-insert race only costs
	// redundant lookups, never a rule bypass.
	if err := setPresenceBit(pm.presence, rulePresencePort); err != nil {
		return err
	}
	return pm.portPolicy.Put(key, ruleValue{Action: uint32(action), Priority: priority})
}

// Unblock removes a port rule matching dst, protocol, and dport.
func (pm *PortPolicyManager) Unblock(dst, protocol string, dport uint16) error {
	return pm.UnblockWithAction(dst, protocol, dport, 0)
}

// UnblockWithAction removes the port rule for dst, protocol, dport and sport.
func (pm *PortPolicyManager) UnblockWithAction(dst, protocol string, dport, sport uint16) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := pm.newPortKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	if err := pm.portPolicy.Delete(key); err != nil {
		return err
	}
	return pm.syncPresence()
}

// List returns all port rules currently in the map.
func (pm *PortPolicyManager) List() ([]server.PortRule, error) {
	var (
		rules []server.PortRule
		key   firewallPortRuleKey
		value ruleValue
	)
	iter := pm.portPolicy.Iterate()
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

// Clear removes every port rule from the map.
func (pm *PortPolicyManager) Clear() error {
	var (
		key   firewallPortRuleKey
		value ruleValue
	)
	iter := pm.portPolicy.Iterate()
	for iter.Next(&key, &value) {
		if err := pm.portPolicy.Delete(key); err != nil {
			return err
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return pm.syncPresence()
}
