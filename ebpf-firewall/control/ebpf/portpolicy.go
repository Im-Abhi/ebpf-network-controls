package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

// portRuleValue is the value stored for every entry in the port_policy map.
// It must match the C `value, __u32` definition in bpf/maps.h. 1 = DROP,
// 0 is reserved (PASS) for future use.
const (
	portRuleDrop    uint32 = 1
	portAnyProtocol uint8  = 0
	portAnyPort     uint16 = 0
	protoTCP        uint8  = 6
	protoUDP        uint8  = 17
)

// PortRule describes a single protocol+port+destination rule.
type PortRule struct {
	Protocol string // "tcp", "udp", or "" (any)
	Port     uint16 // destination port, or 0 (any)
	Dst      string // destination IP
}

// firewallPortRuleKey mirrors struct port_rule_key in bpf/maps.h:
//
//	struct port_rule_key {
//	    __u8  protocol;   // IPPROTO_TCP/UDP, 0 = any
//	    __u16 dport;      // destination port, network byte order, 0 = any
//	    __u32 dst;        // destination IP, network byte order
//	};
//
// The generated type (after `make generate`) uses structs.HostLayout so its
// on-wire layout exactly matches the C struct, including the alignment
// padding after protocol. Only this layer knows the byte layout.

// PortPolicyManager provides an abstraction over the port_policy eBPF map.
type PortPolicyManager struct {
	portPolicy *ebpf.Map
}

// NewPortPolicyManager wraps the port_policy map.
func NewPortPolicyManager(m *ebpf.Map) *PortPolicyManager {
	return &PortPolicyManager{portPolicy: m}
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

// newPortKey builds the map key for a (dst, protocol, port) rule.
func (pm *PortPolicyManager) newPortKey(dst string, proto uint8, port uint16) (firewallPortRuleKey, error) {
	var key firewallPortRuleKey

	ip := net.ParseIP(strings.TrimSpace(dst)).To4()
	if ip == nil {
		return key, fmt.Errorf("invalid IPv4 destination %q", dst)
	}

	key.Protocol = proto
	key.Dst = binary.LittleEndian.Uint32(ip)

	// dport must be in network byte order: the C datapath compares it against
	// tcp->dest, whose in-memory bytes are the wire bytes (high byte first,
	// e.g. port 22 -> [0x00, 0x16]). Store the value whose little-endian bytes
	// reproduce that sequence, i.e. htons(port) on a little-endian host.
	netBytes := []byte{byte(port >> 8), byte(port & 0xff)}
	key.Dport = binary.LittleEndian.Uint16(netBytes)

	return key, nil
}

// Block adds a port rule that DROPs traffic to dst on the given protocol/port.
// protocol may be "tcp", "udp", or "" (any). port of 0 means any port.
func (pm *PortPolicyManager) Block(dst, protocol string, port uint16) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := pm.newPortKey(dst, proto, port)
	if err != nil {
		return err
	}
	return pm.portPolicy.Put(key, portRuleDrop)
}

// Unblock removes a port rule matching dst, protocol, and port.
func (pm *PortPolicyManager) Unblock(dst, protocol string, port uint16) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := pm.newPortKey(dst, proto, port)
	if err != nil {
		return err
	}
	return pm.portPolicy.Delete(key)
}

// List returns all port rules currently in the map.
func (pm *PortPolicyManager) List() ([]PortRule, error) {
	var (
		rules []PortRule
		key   firewallPortRuleKey
		value uint32
	)
	iter := pm.portPolicy.Iterate()
	for iter.Next(&key, &value) {
		ipBytes := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Dst)
		rules = append(rules, PortRule{
			Protocol: codeToProto(key.Protocol),
			Port:     key.Dport,
			Dst:      ipBytes.String(),
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
		value uint32
	)
	iter := pm.portPolicy.Iterate()
	for iter.Next(&key, &value) {
		if err := pm.portPolicy.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}
