package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"ebpf-firewall/control/rules"
	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf"
)

// The policy layer is exactly two table shapes, instantiated once per
// direction (see facade.go):
//
//	cidrTable -> blocked_ips / egress_blocked_ips  (LPM trie; key = prefix)
//	portTable -> port_policy / egress_port_policy  (hash; key = dst+proto+dport+sport)
//
// A table owns everything that must behave identically in both directions:
//
//   - The on-wire key/value encoding (see the helpers below — the byte order
//     contracts with bpf/maps.h are the subtle part of the whole control plane).
//   - The presence-bit ordering contract: the bit is SET before the first
//     insert and CLEARED only after the last delete, so the datapath's
//     empty-map fast path (rule_presence in bpf/maps.h) never bypasses a live
//     rule. A set-during-insert race can only cause redundant lookups, never
//     a bypassed rule.
//   - The snapshot-first Clear idiom: deleting keys while iterating a map is
//     not safe (cilium/ebpf) and on a real kernel the iterator can silently
//     skip entries, leaving rules behind with no error.
type cidrTable struct {
	m        *ebpf.Map
	presence *ebpf.Map
	bit      uint32
}

// newCidrTable wraps one IP/CIDR (LPM) policy map. presence may be nil, which
// disables the fast-path flag maintenance (used by standalone test maps).
func newCidrTable(m, presence *ebpf.Map, bit uint32) cidrTable {
	return cidrTable{m: m, presence: presence, bit: bit}
}

// Add inserts or overwrites the rule for an IP/CIDR prefix with the given
// action and priority. The kernel's LPM trie chooses the longest matching
// prefix per packet; priority only orders that match against other rules
// (see decide() in bpf/firewall.c).
func (t cidrTable) Add(cidrStr string, action Action, priority uint32) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	// Advertise before inserting so a pre-existing rule is never skipped by
	// the datapath's empty-map fast path.
	if err := setPresenceBit(t.presence, t.bit); err != nil {
		return err
	}
	return t.m.Put(key, ruleValue{Action: uint32(action), Priority: priority})
}

// Remove deletes the rule for an IP/CIDR prefix.
func (t cidrTable) Remove(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	if err := t.m.Delete(key); err != nil {
		return err
	}
	return t.syncPresence()
}

// Contains reports whether the given IP or CIDR is covered by any rule. This
// is an LPM match, not an exact-key lookup: a rule for 10.0.0.0/8 makes
// 10.20.30.40 covered.
func (t cidrTable) Contains(s string) (bool, error) {
	key, err := ipToKey(s)
	if err != nil {
		return false, err
	}

	var value ruleValue
	err = t.m.Lookup(key, &value)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// List returns all rules as CIDR/action/priority.
func (t cidrTable) List() ([]server.BlockedRule, error) {
	var (
		rules []server.BlockedRule
		key   firewallIpv4LpmKey
		value ruleValue
	)

	iter := t.m.Iterate()
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

// CIDRs returns just the rule prefixes (the `list`/`status` short form).
func (t cidrTable) CIDRs() ([]string, error) {
	rules, err := t.List()
	if err != nil {
		return nil, err
	}
	prefixes := make([]string, 0, len(rules))
	for _, r := range rules {
		prefixes = append(prefixes, r.Cidr)
	}
	return prefixes, nil
}

// Clear removes every rule from the table.
//
// Keys are snapshotted before deletion: deleting keys from a map while
// iterating it is not safe (cilium/ebpf) and can silently skip entries on a
// real kernel.
func (t cidrTable) Clear() error {
	var (
		keys  []firewallIpv4LpmKey
		key   firewallIpv4LpmKey
		value ruleValue
	)

	iter := t.m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := t.m.Delete(k); err != nil {
			return err
		}
	}
	return t.syncPresence()
}

// syncPresence makes the table's presence bit match reality (map empty or
// not). Called after mutations that may have emptied the map.
func (t cidrTable) syncPresence() error {
	has, err := mapHasEntries(t.m)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(t.presence, t.bit)
	}
	return clearPresenceBit(t.presence, t.bit)
}

// portTable is one protocol/port rule table: a hash map keyed by
// (dst, protocol, dport, sport) plus the presence bit advertising its
// non-emptiness. 0 in protocol, dport or sport means "any" (the datapath
// probes all four specificity keys per packet).
type portTable struct {
	m        *ebpf.Map
	presence *ebpf.Map
	bit      uint32
}

// newPortTable wraps one port-policy hash map. presence may be nil.
func newPortTable(m, presence *ebpf.Map, bit uint32) portTable {
	return portTable{m: m, presence: presence, bit: bit}
}

// Add inserts or overwrites the rule for (dst, protocol, dport, sport).
func (t portTable) Add(dst, protocol string, dport, sport uint16, action Action, priority uint32) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := buildPortRuleKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	// Advertise before inserting (same ordering contract as cidrTable.Add).
	if err := setPresenceBit(t.presence, t.bit); err != nil {
		return err
	}
	return t.m.Put(key, ruleValue{Action: uint32(action), Priority: priority})
}

// Remove deletes the rule for (dst, protocol, dport, sport).
func (t portTable) Remove(dst, protocol string, dport, sport uint16) error {
	proto, err := protoToCode(protocol)
	if err != nil {
		return err
	}
	key, err := buildPortRuleKey(dst, proto, dport, sport)
	if err != nil {
		return err
	}
	if err := t.m.Delete(key); err != nil {
		return err
	}
	return t.syncPresence()
}

// List returns all port rules currently in the table.
func (t portTable) List() ([]server.PortRule, error) {
	rules := make([]server.PortRule, 0, 8)
	var (
		key   firewallPortRuleKey
		value ruleValue
	)
	iter := t.m.Iterate()
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

// Clear removes every rule from the table (snapshot-first; see cidrTable).
func (t portTable) Clear() error {
	var (
		keys  []firewallPortRuleKey
		key   firewallPortRuleKey
		value ruleValue
	)
	iter := t.m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := t.m.Delete(k); err != nil {
			return err
		}
	}
	return t.syncPresence()
}

// syncPresence makes the table's presence bit match reality.
func (t portTable) syncPresence() error {
	has, err := mapHasEntries(t.m)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(t.presence, t.bit)
	}
	return clearPresenceBit(t.presence, t.bit)
}

// domainTable is the hostname blocklist (URL filtering): a hash map keyed
// by the name itself. It is consumed only by the TC egress datapath
// (tls_sni_extract / http_host_extract in bpf/firewall.c), and every entry
// carries ACTION_DROP — the blocklist is an explicit deny, not a priority
// participant.
//
// Key normalization lives here so every writer (the file loader today, a
// CLI command later) produces byte-identical keys to the datapath's
// probes: lowercase, truncated to the kernel's 63-byte contract
// (DOMAIN_NAME_MAX in bpf/firewall.c), zero-padded by the marshaller.
type domainTable struct {
	m        *ebpf.Map
	presence *ebpf.Map
	bit      uint32
}

// newDomainTable wraps one hostname-blocklist hash map. presence may be
// nil, which disables the fast-path flag maintenance (used by standalone
// test maps).
func newDomainTable(m, presence *ebpf.Map, bit uint32) domainTable {
	return domainTable{m: m, presence: presence, bit: bit}
}

// domainNameMax must match DOMAIN_NAME_MAX in bpf/firewall.c: longer names
// are truncated identically on both sides of the map.
const domainNameMax = 63

// domainKeyOf normalizes a hostname into the reversed LPM map key. The
// datapath stores and probes names reversed so a parent suffix is a byte
// prefix of the reversed name; one longest-prefix-match lookup then covers
// subdomains (see lpm_domain_key in bpf/maps.h). Normalization: lowercase,
// truncated to the kernel's 63-byte contract (DOMAIN_NAME_MAX in
// bpf/firewall.c); prefixlen carries the effective length in bits.
func domainKeyOf(name string) (firewallLpmDomainKey, error) {
	var key firewallLpmDomainKey
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return key, fmt.Errorf("empty domain name")
	}
	if len(name) > domainNameMax {
		name = name[:domainNameMax] // same truncation contract as the datapath
	}
	key.Prefixlen = uint32(len(name) * 8)
	for i := 0; i < len(name); i++ {
		key.Name[len(name)-1-i] = name[i]
	}
	return key, nil
}

// Add inserts a hostname with the blocklist's fixed verdict (DROP).
func (t domainTable) Add(name string) error {
	key, err := domainKeyOf(name)
	if err != nil {
		return err
	}
	// Advertise before inserting (same ordering contract as cidrTable).
	if err := setPresenceBit(t.presence, t.bit); err != nil {
		return err
	}
	return t.m.Put(key, ruleValue{Action: uint32(ActionDrop)})
}

// Remove deletes a hostname from the table.
func (t domainTable) Remove(name string) error {
	key, err := domainKeyOf(name)
	if err != nil {
		return err
	}
	if err := t.m.Delete(key); err != nil {
		return err
	}
	return t.syncPresence()
}

// Contains reports whether the hostname is on the blocklist.
func (t domainTable) Contains(name string) (bool, error) {
	key, err := domainKeyOf(name)
	if err != nil {
		return false, err
	}
	var value ruleValue
	err = t.m.Lookup(key, &value)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// List returns all blocklisted hostnames.
func (t domainTable) List() ([]string, error) {
	names := make([]string, 0, 8)
	var (
		key   firewallLpmDomainKey
		value ruleValue
	)
	iter := t.m.Iterate()
	for iter.Next(&key, &value) {
		n := int(key.Prefixlen / 8) // effective name length in bytes
		if n > len(key.Name) {
			n = len(key.Name)
		}
		name := make([]byte, n)
		for i := 0; i < n; i++ {
			name[i] = key.Name[n-1-i] // keys are stored reversed
		}
		names = append(names, string(name))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// Clear removes every hostname from the table (snapshot-first; see
// cidrTable).
func (t domainTable) Clear() error {
	var (
		keys  []firewallLpmDomainKey
		key   firewallLpmDomainKey
		value ruleValue
	)
	iter := t.m.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range keys {
		if err := t.m.Delete(k); err != nil {
			return err
		}
	}
	return t.syncPresence()
}

// syncPresence makes the table's presence bit match reality.
func (t domainTable) syncPresence() error {
	has, err := mapHasEntries(t.m)
	if err != nil {
		return err
	}
	if has {
		return setPresenceBit(t.presence, t.bit)
	}
	return clearPresenceBit(t.presence, t.bit)
}

// ── Key & wire-encoding helpers ──────────────────────────────────────────────
// These encode the byte-order contracts with bpf/maps.h. Both directions use
// them unchanged; only the maps differ.

// newLpmKey builds an LPM trie lookup/insertion key for a parsed IPv4 network.
//
// The C key struct is an 8-byte layout:
//
//	struct ipv4_lpm_key {
//	    __u32 prefixlen;   // 4 bytes: prefix length (bits)
//	    __u32 data;        // 4 bytes: the IPv4 address in network byte order
//	};
//
// The BPF program inserts on the wire by copying ip->saddr into data, so the
// map key's raw bytes carry the IPv4 address in network order. The kernel LPM
// trie then matches `prefixlen` most-significant bits of those bytes. To
// reproduce the identical byte layout from Go we write the network-order
// address into the uint32 field using LittleEndian, which preserves the byte
// order `IP[0] IP[1] IP[2] IP[3]` in memory. Using BigEndian here would
// reverse the bytes and break prefix matching.
func newLpmKey(ipBytes net.IP, prefixLen int) firewallIpv4LpmKey {
	var key firewallIpv4LpmKey
	key.Prefixlen = uint32(prefixLen)
	key.Data = binary.LittleEndian.Uint32(ipBytes[:4])
	return key
}

// ipToKey converts either a bare IP or a CIDR into a /32 lookup key. The
// lookup key for an LPM match is always the exact /32 address; the kernel
// returns the longest matching rule prefix at or above it.
func ipToKey(s string) (firewallIpv4LpmKey, error) {
	ipBytes, err := ipBytesOf(s)
	if err != nil {
		return firewallIpv4LpmKey{}, err
	}
	return newLpmKey(ipBytes, 32), nil
}

// ipBytesOf returns the 4-byte network-order representation of an IP or CIDR.
func ipBytesOf(s string) (net.IP, error) {
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("only IPv4 is supported: %q", s)
	}

	ipNet, err := rules.ParseIPOrCIDR(s)
	if err != nil {
		return nil, err
	}
	return ipNet.IP, nil
}

// buildPortRuleKey builds the map key for a (dst, protocol, dport, sport)
// rule. It is shared by both directions so the identical key layout is
// encoded in exactly one place.
func buildPortRuleKey(dst string, proto uint8, dport, sport uint16) (firewallPortRuleKey, error) {
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
// as stored in the map key.
func portToWire(p uint16) uint16 {
	netBytes := []byte{byte(p >> 8), byte(p & 0xff)}
	return binary.LittleEndian.Uint16(netBytes)
}

// wireToPort converts a network-byte-order port stored in the map key back to
// the logical port number. The key keeps the wire bytes (e.g. port 22 ->
// [0x00, 0x16]); on a little-endian host the stored uint16 is 0x1600, so the
// wire bytes are rebuilt and read back big-endian to recover the port.
func wireToPort(w uint16) uint16 {
	b := [2]byte{byte(w), byte(w >> 8)}
	return binary.BigEndian.Uint16(b[:])
}

// Protocol/port sentinel values. A protocol, destination port or source port
// of zero means "any" (see struct port_rule_key in bpf/maps.h).
const (
	portAnyProtocol uint8  = 0
	portAnyPort     uint16 = 0
	protoTCP        uint8  = 6
	protoUDP        uint8  = 17
)

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
