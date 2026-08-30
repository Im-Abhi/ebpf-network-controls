package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"ebpf-firewall/control/rules"

	"github.com/cilium/ebpf"
)

// blockedIPValue is the value stored for every entry in the blocked_ips map.
// It must match the C `value, __u32` definition in bpf/maps.h.
const blockedIPValue uint32 = 1

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

// MapManager provides an abstraction over the eBPF maps used for policy enforcement.
type MapManager struct {
	blockedIps *ebpf.Map
}

// NewMapManager creates a new MapManager wrapping the provided eBPF map.
func NewMapManager(blockedIpsMap *ebpf.Map) *MapManager {
	return &MapManager{
		blockedIps: blockedIpsMap,
	}
}

// BlockIP adds an IP or CIDR to the blocked IPs eBPF map.
func (pm *MapManager) BlockIP(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	return pm.blockedIps.Put(key, blockedIPValue)
}

// UnblockIP removes an IP or CIDR from the blocked IPs eBPF map.
func (pm *MapManager) UnblockIP(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()
	key := newLpmKey(ipNet.IP, ones)

	return pm.blockedIps.Delete(key)
}

// ipToKey converts either a bare IP or a CIDR into a /32 lookup key. The lookup
// key for an LPM match is always the exact /32 address; the kernel returns the
// longest matching blocked prefix at or above it.
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

// IsBlocked reports whether the given IP or CIDR is covered by any blocked
// prefix. This is an LPM match, not an exact-key lookup: blocking 10.0.0.0/8
// makes 10.20.30.40 blocked.
func (pm *MapManager) IsBlocked(s string) (bool, error) {
	key, err := ipToKey(s)
	if err != nil {
		return false, err
	}

	var value uint32
	err = pm.blockedIps.Lookup(key, &value)
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ListBlockedIPs returns the current set of blocked prefixes as CIDR strings.
func (pm *MapManager) ListBlockedIPs() ([]string, error) {
	var (
		prefixes []string
		key      firewallIpv4LpmKey
		value    uint32
	)

	iter := pm.blockedIps.Iterate()
	for iter.Next(&key, &value) {
		ipBytes := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipBytes, key.Data)
		prefixes = append(prefixes, fmt.Sprintf("%s/%d", ipBytes.String(), key.Prefixlen))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}

	return prefixes, nil
}

// Clear removes every blocked prefix from the map.
func (pm *MapManager) Clear() error {
	var (
		key   firewallIpv4LpmKey
		value uint32
	)

	iter := pm.blockedIps.Iterate()
	for iter.Next(&key, &value) {
		if err := pm.blockedIps.Delete(key); err != nil {
			return err
		}
	}
	return iter.Err()
}
