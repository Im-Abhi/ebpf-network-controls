package ebpf

import (
	"ebpf-firewall/control/rules"

	"github.com/cilium/ebpf"
)

// Ipv4LpmKey must match the kernel struct memory layout for LPM_TRIE
type Ipv4LpmKey struct {
	PrefixLen uint32
	Data      [4]byte
}

// MapManager provides an abstraction over the eBPF maps used for policy enforcement
type MapManager struct {
	blockedIps *ebpf.Map
}

// NewMapManager creates a new MapManager wrapping the provided eBPF map
func NewMapManager(blockedIpsMap *ebpf.Map) *MapManager {
	return &MapManager{
		blockedIps: blockedIpsMap,
	}
}

// BlockIP adds an IP or CIDR to the blocked IPs eBPF map
func (pm *MapManager) BlockIP(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()

	var key Ipv4LpmKey
	key.PrefixLen = uint32(ones)
	copy(key.Data[:], ipNet.IP) // ipNet.IP is already 4 bytes

	var value uint32 = 1
	return pm.blockedIps.Put(key, value)
}

// UnblockIP removes an IP or CIDR from the blocked IPs eBPF map
func (pm *MapManager) UnblockIP(cidrStr string) error {
	ipNet, err := rules.ParseIPOrCIDR(cidrStr)
	if err != nil {
		return err
	}

	ones, _ := ipNet.Mask.Size()

	var key Ipv4LpmKey
	key.PrefixLen = uint32(ones)
	copy(key.Data[:], ipNet.IP)

	return pm.blockedIps.Delete(key)
}
