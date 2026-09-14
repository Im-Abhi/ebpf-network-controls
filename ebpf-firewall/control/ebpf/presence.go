package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

// Rule-presence bits mirroring bpf/maps.h (RULE_IP_PRESENT, RULE_PORT_PRESENT).
// The datapath skips the blocked_ips / port_policy lookups while the matching
// bit is clear, because an empty map can only miss. Managers keep the bits
// conservative (set before the first insert, cleared only after the last
// delete) so a live rule is never bypassed.
const (
	rulePresenceIP   uint32 = 1 << 0
	rulePresencePort uint32 = 1 << 1
)

// presenceMapKey is entry 0 of the single-entry rule_presence array map.
var presenceMapKey = uint32(0)

// setPresenceBit ORs the given bit into the rule_presence map. A nil map
// (standalone test maps with no datapath attached) is a no-op.
func setPresenceBit(presence *ebpf.Map, bit uint32) error {
	if presence == nil {
		return nil
	}
	var flags uint32
	if err := presence.Lookup(presenceMapKey, &flags); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return presence.Put(presenceMapKey, flags|bit)
}

// clearPresenceBit clears the given bit from the rule_presence map. A nil map
// is a no-op.
func clearPresenceBit(presence *ebpf.Map, bit uint32) error {
	if presence == nil {
		return nil
	}
	var flags uint32
	if err := presence.Lookup(presenceMapKey, &flags); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return presence.Put(presenceMapKey, flags &^ bit)
}

// mapHasEntries reports whether the given map contains at least one entry,
// halting at the first hit so it runs in O(1) when populated. The generic
// []byte key avoids tying this helper to a specific key struct.
func mapHasEntries(m *ebpf.Map) (bool, error) {
	var key []byte
	var value uint32
	iter := m.Iterate()
	has := iter.Next(&key, &value)
	if err := iter.Err(); err != nil {
		return false, err
	}
	return has, nil
}