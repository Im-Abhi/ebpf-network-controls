package ebpf

// ruleValue mirrors struct rule_value in bpf/maps.h, the value stored in both
// the blocked_ips (LPM trie) and port_policy (hash) maps:
//
//	struct rule_value {
//	    __u32 action;    // enum rule_action (0 = PASS, 1 = DROP)
//	    __u32 priority;  // higher wins; tie -> DROP
//	};
//
// It is declared here rather than relying on the bpf2go-generated binding so
// the control plane compiles without a regeneration step and the on-wire
// contract between the maps and this code stays visible in one place. It must
// be kept in sync with bpf/maps.h. Both fields are fixed-width and exported,
// so cilium/ebpf marshals it as the two little-endian uint32s the datapath
// expects.
type ruleValue struct {
	Action   uint32
	Priority uint32
}

// Conntrack state values stored in ctValue.State. They must match enum
// ct_state in bpf/maps.h.
const (
	ctStateNew         uint32 = 1
	ctStateEstablished uint32 = 2
	ctStateClosed      uint32 = 3
)

// ctStateString maps a stored state value to its canonical name for the
// control plane. Unknown values (e.g. an older datapath) render as
// "unknown".
func ctStateString(state uint32) string {
	switch state {
	case ctStateNew:
		return "new"
	case ctStateEstablished:
		return "established"
	case ctStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// ctKey mirrors struct ct_key in bpf/maps.h, the key of the conntrack map:
//
//	struct ct_key {
//	    __u32 saddr;     // network byte order
//	    __u32 daddr;     // network byte order
//	    __u16 sport;     // network byte order
//	    __u16 dport;     // network byte order
//	    __u8  protocol;  // IPPROTO_TCP
//	    __u8  _pad[3];
//	};
//
// The blank padding field is written as zeroes by cilium/ebpf's marshaller, so
// it matches the datapath's __builtin_memset-ed key. Declared here (rather
// than using the bpf2go binding) so the control plane compiles without a
// regeneration step; keep it in sync with bpf/maps.h.
type ctKey struct {
	Saddr    uint32
	Daddr    uint32
	Sport    uint16
	Dport    uint16
	Protocol uint8
	_        [3]byte
}

// ctValue mirrors struct ct_value in bpf/maps.h:
//
//	struct ct_value {
//	    __u64 last_seen; // bpf_ktime_get_ns() (CLOCK_MONOTONIC)
//	    __u32 state;     // enum ct_state
//	    __u32 _pad;
//	};
type ctValue struct {
	LastSeen uint64
	State    uint32
	_        uint32
}
