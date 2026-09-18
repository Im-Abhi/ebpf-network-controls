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
