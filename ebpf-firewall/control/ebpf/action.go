package ebpf

import "fmt"

// Action is the per-rule verdict stored in policy maps. It must match
// enum rule_action in bpf/maps.h: 0 = PASS, 1 = DROP.
type Action uint32

const (
	ActionPass Action = 0
	ActionDrop Action = 1
)

// ParseAction maps a human string ("pass", "drop") to an Action.
// It also accepts the empty string as "drop" to keep existing callers
// (which always meant DROP) source-compatible.
func ParseAction(s string) (Action, error) {
	switch s {
	case "", "drop":
		return ActionDrop, nil
	case "pass":
		return ActionPass, nil
	default:
		return 0, fmt.Errorf("invalid action %q (use pass or drop)", s)
	}
}

// String returns the canonical name for an Action.
func (a Action) String() string {
	if a == ActionPass {
		return "pass"
	}
	return "drop"
}
