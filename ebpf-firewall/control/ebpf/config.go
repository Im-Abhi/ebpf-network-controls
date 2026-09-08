package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// DefaultPolicy is the fallback verdict applied by the datapath when no rule
// matches. It must match enum default_policy in bpf/maps.h: 0 = ALLOW, 1 = DENY.
type DefaultPolicy uint32

const (
	DefaultAllow DefaultPolicy = 0
	DefaultDeny  DefaultPolicy = 1
)

// ParseDefaultPolicy maps "allow"/"deny" (or empty = allow) to a DefaultPolicy.
func ParseDefaultPolicy(s string) (DefaultPolicy, error) {
	switch s {
	case "", "allow":
		return DefaultAllow, nil
	case "deny":
		return DefaultDeny, nil
	default:
		return 0, fmt.Errorf("invalid default policy %q (use allow or deny)", s)
	}
}

// String returns the canonical name for a DefaultPolicy.
func (p DefaultPolicy) String() string {
	if p == DefaultDeny {
		return "deny"
	}
	return "allow"
}

// ConfigManager reads and writes the single-entry config map that holds the
// default policy. Key 0 holds the default policy value.
type ConfigManager struct {
	config *ebpf.Map
}

// NewConfigManager wraps the config map.
func NewConfigManager(m *ebpf.Map) *ConfigManager {
	return &ConfigManager{config: m}
}

// SetDefaultPolicy writes the default policy into the config map.
func (cm *ConfigManager) SetDefaultPolicy(p DefaultPolicy) error {
	var key uint32 = 0
	return cm.config.Put(key, uint32(p))
}

// DefaultPolicy reads the default policy from the config map, treating a
// missing entry as DefaultAllow (matching the datapath fallback).
func (cm *ConfigManager) DefaultPolicy() (DefaultPolicy, error) {
	var key uint32 = 0
	var value uint32
	if err := cm.config.Lookup(key, &value); err != nil {
		if err == ebpf.ErrKeyNotExist {
			return DefaultAllow, nil
		}
		return DefaultAllow, err
	}
	return DefaultPolicy(value), nil
}
