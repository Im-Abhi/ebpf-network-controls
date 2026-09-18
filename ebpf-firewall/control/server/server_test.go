package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// fakePolicy is a thread-safe in-memory Policy for unit tests (no kernel).
type fakePolicy struct {
	mu     sync.Mutex
	ips    map[string]BlockedRule
	rules  map[string]PortRule
	call   bool
	stat   Stats
	statOK bool
	def    string
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{
		ips:   make(map[string]BlockedRule),
		rules: make(map[string]PortRule),
		def:   "allow",
	}
}

func (f *fakePolicy) BlockIP(cidr string) error {
	return f.BlockIPWithActionPriority(cidr, "drop", 0)
}

func (f *fakePolicy) BlockIPWithAction(cidr, action string) error {
	return f.BlockIPWithActionPriority(cidr, action, 0)
}

func (f *fakePolicy) BlockIPWithActionPriority(cidr, action string, priority uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips[cidr] = BlockedRule{Cidr: cidr, Action: action, Priority: priority}
	return nil
}

func (f *fakePolicy) UnblockIP(cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ips, cidr)
	return nil
}

func (f *fakePolicy) ListBlockedIPs() ([]string, error) {
	rules, err := f.ListBlockedRules()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Cidr)
	}
	return out, nil
}

func (f *fakePolicy) ListBlockedRules() ([]BlockedRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]BlockedRule, 0, len(f.ips))
	for _, r := range f.ips {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakePolicy) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips = make(map[string]BlockedRule)
	return nil
}

func (f *fakePolicy) Interface() string {
	return "test0"
}

func (f *fakePolicy) AttachMode() string {
	return "xdpGeneric"
}

func (f *fakePolicy) Stats() (Stats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statOK {
		return f.stat, nil
	}
	return Stats{
		TotalPackets: 100,
		TotalBytes:   5000,
		DropPackets:  10,
		DropBytes:    600,
		PassPackets:  90,
		PassBytes:    4400,
	}, nil
}

func (f *fakePolicy) BlockPortRule(dst, protocol string, dport, sport uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[portKey(dst, protocol, dport, sport)] = PortRule{Protocol: protocol, Port: dport, SPort: sport, Dst: dst, Action: "drop"}
	return nil
}

func (f *fakePolicy) BlockPortRuleWithAction(dst, protocol string, dport, sport uint16, action string) error {
	return f.BlockPortRuleWithActionPriority(dst, protocol, dport, sport, action, 0)
}

func (f *fakePolicy) BlockPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, action string, priority uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[portKey(dst, protocol, dport, sport)] = PortRule{Protocol: protocol, Port: dport, SPort: sport, Dst: dst, Action: action, Priority: priority}
	return nil
}

func (f *fakePolicy) SetDefaultPolicy(s string) error {
	if s != "allow" && s != "deny" {
		return fmt.Errorf("invalid default policy %q", s)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.def = s
	return nil
}

func (f *fakePolicy) DefaultPolicy() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.def, nil
}

func (f *fakePolicy) UnblockPortRule(dst, protocol string, dport, sport uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, portKey(dst, protocol, dport, sport))
	return nil
}

func (f *fakePolicy) ListPortRules() ([]PortRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]PortRule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakePolicy) ClearPortRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = make(map[string]PortRule)
	return nil
}

func portKey(dst, protocol string, dport, sport uint16) string {
	return fmt.Sprintf("%s/%s/%d/%d", dst, protocol, dport, sport)
}

func TestHandle_BlockListUnblockClear(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	if resp := s.handle(Request{Command: CmdBlock, Value: "8.8.8.8"}); !resp.OK {
		t.Errorf("block: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdList}); !resp.OK || resp.Count != 1 {
		t.Errorf("list after block: %+v", resp)
	} else if !reflect.DeepEqual(resp.Blocked, []string{"8.8.8.8"}) {
		t.Errorf("list blocked = %v, want [8.8.8.8]", resp.Blocked)
	}

	if resp := s.handle(Request{Command: CmdStatus}); !resp.OK || resp.Count != 1 {
		t.Errorf("status: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdUnblock, Value: "8.8.8.8"}); !resp.OK {
		t.Errorf("unblock: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdStatus}); !resp.OK || resp.Count != 0 {
		t.Errorf("status after unblock: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdClear}); !resp.OK {
		t.Errorf("clear: %+v", resp)
	}
}

func TestHandle_BlockPortRule(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	// block with protocol + port routes to the port-rule path
	if resp := s.handle(Request{Command: CmdBlock, Value: "192.168.1.100", Protocol: "tcp", Port: 22, SPort: 50000}); !resp.OK {
		t.Errorf("block port rule: %+v", resp)
	}

	resp := s.handle(Request{Command: CmdListPorts})
	if !resp.OK || resp.Count != 1 {
		t.Fatalf("listports: %+v", resp)
	}
	if resp.PortRules[0].Dst != "192.168.1.100" || resp.PortRules[0].Protocol != "tcp" || resp.PortRules[0].Port != 22 || resp.PortRules[0].SPort != 50000 {
		t.Errorf("unexpected rule: %+v", resp.PortRules)
	}

	// unblock with same flags removes it
	if resp := s.handle(Request{Command: CmdUnblock, Value: "192.168.1.100", Protocol: "tcp", Port: 22, SPort: 50000}); !resp.OK {
		t.Errorf("unblock port rule: %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdListPorts}); !resp.OK || resp.Count != 0 {
		t.Errorf("listports after unblock: %+v", resp)
	}
}

func TestHandle_BlockPlainIPStillWorks(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	// block without protocol/port routes to the IP path
	if resp := s.handle(Request{Command: CmdBlock, Value: "8.8.8.8"}); !resp.OK {
		t.Errorf("block plain IP: %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdListPorts}); resp.Count != 0 {
		t.Errorf("port rules should be empty, got %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdList}); resp.Count != 1 {
		t.Errorf("IP list should have 1, got %+v", resp)
	}
}

func TestHandle_DefaultPolicy(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	// default command reads/writes the default policy
	if resp := s.handle(Request{Command: CmdDefault, Value: "deny"}); !resp.OK {
		t.Errorf("set default deny: %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdStatus}); !resp.OK {
		t.Fatalf("status: %+v", resp)
	} else if resp.Default != "deny" {
		t.Errorf("status default = %q, want deny", resp.Default)
	}

	// invalid value propagates the error
	if resp := s.handle(Request{Command: CmdDefault, Value: "bogus"}); resp.OK {
		t.Errorf("invalid default should not be ok: %+v", resp)
	}
}

func TestHandle_BlockWithAction(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	// port rule with explicit action routes to the WithAction path
	if resp := s.handle(Request{Command: CmdBlock, Value: "192.168.1.100", Protocol: "tcp", Port: 22, Action: "pass"}); !resp.OK {
		t.Errorf("block port with action: %+v", resp)
	}
	resp := s.handle(Request{Command: CmdListPorts})
	if !resp.OK || resp.Count != 1 {
		t.Fatalf("listports: %+v", resp)
	}
	if resp.PortRules[0].Action != "pass" {
		t.Errorf("port rule action = %q, want pass", resp.PortRules[0].Action)
	}

	// IP rule with explicit action
	if resp := s.handle(Request{Command: CmdBlock, Value: "10.0.0.0/8", Action: "pass"}); !resp.OK {
		t.Errorf("block IP with action: %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdList}); resp.Count != 1 {
		t.Errorf("IP list should have 1, got %+v", resp)
	}
}

func TestHandle_BlockPriority(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	// port rule with explicit action + priority carries the priority through
	if resp := s.handle(Request{Command: CmdBlock, Value: "192.168.1.100", Protocol: "tcp", Port: 22, Action: "pass", Priority: 100}); !resp.OK {
		t.Fatalf("block port with priority: %+v", resp)
	}
	resp := s.handle(Request{Command: CmdListPorts})
	if !resp.OK || resp.Count != 1 {
		t.Fatalf("listports: %+v", resp)
	}
	if resp.PortRules[0].Priority != 100 {
		t.Errorf("port rule priority = %d, want 100", resp.PortRules[0].Priority)
	}

	// IP rule with explicit action + priority is returned in BlockedRules
	if resp := s.handle(Request{Command: CmdBlock, Value: "10.0.0.0/8", Action: "pass", Priority: 7}); !resp.OK {
		t.Fatalf("block IP with priority: %+v", resp)
	}
	resp = s.handle(Request{Command: CmdList})
	if !resp.OK || resp.Count != 1 || len(resp.BlockedRules) != 1 {
		t.Fatalf("list: %+v", resp)
	}
	if resp.BlockedRules[0].Priority != 7 || resp.BlockedRules[0].Action != "pass" {
		t.Errorf("blocked rule = %+v, want action pass priority 7", resp.BlockedRules[0])
	}
}

func TestHandle_ClearRemovesPortRules(t *testing.T) {
	policy := newFakePolicy()
	s := New("unused.sock", policy)

	if resp := s.handle(Request{Command: CmdBlock, Value: "192.168.1.100", Protocol: "tcp", Port: 22}); !resp.OK {
		t.Fatalf("block port rule: %+v", resp)
	}
	if resp := s.handle(Request{Command: CmdBlock, Value: "8.8.8.8"}); !resp.OK {
		t.Fatalf("block ip: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdClear}); !resp.OK {
		t.Fatalf("clear: %+v", resp)
	}

	if resp := s.handle(Request{Command: CmdList}); resp.OK && resp.Count != 0 {
		t.Errorf("list after clear = %+v, want empty", resp)
	}
	if resp := s.handle(Request{Command: CmdListPorts}); resp.OK && resp.Count != 0 {
		t.Errorf("listports after clear = %+v, want empty", resp)
	}
}

func TestHandle_UnknownCommand(t *testing.T) {
	s := New("unused.sock", newFakePolicy())
	if resp := s.handle(Request{Command: "bogus"}); resp.OK {
		t.Errorf("unknown command should not be ok: %+v", resp)
	}
}

func TestHandle_Stats(t *testing.T) {
	s := New("unused.sock", newFakePolicy())
	resp := s.handle(Request{Command: CmdStats})
	if !resp.OK {
		t.Fatalf("stats: %+v", resp)
	}
	if resp.Stats == nil {
		t.Fatal("stats response has nil Stats")
	}
	if resp.Stats.TotalPackets != 100 {
		t.Errorf("TotalPackets = %d, want 100", resp.Stats.TotalPackets)
	}
	if resp.Stats.DropBytes != 600 {
		t.Errorf("DropBytes = %d, want 600", resp.Stats.DropBytes)
	}
}

// errPolicy returns an error from every blocked-side operation.
type errPolicy struct{}

func (p *errPolicy) BlockIP(string) error                           { return errors.New("boom") }
func (p *errPolicy) BlockIPWithAction(string, string) error         { return errors.New("boom") }
func (p *errPolicy) BlockIPWithActionPriority(string, string, uint32) error {
	return errors.New("boom")
}
func (p *errPolicy) UnblockIP(string) error                  { return errors.New("boom") }
func (p *errPolicy) ListBlockedIPs() ([]string, error)       { return nil, errors.New("boom") }
func (p *errPolicy) ListBlockedRules() ([]BlockedRule, error) { return nil, errors.New("boom") }
func (p *errPolicy) Clear() error                            { return errors.New("boom") }
func (p *errPolicy) Interface() string                       { return "" }
func (p *errPolicy) AttachMode() string                      { return "" }
func (p *errPolicy) Stats() (Stats, error)                   { return Stats{}, errors.New("boom") }
func (p *errPolicy) BlockPortRule(string, string, uint16, uint16) error { return errors.New("boom") }
func (p *errPolicy) BlockPortRuleWithAction(string, string, uint16, uint16, string) error {
	return errors.New("boom")
}
func (p *errPolicy) BlockPortRuleWithActionPriority(string, string, uint16, uint16, string, uint32) error {
	return errors.New("boom")
}
func (p *errPolicy) UnblockPortRule(string, string, uint16, uint16) error { return errors.New("boom") }
func (p *errPolicy) ListPortRules() ([]PortRule, error)                    { return nil, errors.New("boom") }
func (p *errPolicy) ClearPortRules() error                                 { return errors.New("boom") }
func (p *errPolicy) SetDefaultPolicy(string) error                         { return errors.New("boom") }
func (p *errPolicy) DefaultPolicy() (string, error)                        { return "", errors.New("boom") }

func TestHandle_PropagatesErrors(t *testing.T) {
	s := New("unused.sock", &errPolicy{})

	for _, cmd := range []Command{CmdBlock, CmdUnblock, CmdList, CmdClear, CmdStats, CmdListPorts, CmdDefault} {
		if resp := s.handle(Request{Command: cmd, Value: "x"}); resp.OK {
			t.Errorf("%s should not be ok with failing policy: %+v", cmd, resp)
		}
	}
}

func TestStartClose_SocketRemoved(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fw.sock")
	policy := newFakePolicy()
	s := New(socketPath, policy)

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancel()
}
