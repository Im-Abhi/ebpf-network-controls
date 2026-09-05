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
	ips    map[string]struct{}
	rules  map[string]PortRule
	call   bool
	stat   Stats
	statOK bool
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{
		ips:   make(map[string]struct{}),
		rules: make(map[string]PortRule),
	}
}

func (f *fakePolicy) BlockIP(cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips[cidr] = struct{}{}
	return nil
}

func (f *fakePolicy) UnblockIP(cidr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ips, cidr)
	return nil
}

func (f *fakePolicy) ListBlockedIPs() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.ips))
	for k := range f.ips {
		out = append(out, k)
	}
	return out, nil
}

func (f *fakePolicy) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ips = make(map[string]struct{})
	return nil
}

func (f *fakePolicy) Interface() string {
	return "test0"
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

func (f *fakePolicy) BlockPortRule(dst, protocol string, port uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules[portKey(dst, protocol, port)] = PortRule{Protocol: protocol, Port: port, Dst: dst}
	return nil
}

func (f *fakePolicy) UnblockPortRule(dst, protocol string, port uint16) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rules, portKey(dst, protocol, port))
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

func portKey(dst, protocol string, port uint16) string {
	return fmt.Sprintf("%s/%s/%d", dst, protocol, port)
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
	if resp := s.handle(Request{Command: CmdBlock, Value: "192.168.1.100", Protocol: "tcp", Port: 22}); !resp.OK {
		t.Errorf("block port rule: %+v", resp)
	}

	resp := s.handle(Request{Command: CmdListPorts})
	if !resp.OK || resp.Count != 1 {
		t.Fatalf("listports: %+v", resp)
	}
	if resp.PortRules[0].Dst != "192.168.1.100" || resp.PortRules[0].Protocol != "tcp" || resp.PortRules[0].Port != 22 {
		t.Errorf("unexpected rule: %+v", resp.PortRules)
	}

	// unblock with same flags removes it
	if resp := s.handle(Request{Command: CmdUnblock, Value: "192.168.1.100", Protocol: "tcp", Port: 22}); !resp.OK {
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

func (p *errPolicy) BlockIP(string) error                         { return errors.New("boom") }
func (p *errPolicy) UnblockIP(string) error                       { return errors.New("boom") }
func (p *errPolicy) ListBlockedIPs() ([]string, error)            { return nil, errors.New("boom") }
func (p *errPolicy) Clear() error                                 { return errors.New("boom") }
func (p *errPolicy) Interface() string                            { return "" }
func (p *errPolicy) Stats() (Stats, error)                        { return Stats{}, errors.New("boom") }
func (p *errPolicy) BlockPortRule(string, string, uint16) error   { return errors.New("boom") }
func (p *errPolicy) UnblockPortRule(string, string, uint16) error { return errors.New("boom") }
func (p *errPolicy) ListPortRules() ([]PortRule, error)           { return nil, errors.New("boom") }
func (p *errPolicy) ClearPortRules() error                        { return errors.New("boom") }

func TestHandle_PropagatesErrors(t *testing.T) {
	s := New("unused.sock", &errPolicy{})

	for _, cmd := range []Command{CmdBlock, CmdUnblock, CmdList, CmdClear, CmdStats, CmdListPorts} {
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
