package server

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

// fakePolicy is a thread-safe in-memory Policy for unit tests (no kernel).
type fakePolicy struct {
	mu   sync.Mutex
	ips  map[string]struct{}
	call bool
}

func newFakePolicy() *fakePolicy {
	return &fakePolicy{ips: make(map[string]struct{})}
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

func TestHandle_UnknownCommand(t *testing.T) {
	s := New("unused.sock", newFakePolicy())
	if resp := s.handle(Request{Command: "bogus"}); resp.OK {
		t.Errorf("unknown command should not be ok: %+v", resp)
	}
}

// errPolicy returns an error from every blocked-side operation.
type errPolicy struct{}

func (p *errPolicy) BlockIP(string) error              { return errors.New("boom") }
func (p *errPolicy) UnblockIP(string) error            { return errors.New("boom") }
func (p *errPolicy) ListBlockedIPs() ([]string, error) { return nil, errors.New("boom") }
func (p *errPolicy) Clear() error                      { return errors.New("boom") }
func (p *errPolicy) Interface() string                 { return "" }

func TestHandle_PropagatesErrors(t *testing.T) {
	s := New("unused.sock", &errPolicy{})

	for _, cmd := range []Command{CmdBlock, CmdUnblock, CmdList, CmdClear} {
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
