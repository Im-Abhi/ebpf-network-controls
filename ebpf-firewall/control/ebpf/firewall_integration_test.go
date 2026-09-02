//go:build integration

package ebpf

import (
	"testing"
)

// These tests exercise the full Firewall facade (load + attach + dynamic policy
// updates) against a real kernel. They require:
//   - Linux with eBPF support
//   - the generated firewall_bpf.o (run `make generate` first)
//   - root (or CAP_BPF + CAP_NET_ADMIN): run with `sudo go test ./control/ebpf/`
//
// The dynamic-update assertions prove the core milestone: mutating the blocklist
// map must NOT reload or detach the attached XDP program.

// cleanup replaces the test's late cleanup when the Firewall is already stopped.
func stopFirewall(t *testing.T, f *Firewall) {
	t.Helper()
	if err := f.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestFirewall_LoadAttachDynamicPolicy(t *testing.T) {
	ifname := "lo" // native XDP may not be supported on lo, but generic is.
	fw, err := NewFirewall(ifname)
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	t.Cleanup(func() { stopFirewall(t, fw) })

	if err := fw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Dynamic rule change while attached: the program must not be reloaded.
	if err := fw.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	if err := fw.BlockIP("10.0.0.0/8"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	// Confirm the map actually updated behind the still-attached program.
	if ok, err := fw.IsBlocked("1.2.3.4"); err != nil || !ok {
		t.Errorf("IsBlocked(1.2.3.4) = %v, %v; want true", ok, err)
	}
	if ok, err := fw.IsBlocked("10.20.30.40"); err != nil || !ok {
		t.Errorf("IsBlocked(10.20.30.40) = %v, %v; want true (/8)", ok, err)
	}

	// Removing a rule must also leave the program attached.
	if err := fw.UnblockIP("1.2.3.4"); err != nil {
		t.Fatalf("UnblockIP: %v", err)
	}
	if ok, err := fw.IsBlocked("1.2.3.4"); err != nil || ok {
		t.Errorf("IsBlocked(1.2.3.4) after unblock = %v, %v; want false", ok, err)
	}
	// The /8 still covers 10.x.y.z.
	if ok, err := fw.IsBlocked("10.20.30.40"); err != nil || !ok {
		t.Errorf("IsBlocked(10.20.30.40) after unblocking /32 = %v, %v; want true (/8)", ok, err)
	}

	// Program must still be considered attached (link not closed by the updates).
	if fw.prog.link == nil {
		t.Error("program link is nil after dynamic updates; XDP was detached")
	}

	// List + clear roundtrip.
	list, err := fw.ListBlockedIPs()
	if err != nil {
		t.Fatalf("ListBlockedIPs: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListBlockedIPs len = %d, want 1 (got %v)", len(list), list)
	}
	if err := fw.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if ok, err := fw.IsBlocked("10.20.30.40"); err != nil || ok {
		t.Errorf("IsBlocked(10.20.30.40) after clear = %v, %v; want false", ok, err)
	}
}

func TestFirewall_StartIdempotent(t *testing.T) {
	fw, err := NewFirewall("lo")
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	t.Cleanup(func() { stopFirewall(t, fw) })

	if err := fw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Second Start must be a harmless no-op (already attached).
	if err := fw.Start(); err != nil {
		t.Fatalf("second Start: %v", err)
	}
}

func TestFirewall_StopDetaches(t *testing.T) {
	fw, err := NewFirewall("lo")
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}

	if err := fw.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if fw.prog.link == nil {
		t.Fatal("link nil after Start")
	}

	if err := fw.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if fw.prog.link != nil {
		t.Error("link still set after Stop; program not detached")
	}
}
