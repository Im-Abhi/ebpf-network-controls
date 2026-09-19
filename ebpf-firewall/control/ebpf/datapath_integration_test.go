//go:build integration

package ebpf

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// XDP verdicts (linux/bpf.h).
const (
	testXDPDrop = 1
	testXDPPass = 2
)

// TCP flag bits, matching the datapath masks in bpf/firewall.c.
const (
	tcpFlagFIN byte = 0x01
	tcpFlagSYN byte = 0x02
	tcpFlagRST byte = 0x04
	tcpFlagACK byte = 0x10
)

// These tests exercise the real datapath (bpf/firewall.c) by injecting packets
// through BPF_PROG_TEST_RUN (cilium/ebpf Program.Run), asserting the returned
// XDP verdict, and checking the global counters. They require:
//   - Linux with eBPF support
//   - generated firewall_bpf.o / firewall_bpf.go (`make generate`)
//   - root (or CAP_BPF + CAP_NET_ADMIN): `sudo go test -tags integration ./control/ebpf/`
//
// The program is loaded but NOT attached to an interface; the `lo` name is
// only required because LoadXDP validates the interface exists.

func loadTestFirewall(t *testing.T) *Firewall {
	t.Helper()
	fw, err := NewFirewall("lo")
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	t.Cleanup(func() {
		if err := fw.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return fw
}

// runPacket feeds a raw Ethernet frame through the datapath and returns the
// XDP verdict.
func runPacket(t *testing.T, fw *Firewall, pkt []byte) int {
	t.Helper()
	ret, err := fw.prog.prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog.Run: %v", err)
	}
	return int(ret)
}

func mustVerdict(t *testing.T, fw *Firewall, pkt []byte, want int) {
	t.Helper()
	got := runPacket(t, fw, pkt)
	if got != want {
		t.Fatalf("verdict = %d, want %d (data %x)", got, want, pkt)
	}
}

// --- packet builders ---------------------------------------------------

func ethHeaderEthertype(etherType uint16) []byte {
	h := make([]byte, 14)
	h[12] = byte(etherType >> 8)
	h[13] = byte(etherType)
	return h
}

func ipv4Header(src, dst net.IP, proto uint8, l4len int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // IPv4, IHL=5
	// total length
	h[2] = byte((20 + l4len) >> 8)
	h[3] = byte(20 + l4len)
	h[8] = 64           // ttl
	h[9] = proto        // protocol
	copy(h[12:16], src) // src addr
	copy(h[16:20], dst) // dst addr
	return h
}

func tcpHeader(sport, dport uint16) []byte {
	// Default to a SYN, the historical handshake opener.
	return tcpHeaderFlags(sport, dport, tcpFlagSYN)
}

func tcpHeaderFlags(sport, dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	h[0] = byte(sport >> 8)
	h[1] = byte(sport)
	h[2] = byte(dport >> 8)
	h[3] = byte(dport)
	h[12] = 0x50 // data offset 5
	h[13] = flags
	return h
}

func udpHeader(sport, dport uint16) []byte {
	h := make([]byte, 8)
	h[0] = byte(sport >> 8)
	h[1] = byte(sport)
	h[2] = byte(dport >> 8)
	h[3] = byte(dport)
	h[4] = 0
	h[5] = 8 // UDP length = 8
	return h
}

func v4Packet(src, dst net.IP, proto uint8, sport, dport uint16) []byte {
	return v4PacketFlags(src, dst, proto, sport, dport, tcpFlagSYN)
}

func v4PacketFlags(src, dst net.IP, proto uint8, sport, dport uint16, flags byte) []byte {
	var l4 []byte
	switch proto {
	case 6: // TCP
		l4 = tcpHeaderFlags(sport, dport, flags)
	case 17: // UDP
		l4 = udpHeader(sport, dport)
	}
	eth := ethHeaderEthertype(0x0800)
	ip := ipv4Header(src, dst, proto, len(l4))
	pkt := append(eth, ip...)
	return append(pkt, l4...)
}

func ip(s string) net.IP {
	return net.ParseIP(s).To4()
}

func tcpPkt(src, dst string, sport, dport uint16) []byte {
	return v4Packet(ip(src), ip(dst), 6, sport, dport)
}

func tcpPktFlags(src, dst string, sport, dport uint16, flags byte) []byte {
	return v4PacketFlags(ip(src), ip(dst), 6, sport, dport, flags)
}

// ctStates parses the manager's listing into a map of "sport:dport" -> state
// for unambiguous assertions on the standard 5-tuples used in these tests.
func ctStates(t *testing.T, fw *Firewall) map[string]string {
	t.Helper()
	entries, err := fw.ListConntrack()
	if err != nil {
		t.Fatalf("ListConntrack: %v", err)
	}
	byFlow := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.Protocol != "tcp" {
			t.Fatalf("conntrack entry with protocol %q, want tcp only: %+v", e.Protocol, e)
		}
		byFlow[fmt.Sprintf("%d:%d", e.Sport, e.Dport)] = e.State
	}
	return byFlow
}

func udpPkt(src, dst string, sport, dport uint16) []byte {
	return v4Packet(ip(src), ip(dst), 17, sport, dport)
}

// --- datapath scenarios ------------------------------------------------

func TestDatapath_DefaultAllow_Passes(t *testing.T) {
	fw := loadTestFirewall(t)

	// No rules, default allow: anything parsed passes.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
	mustVerdict(t, fw, udpPkt("10.0.0.1", "8.8.8.8", 1000, 53), testXDPPass)
}

func TestDatapath_DefaultDeny_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	// No matching rules, default deny: drops.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
	mustVerdict(t, fw, udpPkt("10.0.0.1", "8.8.8.8", 1000, 53), testXDPDrop)
}

func TestDatapath_BlockedIP_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	// Destination matches the block.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPDrop)
	// Source matches the block.
	mustVerdict(t, fw, tcpPkt("1.2.3.4", "9.9.9.9", 12345, 80), testXDPDrop)
	// Unrelated IP passes.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "5.6.7.8", 12345, 80), testXDPPass)
}

func TestDatapath_CIDR_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockIP("10.0.0.0/8"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	mustVerdict(t, fw, tcpPkt("11.0.0.1", "10.1.2.3", 1000, 80), testXDPDrop)
	mustVerdict(t, fw, tcpPkt("10.2.3.4", "9.9.9.9", 1000, 80), testXDPDrop)
	mustVerdict(t, fw, tcpPkt("11.0.0.1", "172.16.0.1", 1000, 80), testXDPPass)
}

func TestDatapath_PortRule_DropsOnlyMatching(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockPortRule("1.2.3.4", "tcp", 22, 0); err != nil {
		t.Fatalf("BlockPortRule: %v", err)
	}

	// Matching dst/proto/port drops.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
	// Same dst, different port: passes.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPPass)
	// Same port, UDP: passes.
	mustVerdict(t, fw, udpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
}

func TestDatapath_PortRule_SourcePort(t *testing.T) {
	fw := loadTestFirewall(t)

	// Block only when the source port is 50000.
	if err := fw.BlockPortRule("1.2.3.4", "tcp", 22, 50000); err != nil {
		t.Fatalf("BlockPortRule: %v", err)
	}

	// Exact (proto, dport, sport) matches -> drop.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 50000, 22), testXDPDrop)
	// Same dport but different source port -> no candidate matches -> pass.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
	// Same sport but different dport -> pass.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 50000, 80), testXDPPass)
	// UDP on same dport/sport -> protocol differs -> pass.
	mustVerdict(t, fw, udpPkt("192.168.0.1", "1.2.3.4", 50000, 22), testXDPPass)
}

func TestDatapath_PortRule_Specifity(t *testing.T) {
	fw := loadTestFirewall(t)

	// Most-specific rule drops exactly src-port 50000 -> dst:22.
	if err := fw.BlockPortRule("1.2.3.4", "tcp", 22, 50000); err != nil {
		t.Fatalf("BlockPortRule: %v", err)
	}
	// Less-specific rule PASSes any other tcp traffic to dst:22.
	if err := fw.BlockPortRuleWithAction("1.2.3.4", "tcp", 22, 0, "pass"); err != nil {
		t.Fatalf("BlockPortRuleWithAction: %v", err)
	}

	// Exact match wins (DROP) even though the wildcard PASS rule exists.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 50000, 22), testXDPDrop)
	// Other source ports fall through to the PASS rule.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
}

func TestDatapath_PassRule_OverridesDefaultDeny(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	if err := fw.BlockIPWithAction("1.2.3.4", "pass"); err != nil {
		t.Fatalf("BlockIPWithAction: %v", err)
	}

	// Explicit PASS rule allows even under default-deny.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPPass)
	// Other traffic still denied.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "5.6.7.8", 12345, 80), testXDPDrop)
}

func TestDatapath_DropWinsOverPass(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	// PASS rule for the IP, but a DROP port rule for the same dst:22.
	if err := fw.BlockIPWithAction("1.2.3.4", "pass"); err != nil {
		t.Fatalf("BlockIPWithAction: %v", err)
	}
	if err := fw.BlockPortRule("1.2.3.4", "tcp", 22, 0); err != nil {
		t.Fatalf("BlockPortRule: %v", err)
	}

	// DROP wins over the PASS rule.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
	// Non-port traffic still allowed by the PASS rule.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPPass)
}

func TestDatapath_Priority_HigherPassOverridesBroadDrop(t *testing.T) {
	fw := loadTestFirewall(t)

	// Broad DROP for the whole IP at a low priority, plus a high-priority PASS
	// exception for tcp/22. This is the canonical use case: punch a hole in a
	// block without widening it.
	if err := fw.BlockIPWithActionPriority("1.2.3.4", "drop", 10); err != nil {
		t.Fatalf("BlockIPWithActionPriority: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "pass", 20); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	// Both rules match tcp/22; the higher-priority PASS wins.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
	// Other traffic only matches the IP DROP.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPDrop)
}

func TestDatapath_Priority_HigherDropBeatsLowerPass(t *testing.T) {
	fw := loadTestFirewall(t)

	// Inverse: high-priority IP DROP beats a lower-priority port PASS.
	if err := fw.BlockIPWithActionPriority("1.2.3.4", "drop", 20); err != nil {
		t.Fatalf("BlockIPWithActionPriority: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "pass", 5); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
}

func TestDatapath_Priority_TieResolvesToDrop(t *testing.T) {
	fw := loadTestFirewall(t)

	// Equal priority, one PASS and one DROP: DROP wins regardless of which
	// table it came from.
	if err := fw.BlockIPWithActionPriority("1.2.3.4", "pass", 5); err != nil {
		t.Fatalf("BlockIPWithActionPriority: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "drop", 5); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
	// Traffic that only matches the PASS rule still passes.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPPass)
}

func TestDatapath_Priority_OverridesPortSpecificity(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	// A more specific rule at a lower priority must lose to a broader rule at
	// a higher priority: exact (dst:22, sport:50000) DROP prio 1 versus
	// wildcard dst:22 PASS prio 10.
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 50000, "drop", 1); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "pass", 10); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	// The exact packet matches both; priority, not specificity, decides.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 50000, 22), testXDPPass)
	// Other source ports match only the wildcard PASS.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPPass)
	// Unrelated port still hits default deny.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPDrop)
}

func TestDatapath_PortRule_EqualPriorityKeepsSpecificity(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	// At the default priority 0 the historical most-specific-first order is
	// unchanged: an exact PASS rule wins over a broader DROP rule for the
	// traffic it matches (regression guard for pre-priority rulesets).
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 50000, "pass", 0); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority(pass): %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "drop", 0); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority(drop): %v", err)
	}

	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 50000, 22), testXDPPass)
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 22), testXDPDrop)
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPDrop)
}

func TestDatapath_NonIPv4_UsesDefault(t *testing.T) {
	fw := loadTestFirewall(t)

	// ARP frame (ethertype 0x0806): not IPv4, should follow default (allow).
	arp := ethHeaderEthertype(0x0806)
	arp = append(arp, make([]byte, 28)...)
	mustVerdict(t, fw, arp, testXDPPass)

	// Same under default-deny.
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	mustVerdict(t, fw, arp, testXDPDrop)
}

func TestDatapath_Malformed_UsesDefault(t *testing.T) {
	fw := loadTestFirewall(t)

	// 14-byte Ethernet header with IPv4 ethertype but no IP payload:
	// parse_iphdr fails its bounds check, so the default policy applies.
	ethOnly := ethHeaderEthertype(0x0800)
	mustVerdict(t, fw, ethOnly, testXDPPass)

	// Ethernet plus a truncated IPv4 header (only 5 bytes after ethertype).
	trunc := ethHeaderEthertype(0x0800)
	trunc = append(trunc, 0x45, 0x00, 0x00, 0x14, 0x00) // partial IPv4
	mustVerdict(t, fw, trunc, testXDPPass)

	// Under default deny both drop.
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	mustVerdict(t, fw, ethOnly, testXDPDrop)
	mustVerdict(t, fw, trunc, testXDPDrop)
}

func TestDatapath_Conntrack_SpoofedAckCreatesNoState(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	// SYN is denied by default-deny, so no state is written...
	mustVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testXDPDrop)
	// ...and a spoofed ACK (no prior SYN) must not fabricate an established
	// flow: it is still denied and still leaves no state behind.
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPDrop)

	if states := ctStates(t, fw); len(states) != 0 {
		t.Errorf("conntrack = %v, want empty after dropped SYN + spoofed ACK", states)
	}
}

func TestDatapath_Conntrack_EstablishedFlowPassesAfterRuleRemoved(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	// A narrow PASS rule lets the handshake in; afterwards it is removed to
	// prove the ESTABLISHED state itself (not the rule) carries the flow.
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 50000, "pass", 5); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	// SYN -> NEW, ACK on NEW -> ESTABLISHED.
	mustVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testXDPPass)
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPPass)
	if s := ctStates(t, fw)["50000:22"]; s != "established" {
		t.Fatalf("flow state = %q, want established", s)
	}

	if err := fw.UnblockPortRule("1.2.3.4", "tcp", 22, 50000); err != nil {
		t.Fatalf("UnblockPortRule: %v", err)
	}

	// With the rule gone, the established flow still passes under default-deny.
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPPass)
	// A different flow has no state and no rule: denied.
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 60000, 22, tcpFlagACK), testXDPDrop)
}

func TestDatapath_Conntrack_FinClosesFlow(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 50000, "pass", 5); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	mustVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testXDPPass)
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPPass)
	if err := fw.UnblockPortRule("1.2.3.4", "tcp", 22, 50000); err != nil {
		t.Fatalf("UnblockPortRule: %v", err)
	}

	// FIN closes the flow (still passes, then flips to CLOSED).
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagFIN|tcpFlagACK), testXDPPass)
	if s := ctStates(t, fw)["50000:22"]; s != "closed" {
		t.Fatalf("flow state = %q, want closed", s)
	}

	// After close, a stray packet no longer has the established fast-path.
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPDrop)
}

func TestDatapath_Conntrack_MidStreamRuleAcceptMarksEstablished(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	if err := fw.BlockPortRuleWithActionPriority("1.2.3.4", "tcp", 22, 0, "pass", 5); err != nil {
		t.Fatalf("BlockPortRuleWithActionPriority: %v", err)
	}

	// A mid-stream ACK (no SYN seen) accepted by a rule records the flow as
	// already established, so removal of the rule still lets it through.
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 12345, 22, tcpFlagACK), testXDPPass)
	if s := ctStates(t, fw)["12345:22"]; s != "established" {
		t.Fatalf("flow state = %q, want established", s)
	}
}

func TestDatapath_Conntrack_NotTrackedUnderDefaultAllow(t *testing.T) {
	fw := loadTestFirewall(t)

	// Under default-allow the stateful table is never consulted or written:
	// it could not change any verdict, only add cost.
	mustVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testXDPPass)
	mustVerdict(t, fw, tcpPktFlags("10.0.0.1", "1.2.3.4", 50000, 22, tcpFlagACK), testXDPPass)
	if states := ctStates(t, fw); len(states) != 0 {
		t.Errorf("conntrack = %v, want empty under default-allow", states)
	}
}

func TestDatapath_Conntrack_TcpOnlyUnderDefaultDeny(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}

	// Denied UDP traffic is not tracked (TCP-only table).
	mustVerdict(t, fw, udpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testXDPDrop)
	if states := ctStates(t, fw); len(states) != 0 {
		t.Errorf("conntrack = %v, want empty (TCP-only)", states)
	}
}

func TestDatapath_CountersTrackDropsAndPasses(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	dropPkt := tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80)
	passPkt := tcpPkt("192.168.0.1", "5.6.7.8", 12345, 80)

	mustVerdict(t, fw, dropPkt, testXDPDrop)
	mustVerdict(t, fw, passPkt, testXDPPass)

	stats, err := fw.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	// BPF_PROG_TEST_RUN may execute the program more than once per call under
	// certain interruptions, so counters must be at least the expected deltas.
	if stats.DropPackets < 1 {
		t.Errorf("DropPackets = %d, want >= 1", stats.DropPackets)
	}
	if stats.PassPackets < 1 {
		t.Errorf("PassPackets = %d, want >= 1", stats.PassPackets)
	}
	if stats.TotalPackets < 2 {
		t.Errorf("TotalPackets = %d, want >= 2", stats.TotalPackets)
	}
}
