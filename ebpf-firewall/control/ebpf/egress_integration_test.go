//go:build integration

package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TC verdicts (linux/pkt_cls.h). firewall_tc_egress returns TC_ACT_OK (pass)
// or TC_ACT_SHOT (drop); the XDP program is exercised separately through
// mustVerdict/runPacket with the XDP verdicts.
const (
	testTC_OK   = 0
	testTC_SHOT = 2
)

// These tests exercise the TC egress datapath (bpf/firewall.c
// firewall_tc_egress) by injecting packets through BPF_PROG_TEST_RUN on the
// classifier itself, asserting the returned TC verdict, and cross-checking the
// XDP ingress path where the two hooks share state (conntrack). Requirements
// match datapath_integration_test.go: Linux with eBPF, generated bindings
// (`make generate`), root (sudo go test -tags integration ./control/ebpf/).
//
// Egress semantics per bpf/maps.h: the source of an outgoing packet is always
// the local host, so egress rules key on the REMOTE DESTINATION only (dst for
// IP/CIDR rules, dst+ports for port rules). The hooks share the conntrack
// table: egress writes reverse-orientation (reply-side) entries as
// ESTABLISHED so the unchanged XDP exact-tuple probe passes inbound replies.

func runEgressPacket(t *testing.T, fw *Firewall, pkt []byte) int {
	t.Helper()
	ret, err := fw.tc.prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("tc egress prog.Run: %v", err)
	}
	return int(ret)
}

func mustEgressVerdict(t *testing.T, fw *Firewall, pkt []byte, want int) {
	t.Helper()
	got := runEgressPacket(t, fw, pkt)
	if got != want {
		t.Fatalf("egress verdict = %d, want %d (data %x)", got, want, pkt)
	}
}

func TestEgressDatapath_DefaultAllow_Passes(t *testing.T) {
	fw := loadTestFirewall(t)

	// No egress rules, egress default allow (maps.h absence fallback): any
	// outbound packet passes.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 22), testTC_OK)
	mustEgressVerdict(t, fw, udpPkt("10.0.0.1", "8.8.8.8", 1000, 53), testTC_OK)
}

func TestEgressDatapath_DefaultDeny_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetEgressDefault("deny"); err != nil {
		t.Fatalf("SetEgressDefault: %v", err)
	}

	// No matching egress rules, egress default deny: drops.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 22), testTC_SHOT)
	mustEgressVerdict(t, fw, udpPkt("10.0.0.1", "8.8.8.8", 1000, 53), testTC_SHOT)
}

func TestEgressDatapath_BlockedDestination_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockEgressWithAction("1.2.3.4", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}

	// The remote destination matches the egress block: drop.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 80), testTC_SHOT)
	// A different destination is unaffected.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "5.6.7.8", 12345, 80), testTC_OK)

	// Egress rules are dst-only: an outbound packet whose SOURCE lies in the
	// blocked range must still pass, because matching the local source would
	// self-poison all egress traffic.
	mustEgressVerdict(t, fw, tcpPkt("1.2.3.4", "5.6.7.8", 12345, 80), testTC_OK)
}

func TestEgressDatapath_CIDR_DropsByDestination(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockEgressWithAction("10.0.0.0/8", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}

	// Outbound to a destination inside the CIDR: drop.
	mustEgressVerdict(t, fw, tcpPkt("11.0.0.1", "10.1.2.3", 1000, 80), testTC_SHOT)
	// Outbound FROM an address inside the CIDR to elsewhere: pass (dst-only).
	mustEgressVerdict(t, fw, tcpPkt("10.2.3.4", "9.9.9.9", 1000, 80), testTC_OK)
	// Unrelated destination: pass.
	mustEgressVerdict(t, fw, tcpPkt("11.0.0.1", "172.16.0.1", 1000, 80), testTC_OK)
}

func TestEgressDatapath_PortRule_DropsOnlyMatching(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockEgressPortRule("1.2.3.4", "tcp", 443, 0); err != nil {
		t.Fatalf("BlockEgressPortRule: %v", err)
	}

	// Outbound to the blocked dst:443: drop.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 443), testTC_SHOT)
	// Same dst, different port: pass.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 80), testTC_OK)
	// Same port but UDP: pass.
	mustEgressVerdict(t, fw, udpPkt("10.0.0.1", "1.2.3.4", 12345, 443), testTC_OK)
}

func TestEgressDatapath_HooksAreSeparate(t *testing.T) {
	fw := loadTestFirewall(t)

	// An ingress (XDP) IP rule must not influence the egress verdict and vice
	// versa: the hooks read disjoint policy maps.
	if err := fw.BlockIP("1.2.3.4"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}
	// Egress still passes outbound packets to 1.2.3.4.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 80), testTC_OK)
	// XDP still drops inbound packets to 1.2.3.4.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "1.2.3.4", 12345, 80), testXDPDrop)

	if err := fw.BlockEgressWithAction("5.6.7.8", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}
	// Egress drops its own block...
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "5.6.7.8", 12345, 80), testTC_SHOT)
	// ...while XDP still passes inbound traffic to that destination.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "5.6.7.8", 12345, 80), testXDPPass)
}

// arpPkt builds a minimal Ethernet/ARP frame: an Ethernet II header with the
// ARP ethertype followed by a 28-byte ARP payload. The datapath rejects it as
// non-IPv4, so firewall_tc_egress must apply only the egress default policy.
func arpPkt() []byte {
	pkt := make([]byte, 14+28)
	pkt[12] = 0x08 // h_proto = ETH_P_ARP (0x0806)
	pkt[13] = 0x06
	return pkt
}

func TestEgressDatapath_NonIPv4FollowsDefaultPolicy(t *testing.T) {
	fw := loadTestFirewall(t)

	// Prime the egress IP presence bit AND make the zeroed key used when
	// parsing fails (0.0.0.0/32) resolve to an actual DROP rule. Before the
	// non-IPv4 early return in firewall_tc_egress this exact setup dropped
	// ARP/IPv6 frames even under an egress default of allow; the regression
	// is that parse failures now take only the egress default policy, never
	// the rule tables.
	if err := fw.BlockEgressWithAction("0.0.0.0/0", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}

	// Guard: the egress IP presence bit must be active, otherwise the LPM
	// lookups (and the divergence this test exercises) would never run and
	// the assertions below could pass vacuously.
	var flags uint32
	if err := fw.prog.RulePresence().Lookup(presenceMapKey, &flags); err != nil {
		t.Fatalf("reading rule_presence: %v", err)
	}
	if flags&rulePresenceEgressIP == 0 {
		t.Fatalf("egress IP presence bit not set; the 0.0.0.0/0 rule would never be consulted")
	}

	// First prove the trap: an IPv4 packet to a destination inside 0.0.0.0/0
	// IS dropped by the rule.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "5.6.7.8", 12345, 80), testTC_SHOT)

	// Non-IPv4 frames ignore the rule and follow the egress default instead.
	if err := fw.SetEgressDefault("allow"); err != nil {
		t.Fatalf("SetEgressDefault: %v", err)
	}
	mustEgressVerdict(t, fw, arpPkt(), testTC_OK)

	if err := fw.SetEgressDefault("deny"); err != nil {
		t.Fatalf("SetEgressDefault: %v", err)
	}
	mustEgressVerdict(t, fw, arpPkt(), testTC_SHOT)
}

func TestEgressDatapath_Conntrack_ReverseEntryPassesInboundReplies(t *testing.T) {
	fw := loadTestFirewall(t)
	// Both hooks under default-deny make the conntrack gate active on egress
	// (TCP && (egress deny || ingress deny)).
	if err := fw.SetDefaultPolicy("deny"); err != nil {
		t.Fatalf("SetDefaultPolicy: %v", err)
	}
	if err := fw.SetEgressDefault("deny"); err != nil {
		t.Fatalf("SetEgressDefault: %v", err)
	}
	// The outbound flow is explicitly PASSed so egress accepts it and writes
	// the reverse (reply) orientation entry.
	if err := fw.BlockEgressWithAction("1.2.3.4", "pass"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}

	// Outbound SYN (local host 10.0.0.1:50000 -> 1.2.3.4:22): accepted by the
	// PASS rule; the egress datapath records the reply 5-tuple as ESTABLISHED.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 50000, 22), testTC_OK)

	// The inbound reply (1.2.3.4:22 -> 10.0.0.1:50000) hits the unchanged XDP
	// exact-tuple probe: with the reverse entry present it must pass under
	// ingress default-deny despite there being no ingress rule for it.
	mustVerdict(t, fw, tcpPktFlags("1.2.3.4", "10.0.0.1", 22, 50000, tcpFlagACK), testXDPPass)

	// A distinct inbound flow has neither ingress rule nor reverse entry:
	// denied.
	mustVerdict(t, fw, tcpPktFlags("1.2.3.4", "10.0.0.1", 22, 60000, tcpFlagACK), testXDPDrop)
}

func TestEgressDatapath_ClearEgress_LeavesIngress(t *testing.T) {
	fw := loadTestFirewall(t)

	if err := fw.BlockEgressWithAction("1.2.3.4", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}
	if err := fw.BlockIP("9.9.9.9"); err != nil {
		t.Fatalf("BlockIP: %v", err)
	}

	if err := fw.ClearEgress(); err != nil {
		t.Fatalf("ClearEgress: %v", err)
	}

	// Egress rules gone: pass again.
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 80), testTC_OK)
	// Ingress rule untouched: still dropped on the XDP path.
	mustVerdict(t, fw, tcpPkt("192.168.0.1", "9.9.9.9", 12345, 80), testXDPDrop)
}

func TestEgressDatapath_CountersSeparate(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockEgressWithAction("1.2.3.4", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}

	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "1.2.3.4", 12345, 80), testTC_SHOT)
	mustEgressVerdict(t, fw, tcpPkt("10.0.0.1", "5.6.7.8", 12345, 80), testTC_OK)

	eg, err := fw.EgressStats()
	if err != nil {
		t.Fatalf("EgressStats: %v", err)
	}
	if eg.DropPackets < 1 {
		t.Errorf("egress DropPackets = %d, want >= 1", eg.DropPackets)
	}
	if eg.PassPackets < 1 {
		t.Errorf("egress PassPackets = %d, want >= 1", eg.PassPackets)
	}

	// The ingress counters are separate and must remain at zero.
	st, err := fw.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.TotalPackets != 0 {
		t.Errorf("ingress TotalPackets = %d, want 0 (separate egress counters)", st.TotalPackets)
	}
}