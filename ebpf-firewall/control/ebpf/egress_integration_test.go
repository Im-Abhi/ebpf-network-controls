//go:build integration

package ebpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// cgroup/skb verdicts: firewall_cgroup_egress returns 1 (pass) or 0 (drop);
// the XDP program is exercised separately through mustVerdict/runPacket with
// the XDP verdicts.
const (
	testTC_OK   = 1
	testTC_SHOT = 0
)

// These tests exercise the egress datapath (bpf/firewall.c
// firewall_cgroup_egress) by injecting packets through BPF_PROG_TEST_RUN on the
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
	// The packet builders produce L2 frames; the kernel's TEST_RUN harness
	// for cgroup/skb programs runs eth_type_trans on the injected data, so
	// the program's skb->data ends up at the L3 header — exactly like the
	// live cgroup egress hook. Inject the frame as built.
	ret, err := fw.egress.prog.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("egress prog.Run: %v", err)
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
	if err := fw.BlockEgressPortRuleWithActionPriority("1.2.3.4", "tcp", 443, 0, "drop", 0); err != nil {
		t.Fatalf("BlockEgressPortRuleWithActionPriority: %v", err)
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
// non-IPv4, so firewall_cgroup_egress must apply only the egress default policy.
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
	// non-IPv4 early return in firewall_cgroup_egress this exact setup dropped
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

// TestEgressTables_ClearRemovesAll guards the Clear() contract for both
// egress table shapes. It inserts at least three rules per table so a delete-
// during-iteration hazard (which can silently skip entries on a real kernel)
// has enough state to trip on, and asserts both lists are empty afterwards.
func TestEgressTables_ClearRemovesAll(t *testing.T) {
	ips := newCidrTable(newTestLpmMap(t), nil, 0)
	ports := newPortTable(newTestPortPolicyMap(t), nil, 0)

	for _, cidr := range []string{"1.2.3.4", "10.0.0.0/8", "192.168.0.0/16"} {
		if err := ips.Add(cidr, ActionDrop, 0); err != nil {
			t.Fatalf("Add(%s): %v", cidr, err)
		}
	}

	if err := ports.Add("8.8.8.8", "tcp", 443, 0, ActionDrop, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := ports.Add("8.8.8.8", "udp", 53, 0, ActionDrop, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := ports.Add("1.1.1.1", "tcp", 22, 0, ActionPass, 100); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ipRules, err := ips.List()
	if err != nil {
		t.Fatalf("List before clear: %v", err)
	}
	if len(ipRules) != 3 {
		t.Fatalf("List before clear len = %d, want 3", len(ipRules))
	}
	portRules, err := ports.List()
	if err != nil {
		t.Fatalf("List before clear: %v", err)
	}
	if len(portRules) != 3 {
		t.Fatalf("List before clear len = %d, want 3", len(portRules))
	}

	if err := ips.Clear(); err != nil {
		t.Fatalf("Clear ips: %v", err)
	}
	if err := ports.Clear(); err != nil {
		t.Fatalf("Clear ports: %v", err)
	}

	ipRules, err = ips.List()
	if err != nil {
		t.Fatalf("List after clear: %v", err)
	}
	if len(ipRules) != 0 {
		t.Fatalf("List after clear len = %d, want 0; left over: %+v", len(ipRules), ipRules)
	}
	portRules, err = ports.List()
	if err != nil {
		t.Fatalf("List after clear: %v", err)
	}
	if len(portRules) != 0 {
		t.Fatalf("List after clear len = %d, want 0; left over: %+v", len(portRules), portRules)
	}
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

// ── IPv6 egress (cgroup/skb): the domain stage covers v6 TCP; the v4-only
// tables (IP/CIDR, ports) and conntrack do not apply to v6, whose policy
// surface is the domain stage plus the default policy. ─────────────────────

func ipv6Header(src, dst net.IP, proto uint8, l4len int) []byte {
	h := make([]byte, 40)
	h[0] = 0x60 // version 6, traffic class 0, flow label 0
	h[4] = byte(l4len >> 8)
	h[5] = byte(l4len)
	h[6] = proto // next header
	h[7] = 64    // hop limit
	copy(h[8:24], src.To16())
	copy(h[24:40], dst.To16())
	return h
}

func ip6(s string) net.IP {
	return net.ParseIP(s).To16()
}

func v6Packet(src, dst net.IP, proto uint8, sport, dport uint16) []byte {
	var l4 []byte
	switch proto {
	case 6:
		l4 = tcpHeaderFlags(sport, dport, tcpFlagACK) // data-shaped: the domain gate excludes SYN
	case 17:
		l4 = udpHeader(sport, dport)
	}
	eth := ethHeaderEthertype(0x86DD)
	hdr := ipv6Header(src, dst, proto, len(l4))
	pkt := append(eth, hdr...)
	return append(pkt, l4...)
}

func tcp6Pkt(src, dst string, sport, dport uint16) []byte {
	return v6Packet(ip6(src), ip6(dst), 6, sport, dport)
}

func udp6Pkt(src, dst string, sport, dport uint16) []byte {
	return v6Packet(ip6(src), ip6(dst), 17, sport, dport)
}

// tlsClientHello builds a minimal TLS ClientHello record whose SNI extension
// carries the given name — byte-for-byte the shape tls_sni_extract() walks.
func tlsClientHello(sni string) []byte {
	name := []byte(sni)
	// extLen counts the whole extension block: this builder emits a single
	// server_name extension, whose wire form is type(2) + len(2) + value,
	// where the value is list_len(2) + name_type(1) + name_len(2) + name.
	// Under-declaring it by the 4-byte header makes the handshake
	// internally inconsistent, and the datapath's SNI extractor (which
	// validates the declared lengths, failing open on mismatch) rejects
	// such a ClientHello instead of extracting the name.
	extLen := 4 + 5 + len(name)
	hsLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extLen // ver + random + sid + suites + comp + exts
	recLen := 4 + hsLen

	rec := []byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}
	hs := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	body := []byte{0x03, 0x03} // client version
	for i := 0; i < 32; i++ {  // random
		body = append(body, byte(i))
	}
	body = append(body, 0x00)                   // session id len = 0
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // one compression method
	body = append(body, byte(extLen>>8), byte(extLen))
	body = append(body, 0x00, 0x00)              // ext type: server_name
	body = append(body, 0x00, byte(5+len(name))) // ext length
	body = append(body, 0x00, byte(3+len(name))) // list length
	body = append(body, 0x00)                    // name_type: hostname
	body = append(body, 0x00, byte(len(name)))
	body = append(body, name...)
	return append(append(rec, hs...), body...)
}

func tcp6PktWithPayload(src, dst string, sport, dport uint16, payload []byte) []byte {
	eth := ethHeaderEthertype(0x86DD)
	hdr := ipv6Header(ip6(src), ip6(dst), 6, 20+len(payload))
	l4 := tcpHeaderFlags(sport, dport, tcpFlagACK)
	pkt := append(eth, hdr...)
	pkt = append(pkt, l4...)
	return append(pkt, payload...)
}

func TestEgressDatapath_V6_DefaultAllow_Passes(t *testing.T) {
	fw := loadTestFirewall(t)
	mustEgressVerdict(t, fw, tcp6Pkt("2001:db8::1", "2001:db8::2", 12345, 443), testTC_OK)
	mustEgressVerdict(t, fw, udp6Pkt("2001:db8::1", "2001:db8::2", 1000, 53), testTC_OK)
}

func TestEgressDatapath_V6_DefaultDeny_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.SetEgressDefault("deny"); err != nil {
		t.Fatalf("SetEgressDefault: %v", err)
	}
	mustEgressVerdict(t, fw, tcp6Pkt("2001:db8::1", "2001:db8::2", 12345, 22), testTC_SHOT)

	// v6 does not touch conntrack (the key is an IPv4 tuple).
	if entries, err := fw.ListConntrack(); err != nil || len(entries) != 0 {
		t.Errorf("v6 default-deny wrote conntrack state: %v entries (err %v)", entries, err)
	}
}

func TestEgressDatapath_V6_IPRule_DoesNotApply(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockEgressWithAction("1.2.3.4", "drop"); err != nil {
		t.Fatalf("BlockEgressWithAction: %v", err)
	}
	// The IP tables are IPv4-shaped: a v6 destination is unaffected (v1
	// scope — the v6 policy surface is the domain stage + default policy).
	mustEgressVerdict(t, fw, tcp6Pkt("2001:db8::1", "2001:db8::2", 12345, 80), testTC_OK)
}

func TestEgressDatapath_V6_DomainBlock_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockDomain("bad.example.com"); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}

	// Blocked SNI over v6: the ClientHello stream is dropped.
	mustEgressVerdict(t, fw, tcp6PktWithPayload("2001:db8::1", "2001:db8::2", 12345, 443,
		tlsClientHello("bad.example.com")), testTC_SHOT)
	// Subdomain covered by the reversed-LPM suffix semantics.
	mustEgressVerdict(t, fw, tcp6PktWithPayload("2001:db8::1", "2001:db8::2", 12345, 443,
		tlsClientHello("sub.bad.example.com")), testTC_SHOT)
	// A different name passes.
	mustEgressVerdict(t, fw, tcp6PktWithPayload("2001:db8::1", "2001:db8::2", 12345, 443,
		tlsClientHello("good.example.com")), testTC_OK)
	// Port 80 Host header over v6: blocked via the Host scan.
	hostReq := []byte("GET / HTTP/1.1\r\nHost: bad.example.com\r\n\r\n")
	mustEgressVerdict(t, fw, tcp6PktWithPayload("2001:db8::1", "2001:db8::2", 12345, 80, hostReq), testTC_SHOT)
}

func TestEgressDatapath_DomainBlock_V4_Drops(t *testing.T) {
	fw := loadTestFirewall(t)
	if err := fw.BlockDomain("bad.example.com"); err != nil {
		t.Fatalf("BlockDomain: %v", err)
	}
	// Same verdict on the v4 path, for symmetry.
	pkt := v4PacketFlags(ip("10.0.0.1"), ip("10.0.0.2"), 6, 12345, 443, tcpFlagACK)
	pkt = append(pkt, tlsClientHello("bad.example.com")...)
	mustEgressVerdict(t, fw, pkt, testTC_SHOT)
}
