//go:build integration

package ebpf

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// XDP verdicts (linux/bpf.h).
const (
	testXDPDrop = 1
	testXDPPass = 2
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
	h := make([]byte, 20)
	h[0] = byte(sport >> 8)
	h[1] = byte(sport)
	h[2] = byte(dport >> 8)
	h[3] = byte(dport)
	h[12] = 0x50 // data offset 5
	// flags: SYN
	h[13] = 0x02
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
	var l4 []byte
	switch proto {
	case 6: // TCP
		l4 = tcpHeader(sport, dport)
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
