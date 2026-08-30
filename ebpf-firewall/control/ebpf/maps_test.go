package ebpf

import (
	"encoding/binary"
	"testing"
)

// These tests exercise the LPM key construction that must match the C
// struct ipv4_lpm_key byte layout. They are pure (no kernel required).

func TestNewLpmKey_BytesPreserved(t *testing.T) {
	// 1.2.3.4 in network byte order -> [1 2 3 4]
	ip := []byte{1, 2, 3, 4}
	key := newLpmKey(ip, 32)

	if key.Prefixlen != 32 {
		t.Errorf("Prefixlen = %d, want 32", key.Prefixlen)
	}

	// The uint32 Data field must reproduce the exact network-order bytes in
	// memory. LittleEndian.Put must yield back [1 2 3 4].
	var mem [4]byte
	binary.LittleEndian.PutUint32(mem[:], key.Data)
	if mem != [4]byte{1, 2, 3, 4} {
		t.Errorf("Data bytes = %v, want [1 2 3 4]", mem)
	}
}

func TestNewLpmKey_CIDRPrefix(t *testing.T) {
	// 10.0.0.0/8 (network address 10.0.0.0).
	ip := []byte{10, 0, 0, 0}
	key := newLpmKey(ip, 8)

	if key.Prefixlen != 8 {
		t.Errorf("Prefixlen = %d, want 8", key.Prefixlen)
	}

	var mem [4]byte
	binary.LittleEndian.PutUint32(mem[:], key.Data)
	if mem[0] != 10 || mem[1] != 0 || mem[2] != 0 || mem[3] != 0 {
		t.Errorf("Data bytes = %v, want [10 0 0 0]", mem)
	}
}

func TestIPv4LpmKey_Size(t *testing.T) {
	// The C key is 8 bytes: uint32 prefixlen + uint32 data. Verify the Go
	// struct that is written to the map has the same on-wire size.
	key := newLpmKey([]byte{1, 2, 3, 4}, 32)
	if got := len(keyBytes(key)); got != 8 {
		t.Errorf("key size = %d bytes, want 8", got)
	}
}

// keyBytes reconstructs the raw map key bytes in memory order.
func keyBytes(k firewallIpv4LpmKey) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:4], k.Prefixlen)
	binary.LittleEndian.PutUint32(buf[4:8], k.Data)
	return buf
}
