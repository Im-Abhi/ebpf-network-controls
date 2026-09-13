package main

import (
	"reflect"
	"testing"
)

func TestExtractOptions_FlagsAfterCommand(t *testing.T) {
	args, sock, proto, action, port, sport, err := extractOptions(
		[]string{"block", "10.153.245.175", "--protocol", "tcp", "--dport", "22", "--sport", "50000", "--action", "pass"},
	)
	if err != nil {
		t.Fatalf("extractOptions: %v", err)
	}
	if !reflect.DeepEqual(args, []string{"block", "10.153.245.175"}) {
		t.Errorf("args = %v, want [block 10.153.245.175]", args)
	}
	if sock != "/var/run/ebpf-firewall.sock" {
		t.Errorf("sock = %q, want default", sock)
	}
	if proto != "tcp" || port != 22 || sport != 50000 {
		t.Errorf("proto=%q port=%d sport=%d, want tcp 22 50000", proto, port, sport)
	}
	if action != "pass" {
		t.Errorf("action = %q, want pass", action)
	}
}

func TestExtractOptions_FlagsBeforeCommand(t *testing.T) {
	args, _, proto, action, port, sport, err := extractOptions(
		[]string{"-protocol", "udp", "-dport", "53", "-sport", "1234", "block", "1.2.3.4"},
	)
	if err != nil {
		t.Fatalf("extractOptions: %v", err)
	}
	if !reflect.DeepEqual(args, []string{"block", "1.2.3.4"}) {
		t.Errorf("args = %v", args)
	}
	if proto != "udp" || port != 53 || sport != 1234 {
		t.Errorf("proto=%q port=%d sport=%d, want udp 53 1234", proto, port, sport)
	}
	if action != "" {
		t.Errorf("action = %q, want empty", action)
	}
}

func TestExtractOptions_EqualsForms(t *testing.T) {
	args, sock, proto, action, port, sport, err := extractOptions(
		[]string{"block", "1.2.3.4", "--protocol=tcp", "--dport=8080", "--sport=40000", "--action=drop", "-sock=/tmp/fw.sock"},
	)
	if err != nil {
		t.Fatalf("extractOptions: %v", err)
	}
	if !reflect.DeepEqual(args, []string{"block", "1.2.3.4"}) {
		t.Errorf("args = %v", args)
	}
	if sock != "/tmp/fw.sock" {
		t.Errorf("sock = %q, want /tmp/fw.sock", sock)
	}
	if proto != "tcp" || port != 8080 || sport != 40000 {
		t.Errorf("proto=%q port=%d sport=%d, want tcp 8080 40000", proto, port, sport)
	}
	if action != "drop" {
		t.Errorf("action = %q, want drop", action)
	}
}

func TestExtractOptions_PlainCommand(t *testing.T) {
	args, _, proto, action, port, sport, err := extractOptions([]string{"listports"})
	if err != nil {
		t.Fatalf("extractOptions: %v", err)
	}
	if !reflect.DeepEqual(args, []string{"listports"}) {
		t.Errorf("args = %v", args)
	}
	if proto != "" || port != 0 || sport != 0 || action != "" {
		t.Errorf("proto=%q port=%d sport=%d action=%q, want empty/0", proto, port, sport, action)
	}
}

func TestExtractOptions_Errors(t *testing.T) {
	tests := [][]string{
		{"block", "1.2.3.4", "--protocol"},       // missing value
		{"block", "1.2.3.4", "--dport"},          // missing value
		{"block", "1.2.3.4", "--sport"},          // missing value
		{"block", "1.2.3.4", "--dport", "70000"}, // > 65535
		{"block", "1.2.3.4", "--dport", "oops"},  // not a number
		{"block", "1.2.3.4", "--sport", "70000"}, // > 65535
		{"block", "1.2.3.4", "--action"},         // missing value
		{"block", "1.2.3.4", "--bogus"},          // unknown option
	}
	for _, raw := range tests {
		if _, _, _, _, _, _, err := extractOptions(raw); err == nil {
			t.Errorf("extractOptions(%v): expected error, got nil", raw)
		}
	}
}

func TestParsePort(t *testing.T) {
	for _, flag := range []string{"-dport", "-sport"} {
		if p, err := parsePort("0", flag); err != nil || p != 0 {
			t.Errorf("parsePort(0, %s) = %d, %v", flag, p, err)
		}
		if p, err := parsePort("65535", flag); err != nil || p != 65535 {
			t.Errorf("parsePort(65535, %s) = %d, %v", flag, p, err)
		}
		for _, bad := range []string{"", "-1", "65536", "abc"} {
			if _, err := parsePort(bad, flag); err == nil {
				t.Errorf("parsePort(%q, %s): expected error, got nil", bad, flag)
			}
		}
	}
}
