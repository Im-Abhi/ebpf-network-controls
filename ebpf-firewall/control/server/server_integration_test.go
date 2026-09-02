//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"ebpf-firewall/control/ebpf"
)

// request sends one JSON request over a unix socket and returns the response.
func request(t *testing.T, socketPath string, req Request) Response {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp Response
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestServer_EndToEnd(t *testing.T) {
	fw, err := ebpf.NewFirewall("lo")
	if err != nil {
		t.Fatalf("NewFirewall: %v", err)
	}
	if err := fw.Start(); err != nil {
		fw.Stop()
		t.Fatalf("fw.Start: %v", err)
	}
	defer fw.Stop()

	socketPath := filepath.Join(t.TempDir(), "fw.sock")
	srv := New(socketPath, fw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Close()

	if resp := request(t, socketPath, Request{Command: CmdBlock, Value: "8.8.8.8"}); !resp.OK {
		t.Fatalf("block: %+v", resp)
	}
	if resp := request(t, socketPath, Request{Command: CmdBlock, Value: "10.0.0.0/8"}); !resp.OK {
		t.Fatalf("block /8: %+v", resp)
	}

	if resp := request(t, socketPath, Request{Command: CmdStatus}); !resp.OK || !resp.Attached || resp.Count != 2 {
		t.Fatalf("status: %+v", resp)
	}

	if resp := request(t, socketPath, Request{Command: CmdList}); !resp.OK || resp.Count != 2 {
		t.Fatalf("list: %+v", resp)
	}

	// LPM match must hold through the real kernel map.
	if resp := request(t, socketPath, Request{Command: CmdBlock, Value: "10.0.0.0/8"}); !resp.OK {
		t.Fatalf("re-block: %+v", resp)
	}

	if resp := request(t, socketPath, Request{Command: CmdUnblock, Value: "8.8.8.8"}); !resp.OK {
		t.Fatalf("unblock: %+v", resp)
	}
	// After unblocking 8.8.8.8, 10.0.0.0/8 remains.
	if resp := request(t, socketPath, Request{Command: CmdList}); !resp.OK || resp.Count != 1 {
		t.Fatalf("list after unblock: %+v", resp)
	}

	if resp := request(t, socketPath, Request{Command: CmdClear}); !resp.OK {
		t.Fatalf("clear: %+v", resp)
	}
	if resp := request(t, socketPath, Request{Command: CmdList}); !resp.OK || resp.Count != 0 {
		t.Fatalf("list after clear: %+v", resp)
	}

	// Unknown command over the wire.
	if resp := request(t, socketPath, Request{Command: "nope"}); resp.OK {
		t.Fatalf("unknown command should not be ok: %+v", resp)
	}

	// Malformed JSON over the wire.
	if resp := requestRaw(t, socketPath, "{not json"); resp.OK {
		t.Fatalf("malformed request should not be ok: %+v", resp)
	}
}

// requestRaw sends a raw string over the socket and decodes a Response.
func requestRaw(t *testing.T, socketPath, raw string) Response {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(raw + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}
