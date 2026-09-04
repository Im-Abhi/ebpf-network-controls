package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
)

// Policy is the minimal firewall surface the control server drives. It is
// satisfied by *ebpf.Firewall and lets the server be unit-tested against a
// fake without a kernel.
type Policy interface {
	BlockIP(cidr string) error
	UnblockIP(cidr string) error
	ListBlockedIPs() ([]string, error)
	Clear() error
	Interface() string
	Stats() (Stats, error)
	BlockPortRule(dst, protocol string, port uint16) error
	UnblockPortRule(dst, protocol string, port uint16) error
	ListPortRules() ([]PortRule, error)
}

// Server exposes a newline-delimited JSON API over a Unix socket. Each command
// is applied to the Policy (the running firewall). A single logical daemon
// holds one Server.
type Server struct {
	socketPath string
	policy     Policy

	// mu serializes access to the policy and the live flag.
	mu   sync.Mutex
	live bool
	ln   net.Listener
	wg   sync.WaitGroup
}

// New creates a Server bound to the given policy. Start must be called to
// begin listening.
func New(socketPath string, policy Policy) *Server {
	return &Server{
		socketPath: socketPath,
		policy:     policy,
	}
}

// Start binds the Unix socket and begins accepting connections. It returns
// after binding; the accept loop runs in a background goroutine until either
// ctx is cancelled or Close is called.
func (s *Server) Start(ctx context.Context) error {
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %q: %w", s.socketPath, err)
	}

	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listening on %q: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, 0o700); err != nil {
		ln.Close()
		os.Remove(s.socketPath)
		return fmt.Errorf("setting socket permissions on %q: %w", s.socketPath, err)
	}

	s.ln = ln
	s.mu.Lock()
	s.live = true
	s.mu.Unlock()

	go s.acceptLoop(ctx, ln)

	// Close the listener when the context is cancelled so the accept loop
	// unblocks and exits.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return nil
}

// acceptLoop accepts connections until the listener is closed.
func (s *Server) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// The listener was closed (ctx cancel or Close). Exit.
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

// Close stops accepting, waits for in-flight request handlers, and removes the
// socket file. It is safe to call multiple times.
func (s *Server) Close() error {
	var firstErr error

	if s.ln != nil {
		if err := s.ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.mu.Lock()
	s.live = false
	s.mu.Unlock()

	// Wait for all in-flight connection handlers to finish.
	s.wg.Wait()

	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}

	return firstErr
}

// handleConn reads one newline-delimited JSON request, applies it, writes the
// JSON response, and closes the connection. This is a one-shot control channel.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	defer s.wg.Done()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)

	if !scanner.Scan() {
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		writeResponse(conn, Response{OK: false, Error: "malformed request: " + err.Error()})
		return
	}

	writeResponse(conn, s.handle(req))
}

// writeResponse marshals r to JSON with a trailing newline and sends it.
func writeResponse(conn net.Conn, r Response) {
	data, err := json.Marshal(r)
	if err != nil {
		data = []byte(`{"ok":false,"error":"internal: failed to encode response"}`)
	}
	data = append(data, '\n')
	conn.Write(data)
}

// handle applies a single request against the policy. It is reached through
// the accept loop only while the server is live, so no live gate is needed
// here; the `live` flag is status data used by CmdStatus. Safe for concurrent
// use via the mutex.
func (s *Server) handle(req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch req.Command {
	case CmdBlock:
		if req.Protocol != "" || req.Port != 0 {
			if err := s.policy.BlockPortRule(req.Value, req.Protocol, req.Port); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true}
		}
		if err := s.policy.BlockIP(req.Value); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case CmdUnblock:
		if req.Protocol != "" || req.Port != 0 {
			if err := s.policy.UnblockPortRule(req.Value, req.Protocol, req.Port); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			return Response{OK: true}
		}
		if err := s.policy.UnblockIP(req.Value); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case CmdList:
		blocked, err := s.policy.ListBlockedIPs()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Blocked: blocked, Count: len(blocked)}

	case CmdListPorts:
		rules, err := s.policy.ListPortRules()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, PortRules: rules, Count: len(rules)}

	case CmdStatus:
		blocked, err := s.policy.ListBlockedIPs()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Iface: s.policy.Interface(), Attached: s.live, Count: len(blocked)}

	case CmdClear:
		if err := s.policy.Clear(); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true}

	case CmdStats:
		stats, err := s.policy.Stats()
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Stats: &stats}

	default:
		return Response{OK: false, Error: "unknown command: " + string(req.Command)}
	}
}
