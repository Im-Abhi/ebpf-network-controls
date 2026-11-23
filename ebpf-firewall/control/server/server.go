package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Policy is the minimal firewall surface the control server drives. It is
// satisfied by *ebpf.Firewall and lets the server be unit-tested against a
// fake without a kernel.
//
// The write path is deliberately minimal: every rule add goes through one
// ...WithActionPriority method per (direction × IP/port), with the action and
// priority always explicit. A request without an action is normalized to
// "drop" by the server before calling in (see handleBlock), so the interface
// needs no convenience overloads. Ingress methods manage the XDP policy;
// Egress* methods manage the TC egress policy; the rest is shared state.
type Policy interface {
	// Ingress (XDP) policy.
	BlockIPWithActionPriority(cidr, action string, priority uint32) error
	UnblockIP(cidr string) error
	ListBlockedIPs() ([]string, error)
	ListBlockedRules() ([]BlockedRule, error)
	BlockPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, action string, priority uint32) error
	UnblockPortRule(dst, protocol string, dport, sport uint16) error
	ListPortRules() ([]PortRule, error)
	Clear() error          // ingress IP rules
	ClearPortRules() error // ingress port rules

	// Egress (TC) policy.
	BlockEgressWithActionPriority(cidr, action string, priority uint32) error
	UnblockEgress(cidr string) error
	ListEgressRules() ([]BlockedRule, error)
	BlockEgressPortRuleWithActionPriority(dst, protocol string, dport, sport uint16, action string, priority uint32) error
	UnblockEgressPortRule(dst, protocol string, dport, sport uint16) error
	ListEgressPortRules() ([]PortRule, error)
	ClearEgress() error

	// Egress domain blocklist (URL filtering). Domains are egress-only;
	// Direction on requests is ignored for these commands.
	BlockDomain(name string) error
	UnblockDomain(name string) error
	ListDomains() ([]string, error)
	ClearDomains() error

	// Shared state.
	Interface() string
	AttachMode() string
	Stats() (Stats, error)
	EgressStats() (Stats, error)
	SetDefaultPolicy(s string) error
	DefaultPolicy() (string, error)
	SetEgressDefault(s string) error
	EgressDefault() (string, error)
	ListConntrack() ([]ConntrackEntry, error)
	ClearConntrack() error
	EgressAttached() bool
}

// Direction values accepted for Request.Direction. An empty string is
// normalized to in by normalizeDirection so plain blocks stay ingress-only.
const (
	dirIn   = "in"
	dirOut  = "out"
	dirBoth = "both"
)

// normalizeDirection maps an empty/invalid direction to the set of concrete
// policies it applies to. "" and "in" touch only the ingress maps; "out" only
// the egress maps; "both" both.
func normalizeDirection(d string) ([]string, error) {
	switch d {
	case "", dirIn:
		return []string{dirIn}, nil
	case dirOut:
		return []string{dirOut}, nil
	case dirBoth:
		return []string{dirIn, dirOut}, nil
	default:
		return nil, fmt.Errorf("invalid direction %q (use in, out, or both)", d)
	}
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
// use via the mutex. Each command's logic lives in its own handle* method so
// this function stays a readable dispatch table.
func (s *Server) handle(req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()

	dirs, err := normalizeDirection(req.Direction)
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	// Echo back a canonical single direction (in/out/both) so multi-table
	// replies are self-describing.
	echoDir := dirs[0]
	if len(dirs) == 2 {
		echoDir = dirBoth
	}

	switch req.Command {
	case CmdBlock:
		return s.handleBlock(req, dirs, echoDir)
	case CmdUnblock:
		return s.handleUnblock(req, dirs, echoDir)
	case CmdList:
		return s.handleList(dirs, echoDir)
	case CmdListPorts:
		return s.handleListPorts(dirs, echoDir)
	case CmdStatus:
		return s.handleStatus()
	case CmdSetDefault, CmdDefault:
		return s.handleDefault(req, dirs, echoDir)
	case CmdClear:
		return s.handleClear(dirs, echoDir)
	case CmdBlockDomain:
		return s.handleBlockDomain(req)
	case CmdUnblockDomain:
		return s.handleUnblockDomain(req)
	case CmdListDomains:
		return s.handleListDomains()
	case CmdClearDomains:
		return s.handleClearDomains()
	case CmdConntrack:
		return s.handleConntrack()
	case CmdStats:
		return s.handleStats()
	default:
		return Response{OK: false, Error: "unknown command: " + string(req.Command)}
	}
}

// handleBlock adds one rule per requested direction. A request carries either
// an IP rule (value = IP/CIDR) or a port rule (any of protocol/port/sport
// set), and an optional action + priority. An empty action means DROP — the
// blocklist default — so the ...WithActionPriority methods are called with
// fully explicit arguments.
func (s *Server) handleBlock(req Request, dirs []string, echoDir string) Response {
	action := req.Action
	if action == "" {
		action = "drop"
	}
	isPortRule := req.Protocol != "" || req.Port != 0 || req.SPort != 0

	for _, d := range dirs {
		var err error
		if isPortRule {
			if d == dirIn {
				err = s.policy.BlockPortRuleWithActionPriority(req.Value, req.Protocol, req.Port, req.SPort, action, req.Priority)
			} else {
				err = s.policy.BlockEgressPortRuleWithActionPriority(req.Value, req.Protocol, req.Port, req.SPort, action, req.Priority)
			}
		} else {
			if d == dirIn {
				err = s.policy.BlockIPWithActionPriority(req.Value, action, req.Priority)
			} else {
				err = s.policy.BlockEgressWithActionPriority(req.Value, action, req.Priority)
			}
		}
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
	}
	return Response{OK: true, Direction: echoDir}
}

// handleUnblock removes one rule per requested direction (IP or port rule,
// same discriminator as handleBlock).
func (s *Server) handleUnblock(req Request, dirs []string, echoDir string) Response {
	isPortRule := req.Protocol != "" || req.Port != 0 || req.SPort != 0

	for _, d := range dirs {
		var err error
		if isPortRule {
			if d == dirIn {
				err = s.policy.UnblockPortRule(req.Value, req.Protocol, req.Port, req.SPort)
			} else {
				err = s.policy.UnblockEgressPortRule(req.Value, req.Protocol, req.Port, req.SPort)
			}
		} else {
			if d == dirIn {
				err = s.policy.UnblockIP(req.Value)
			} else {
				err = s.policy.UnblockEgress(req.Value)
			}
		}
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
	}
	return Response{OK: true, Direction: echoDir}
}

// handleList returns the IP rules of the requested directions. Non-nil empty
// slices so an empty table serializes as [] (not null) — clients distinguish
// "listed, nothing here" from "field absent".
func (s *Server) handleList(dirs []string, echoDir string) Response {
	blocked := make([]BlockedRule, 0)
	egress := make([]BlockedRule, 0)
	for _, d := range dirs {
		if d == dirIn {
			rules, err := s.policy.ListBlockedRules()
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			blocked = append(blocked, rules...)
		} else {
			rules, err := s.policy.ListEgressRules()
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			egress = append(egress, rules...)
		}
	}
	blockedCids := make([]string, 0, len(blocked))
	for _, r := range blocked {
		blockedCids = append(blockedCids, r.Cidr)
	}
	return Response{
		OK:           true,
		Blocked:      blockedCids,
		BlockedRules: blocked,
		EgressRules:  egress,
		Count:        len(blocked) + len(egress),
		Direction:    echoDir,
	}
}

// handleListPorts returns the port rules of the requested directions (same
// non-nil-empty-slice contract as handleList).
func (s *Server) handleListPorts(dirs []string, echoDir string) Response {
	ports := make([]PortRule, 0)
	egressPorts := make([]PortRule, 0)
	for _, d := range dirs {
		if d == dirIn {
			rules, err := s.policy.ListPortRules()
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			ports = append(ports, rules...)
		} else {
			rules, err := s.policy.ListEgressPortRules()
			if err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			egressPorts = append(egressPorts, rules...)
		}
	}
	return Response{
		OK:              true,
		PortRules:       ports,
		EgressPortRules: egressPorts,
		Count:           len(ports) + len(egressPorts),
		Direction:       echoDir,
	}
}

func (s *Server) handleStatus() Response {
	blocked, err := s.policy.ListBlockedIPs()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	def, err := s.policy.DefaultPolicy()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	egressDef, err := s.policy.EgressDefault()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{
		OK:             true,
		Iface:          s.policy.Interface(),
		Attached:       s.live,
		Count:          len(blocked),
		Default:        def,
		AttachMode:     s.policy.AttachMode(),
		Direction:      "in",
		EgressDefault:  egressDef,
		EgressAttached: s.policy.EgressAttached(),
	}
}

func (s *Server) handleDefault(req Request, dirs []string, echoDir string) Response {
	for _, d := range dirs {
		var err error
		if d == dirIn {
			err = s.policy.SetDefaultPolicy(req.Value)
		} else {
			err = s.policy.SetEgressDefault(req.Value)
		}
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
	}
	return Response{OK: true, Direction: echoDir}
}

// handleClear wipes the requested directions' rules. Rule changes can
// invalidate established flows, so the shared conntrack table is always
// cleared too — even for a direction-scoped clear (documented contract).
func (s *Server) handleClear(dirs []string, echoDir string) Response {
	for _, d := range dirs {
		var err error
		if d == dirIn {
			if err = s.policy.Clear(); err != nil {
				return Response{OK: false, Error: err.Error()}
			}
			err = s.policy.ClearPortRules()
		} else {
			err = s.policy.ClearEgress()
		}
		if err != nil {
			return Response{OK: false, Error: err.Error()}
		}
	}
	if err := s.policy.ClearConntrack(); err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Direction: echoDir}
}

func (s *Server) handleConntrack() Response {
	entries, err := s.policy.ListConntrack()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Conntrack: entries, Count: len(entries), Direction: "in"}
}

// Domain-blocklist handlers. Domains are an egress-only surface: the
// direction field is ignored, and they are intentionally not part of
// CmdClear — wiping them requires the explicit clear-domains command.

func (s *Server) handleBlockDomain(req Request) Response {
	name := strings.TrimSpace(req.Value)
	if name == "" {
		return Response{OK: false, Error: "block-domain requires a domain name"}
	}
	if err := s.policy.BlockDomain(name); err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Direction: dirOut}
}

func (s *Server) handleUnblockDomain(req Request) Response {
	name := strings.TrimSpace(req.Value)
	if name == "" {
		return Response{OK: false, Error: "unblock-domain requires a domain name"}
	}
	if err := s.policy.UnblockDomain(name); err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Direction: dirOut}
}

func (s *Server) handleListDomains() Response {
	domains, err := s.policy.ListDomains()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	if domains == nil {
		domains = []string{} // empty table serializes as [], not null
	}
	return Response{OK: true, Domains: domains, Count: len(domains), Direction: dirOut}
}

func (s *Server) handleClearDomains() Response {
	if err := s.policy.ClearDomains(); err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Direction: dirOut}
}

func (s *Server) handleStats() Response {
	stats, err := s.policy.Stats()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	egressStats, err := s.policy.EgressStats()
	if err != nil {
		return Response{OK: false, Error: err.Error()}
	}
	return Response{OK: true, Stats: &stats, EgressStats: &egressStats}
}
