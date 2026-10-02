package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"ebpf-firewall/control/server"
)

func main() {
	args, sockPath, protocol, action, direction, portUint, sportUint, priorityUint, err := extractOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "firewallctl: %v\n", err)
		os.Exit(2)
	}

	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	port := uint16(portUint)
	sport := uint16(sportUint)
	priority := uint32(priorityUint)

	cmd := args[0]

	var req server.Request
	switch cmd {
	case "block", "unblock":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "firewallctl: %s requires an IP/CIDR argument\n", cmd)
			os.Exit(2)
		}
		req = server.Request{Command: server.Command(cmd), Value: args[1], Protocol: protocol, Port: port, SPort: sport, Action: action, Priority: priority, Direction: direction}
	case "list":
		req = server.Request{Command: server.CmdList, Direction: direction}
	case "listports":
		req = server.Request{Command: server.CmdListPorts, Direction: direction}
	case "status":
		req = server.Request{Command: server.CmdStatus}
	case "clear":
		req = server.Request{Command: server.CmdClear, Direction: direction}
	case "stats":
		req = server.Request{Command: server.CmdStats}
	case "conntrack":
		req = server.Request{Command: server.CmdConntrack}
	case "default":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "firewallctl: default requires allow or deny")
			os.Exit(2)
		}
		req = server.Request{Command: server.CmdDefault, Value: args[1], Direction: direction}
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "firewallctl: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}

	resp, err := roundTrip(sockPath, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "firewallctl: %v\n", err)
		os.Exit(1)
	}

	printResponse(resp)
}

// extractOptions pulls the -sock/-protocol/-dport/-sport/-dir options out of
// the raw arguments (also accepting --x and x=value forms) so they work in
// any position relative to the command. Go's flag package stops at the first
// positional argument, which made the documented form
// `block <ip> --protocol tcp --dport 22` silently ignore the options.
// Returns the remaining positional arguments.
func extractOptions(raw []string) (args []string, sockPath, protocol, action, direction string, port, sport, priority uint, err error) {
	sockPath = "/var/run/ebpf-firewall.sock"

	for i := 0; i < len(raw); i++ {
		arg := raw[i]
		switch {
		case arg == "-h" || arg == "--help":
			usage()
			os.Exit(0)
		case arg == "-sock" || arg == "--sock":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a path", arg)
			}
			i++
			sockPath = raw[i]
		case strings.HasPrefix(arg, "-sock="):
			sockPath = strings.TrimPrefix(arg, "-sock=")
		case strings.HasPrefix(arg, "--sock="):
			sockPath = strings.TrimPrefix(arg, "--sock=")
		case arg == "-dir" || arg == "--dir":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a value (in, out, or both)", arg)
			}
			i++
			direction, err = parseDirection(raw[i], "-dir")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "-dir="):
			direction, err = parseDirection(strings.TrimPrefix(arg, "-dir="), "-dir")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "--dir="):
			direction, err = parseDirection(strings.TrimPrefix(arg, "--dir="), "--dir")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case arg == "-protocol" || arg == "--protocol":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a value (tcp or udp)", arg)
			}
			i++
			protocol = raw[i]
		case strings.HasPrefix(arg, "-protocol="):
			protocol = strings.TrimPrefix(arg, "-protocol=")
		case strings.HasPrefix(arg, "--protocol="):
			protocol = strings.TrimPrefix(arg, "--protocol=")
		case arg == "-action" || arg == "--action":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a value (pass or drop)", arg)
			}
			i++
			action = raw[i]
		case strings.HasPrefix(arg, "-action="):
			action = strings.TrimPrefix(arg, "-action=")
		case strings.HasPrefix(arg, "--action="):
			action = strings.TrimPrefix(arg, "--action=")
		case arg == "-priority" || arg == "--priority":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a numeric value (0-4294967295)", arg)
			}
			i++
			priority, err = parsePriority(raw[i], "-priority")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "-priority="):
			priority, err = parsePriority(strings.TrimPrefix(arg, "-priority="), "-priority")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "--priority="):
			priority, err = parsePriority(strings.TrimPrefix(arg, "--priority="), "-priority")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case arg == "-dport" || arg == "--dport":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a numeric value (0-65535)", arg)
			}
			i++
			port, err = parsePort(raw[i], "-dport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "-dport="):
			port, err = parsePort(strings.TrimPrefix(arg, "-dport="), "-dport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "--dport="):
			port, err = parsePort(strings.TrimPrefix(arg, "--dport="), "-dport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case arg == "-sport" || arg == "--sport":
			if i+1 >= len(raw) {
				return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("%s requires a numeric value (0-65535)", arg)
			}
			i++
			sport, err = parsePort(raw[i], "-sport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "-sport="):
			sport, err = parsePort(strings.TrimPrefix(arg, "-sport="), "-sport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "--sport="):
			sport, err = parsePort(strings.TrimPrefix(arg, "--sport="), "-sport")
			if err != nil {
				return nil, "", "", "", "", 0, 0, 0, err
			}
		case strings.HasPrefix(arg, "-"):
			return nil, "", "", "", "", 0, 0, 0, fmt.Errorf("unknown option %q", arg)
		default:
			args = append(args, arg)
		}
	}

	return args, sockPath, protocol, action, direction, port, sport, priority, nil
}

// parseDirection validates a -dir value.
func parseDirection(s, flagName string) (string, error) {
	switch s {
	case "in", "out", "both":
		return s, nil
	default:
		return "", fmt.Errorf("invalid %s %q (must be in, out, or both)", flagName, s)
	}
}

// parsePort validates a -dport/-sport value, which must fit in a uint16.
func parsePort(s, flagName string) (uint, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (must be 0-65535)", flagName, s)
	}
	return uint(n), nil
}

// parsePriority validates a -priority value, which must fit in a uint32.
func parsePriority(s, flagName string) (uint, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (must be 0-4294967295)", flagName, s)
	}
	return uint(n), nil
}

// roundTrip dials the Unix socket, sends one request, and decodes the response.
func roundTrip(sockPath string, req server.Request) (server.Response, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return server.Response{}, fmt.Errorf("connecting to %q: %w", sockPath, err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return server.Response{}, fmt.Errorf("sending request: %w", err)
	}

	var resp server.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return server.Response{}, fmt.Errorf("reading response: %w", err)
	}
	return resp, nil
}

// printResponse renders a response for human consumption.
func printResponse(resp server.Response) {
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "error: %s\n", resp.Error)
		os.Exit(1)
	}

	switch {
	case resp.Stats != nil || resp.EgressStats != nil:
		if resp.Stats != nil {
			printStats("ingress", resp.Stats)
		}
		if resp.EgressStats != nil {
			fmt.Println()
			printStats("egress", resp.EgressStats)
		}
	case resp.PortRules != nil || resp.EgressPortRules != nil:
		if len(resp.PortRules) > 0 {
			fmt.Println("port rules:")
			for _, r := range resp.PortRules {
				printPortRule(r)
			}
		}
		if len(resp.EgressPortRules) > 0 {
			fmt.Println("egress port rules:")
			for _, r := range resp.EgressPortRules {
				printPortRule(r)
			}
		}
		if len(resp.PortRules) == 0 && len(resp.EgressPortRules) == 0 {
			fmt.Println("no port rules")
		}
	case resp.Conntrack != nil:
		if resp.Count == 0 {
			fmt.Println("no tracked flows")
			return
		}
		fmt.Printf("conntrack (%d):\n", resp.Count)
		for _, e := range resp.Conntrack {
			fmt.Printf("  %s:%d -> %s:%d %s [%s] age %.1fs\n",
				e.Src, e.Sport, e.Dst, e.Dport, e.Protocol, e.State, e.AgeSeconds)
		}
		return
	case resp.Blocked != nil || resp.BlockedRules != nil || resp.EgressRules != nil:
		if len(resp.BlockedRules) > 0 {
			fmt.Printf("blocked (%d):\n", len(resp.BlockedRules))
			for _, r := range resp.BlockedRules {
				fmt.Printf("  %s [%s] prio %d\n", r.Cidr, r.Action, r.Priority)
			}
		} else if len(resp.Blocked) > 0 {
			fmt.Printf("blocked (%d):\n", len(resp.Blocked))
			for _, cidr := range resp.Blocked {
				fmt.Printf("  %s\n", cidr)
			}
		}
		if len(resp.EgressRules) > 0 {
			fmt.Printf("egress blocked (%d):\n", len(resp.EgressRules))
			for _, r := range resp.EgressRules {
				fmt.Printf("  %s [%s] prio %d\n", r.Cidr, r.Action, r.Priority)
			}
		}
		if len(resp.BlockedRules) == 0 && len(resp.Blocked) == 0 && len(resp.EgressRules) == 0 {
			fmt.Println("no blocked addresses")
		}
	case resp.Iface != "":
		fmt.Printf("interface: %s\n", resp.Iface)
		if resp.AttachMode != "" {
			fmt.Printf("attach mode: %s\n", resp.AttachMode)
		}
		fmt.Printf("control plane: %v\n", resp.Attached)
		fmt.Printf("blocked: %d\n", resp.Count)
		fmt.Printf("default policy: %s\n", resp.Default)
		if resp.EgressAttached {
			fmt.Println("egress: attached")
		} else {
			fmt.Println("egress: detached")
		}
		if resp.EgressDefault != "" {
			fmt.Printf("egress default policy: %s\n", resp.EgressDefault)
		}
	default:
		fmt.Println("ok")
	}
}

// printPortRule renders a single port rule line (shared by both directions).
func printPortRule(r server.PortRule) {
	if r.SPort != 0 {
		fmt.Printf("  %s/%d (sport %d) -> %s [%s] prio %d\n", r.Protocol, r.Port, r.SPort, r.Dst, r.Action, r.Priority)
	} else {
		fmt.Printf("  %s/%d -> %s [%s] prio %d\n", r.Protocol, r.Port, r.Dst, r.Action, r.Priority)
	}
}

func printStats(label string, s *server.Stats) {
	fmt.Printf("%s packets:\n", label)
	fmt.Printf("  Total:   %d\n", s.TotalPackets)
	fmt.Printf("  Passed:  %d\n", s.PassPackets)
	fmt.Printf("  Dropped: %d\n", s.DropPackets)
	fmt.Printf("%s bytes:\n", label)
	fmt.Printf("  Total:   %s\n", formatBytes(s.TotalBytes))
	fmt.Printf("  Passed:  %s\n", formatBytes(s.PassBytes))
	fmt.Printf("  Dropped: %s\n", formatBytes(s.DropBytes))
}

// formatBytes converts a byte count to a human-readable string (B, KB, MB, GB).
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: firewallctl [-sock path] [-dir in|out|both] [-protocol p] [-dport n] [-sport n] [-action a] [-priority n] <command> [args]

Options may appear before or after the command, e.g.
  firewallctl block 1.2.3.4 --protocol tcp --dport 22
  firewallctl --dport 443 --protocol udp --sport 12345 unblock 1.2.3.4
  firewallctl block 10.0.0.0/8 --action drop --priority 100
  firewallctl block 10.0.0.1 --action pass --priority 200
  firewallctl block 6.6.6.6 --dir out
  firewallctl list --dir both

Commands:
  status                 show firewall status
  list                   list blocked IPs/CIDRs (per --dir)
  listports              list protocol/port rules (per --dir)
  block <ip/cidr>        block an IP/CIDR, or with --protocol/--dport a port rule
  unblock <ip/cidr>      unblock an IP/CIDR or port rule
  default allow|deny     set the default (fallback) policy on no match
  clear                  remove rules in the given direction (IP blocklist, port
                         rules, and the shared conntrack state)
  stats                  show packet/byte counters (ingress and egress)
  conntrack              list tracked TCP flows
  help                   show this help

Direction:
  -dir d         which policy to operate on: in (XDP ingress, default),
                 out (TC egress), or both. Egress rules match the remote
                 destination being contacted (dst-only for IP/CIDR rules).
                 Requires a kernel >= 6.6 for the TC egress hook.

Options:
  -sock path       control socket path (default /var/run/ebpf-firewall.sock)
  -protocol p      protocol for a port rule: tcp or udp
  -dport n         destination port for a port rule
  -sport n         source port for a port rule (0 = any source port)
  -action a        rule action: pass or drop (default drop)
  -priority n      rule priority (0-4294967295, default 0); among rules that
                   match a packet the highest priority wins. At equal
                   priority the more specific port rule wins and a tie
                   between an IP rule and a port rule resolves to drop
`)
}
