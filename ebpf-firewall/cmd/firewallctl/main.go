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
	args, sockPath, protocol, portUint, err := extractOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "firewallctl: %v\n", err)
		os.Exit(2)
	}

	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	port := uint16(portUint)

	cmd := args[0]

	var req server.Request
	switch cmd {
	case "block", "unblock":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "firewallctl: %s requires an IP/CIDR argument\n", cmd)
			os.Exit(2)
		}
		req = server.Request{Command: server.Command(cmd), Value: args[1], Protocol: protocol, Port: port}
	case "list":
		req = server.Request{Command: server.CmdList}
	case "listports":
		req = server.Request{Command: server.CmdListPorts}
	case "status":
		req = server.Request{Command: server.CmdStatus}
	case "clear":
		req = server.Request{Command: server.CmdClear}
	case "stats":
		req = server.Request{Command: server.CmdStats}
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

// extractOptions pulls the -sock/-protocol/-dport options out of the raw
// arguments (also accepting --x and x=value forms) so they work in any
// position relative to the command. Go's flag package stops at the first
// positional argument, which made the documented form
// `block <ip> --protocol tcp --dport 22` silently ignore the options.
// Returns the remaining positional arguments.
func extractOptions(raw []string) (args []string, sockPath, protocol string, port uint, err error) {
	sockPath = "/var/run/ebpf-firewall.sock"

	for i := 0; i < len(raw); i++ {
		arg := raw[i]
		switch {
		case arg == "-h" || arg == "--help":
			usage()
			os.Exit(0)
		case arg == "-sock" || arg == "--sock":
			if i+1 >= len(raw) {
				return nil, "", "", 0, fmt.Errorf("%s requires a path", arg)
			}
			i++
			sockPath = raw[i]
		case strings.HasPrefix(arg, "-sock="):
			sockPath = strings.TrimPrefix(arg, "-sock=")
		case strings.HasPrefix(arg, "--sock="):
			sockPath = strings.TrimPrefix(arg, "--sock=")
		case arg == "-protocol" || arg == "--protocol":
			if i+1 >= len(raw) {
				return nil, "", "", 0, fmt.Errorf("%s requires a value (tcp or udp)", arg)
			}
			i++
			protocol = raw[i]
		case strings.HasPrefix(arg, "-protocol="):
			protocol = strings.TrimPrefix(arg, "-protocol=")
		case strings.HasPrefix(arg, "--protocol="):
			protocol = strings.TrimPrefix(arg, "--protocol=")
		case arg == "-dport" || arg == "--dport":
			if i+1 >= len(raw) {
				return nil, "", "", 0, fmt.Errorf("%s requires a numeric value (0-65535)", arg)
			}
			i++
			port, err = parsePort(raw[i])
			if err != nil {
				return nil, "", "", 0, err
			}
		case strings.HasPrefix(arg, "-dport="):
			port, err = parsePort(strings.TrimPrefix(arg, "-dport="))
			if err != nil {
				return nil, "", "", 0, err
			}
		case strings.HasPrefix(arg, "--dport="):
			port, err = parsePort(strings.TrimPrefix(arg, "--dport="))
			if err != nil {
				return nil, "", "", 0, err
			}
		case strings.HasPrefix(arg, "-"):
			return nil, "", "", 0, fmt.Errorf("unknown option %q", arg)
		default:
			args = append(args, arg)
		}
	}

	return args, sockPath, protocol, port, nil
}

// parsePort validates a -dport value, which must fit in a uint16.
func parsePort(s string) (uint, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid -dport %q (must be 0-65535)", s)
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
	case resp.Stats != nil:
		printStats(resp.Stats)
	case resp.PortRules != nil:
		if resp.Count == 0 {
			fmt.Println("no port rules")
			return
		}
		fmt.Println("port rules:")
		for _, r := range resp.PortRules {
			fmt.Printf("  %s/%d -> %s\n", r.Protocol, r.Port, r.Dst)
		}
	case resp.Blocked != nil:
		if resp.Count == 0 {
			fmt.Println("no blocked addresses")
			return
		}
		fmt.Printf("blocked (%d):\n", resp.Count)
		for _, cidr := range resp.Blocked {
			fmt.Printf("  %s\n", cidr)
		}
	case resp.Iface != "":
		fmt.Printf("interface: %s\n", resp.Iface)
		fmt.Printf("control plane: %v\n", resp.Attached)
		fmt.Printf("blocked: %d\n", resp.Count)
	default:
		fmt.Println("ok")
	}
}

func printStats(s *server.Stats) {
	fmt.Println("Packets:")
	fmt.Printf("  Total:   %d\n", s.TotalPackets)
	fmt.Printf("  Passed:  %d\n", s.PassPackets)
	fmt.Printf("  Dropped: %d\n", s.DropPackets)
	fmt.Println()
	fmt.Println("Bytes:")
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
	fmt.Fprintf(os.Stderr, `Usage: firewallctl [-sock path] [-protocol p] [-dport n] <command> [args]

Options may appear before or after the command, e.g.
  firewallctl block 1.2.3.4 --protocol tcp --dport 22
  firewallctl --dport 443 --protocol udp unblock 1.2.3.4

Commands:
  status                 show firewall status
  list                   list blocked IPs/CIDRs
  listports              list protocol/port rules
  block <ip/cidr>        block an IP/CIDR, or with --protocol/--dport a port rule
  unblock <ip/cidr>      unblock an IP/CIDR or port rule
  clear                  remove all rules (IP blocklist and port rules)
  stats                  show packet/byte counters
  help                   show this help

Options:
  -sock path       control socket path (default /var/run/ebpf-firewall.sock)
  -protocol p      protocol for a port rule: tcp or udp
  -dport n         destination port for a port rule
`)
}
