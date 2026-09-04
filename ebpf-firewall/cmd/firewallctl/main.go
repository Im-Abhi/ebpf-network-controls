package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"ebpf-firewall/control/server"
)

func main() {
	var sockPath string
	var protocol string
	var portUint uint
	flag.StringVar(&sockPath, "sock", "/var/run/ebpf-firewall.sock", "unix control socket path")
	flag.StringVar(&protocol, "protocol", "", "protocol for a port rule: tcp or udp (with a port rule)")
	flag.UintVar(&portUint, "dport", 0, "destination port for a port rule (with --protocol)")
	flag.Usage = usage
	flag.Parse()
	port := uint16(portUint)

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

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

Commands:
  status                 show firewall status
  list                   list blocked IPs/CIDRs
  listports              list protocol/port rules
  block <ip/cidr>        block an IP/CIDR, or with --protocol/--dport a port rule
  unblock <ip/cidr>      unblock an IP/CIDR or port rule
  clear                  remove all blocked addresses
  stats                  show packet/byte counters
  help                   show this help

Options:
  -sock path       control socket path (default /var/run/ebpf-firewall.sock)
  -protocol p      protocol for a port rule: tcp or udp
  -dport n         destination port for a port rule

Examples:
  firewallctl block 192.168.1.100 --protocol tcp --dport 22
  firewallctl unblock 192.168.1.100 --protocol tcp --dport 22
`)
}
