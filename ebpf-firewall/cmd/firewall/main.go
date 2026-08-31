package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ebpf-firewall/control/ebpf"
	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var ifname string
	var blockList string
	var sockPath string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.StringVar(&blockList, "block", "", "Comma-separated list of IPs/CIDRs to block (e.g. '192.168.1.5, 10.0.0.0/8')")
	flag.StringVar(&sockPath, "sock", "/var/run/ebpf-firewall.sock", "unix socket path for control")
	flag.Parse()

	log := log.New(os.Stdout, "[firewall] ", log.LstdFlags)

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	fw, err := ebpf.NewFirewall(ifname)
	if err != nil {
		log.Fatalf("Failed to load firewall: %v", err)
	}

	// Attach the XDP program to the interface.
	if err := fw.Start(); err != nil {
		fw.Stop()
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	log.Printf("XDP attached to %s", ifname)

	// Populate the blocked IP's into the kernel map
	if blockList != "" {
		for _, ipStr := range strings.Split(blockList, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}

			if err := fw.BlockIP(ipStr); err != nil {
				log.Printf("Failed to block %s: %v", ipStr, err)
			} else {
				log.Printf("Blocked IP/CIDR: %s", ipStr)
			}
		}
	}

	srv := server.New(sockPath, fw)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("failed to start control server: %v", err)
	}
	log.Printf("control socket listening on %s", sockPath)

	defer fw.Stop()   // runs LAST (LIFO): XDP detaches after socket closes
	defer srv.Close() // runs FIRST: socket closes before XDP detaches

	log.Printf("Successfully attached XDP to %s", ifname)
	log.Printf("Press Ctrl+C to exit and remove the program")

	<-ctx.Done()
	log.Println("Detaching and Exiting...")
}
