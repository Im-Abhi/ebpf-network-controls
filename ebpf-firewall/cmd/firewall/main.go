package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ebpf-firewall/control/loader"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var ifname string
	var blockList string
	flag.StringVar(&ifname, "i", "lo", "Network interface name where the eBPF programs will be attached")
	flag.StringVar(&blockList, "block", "", "Comma-separated list of IPs/CIDRs to block (e.g. '192.168.1.5, 10.0.0.0/8')")
	flag.Parse()

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	fw, err := loader.LoadXDP(ifname)
	if err != nil {
		log.Fatalf("Failed to load and attach XDP: %v", err)
	}
	defer fw.Close()

	// Populate the blocked IP's into the kernel map
	if blockList != "" {
		for _, ipStr := range strings.Split(blockList, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if err := fw.BlockIP(ipStr); err != nil {
				log.Printf("Failed to block %s: %v", ipStr, err)
			} else {
				log.Printf("Successfully blocked IP/CIDR: %s", ipStr)
			}
		}
	}

	log.Printf("Successfully attached firewall to %s", ifname)
	log.Printf("Press Ctrl+C to exit and remove the program")

	<-ctx.Done()
	log.Println("Detaching firewall and Exiting...")
}
