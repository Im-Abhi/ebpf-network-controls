package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ebpf-firewall/control/api"
	"ebpf-firewall/control/ebpf"
	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var ifname string
	var blockList string
	var sockPath string
	var ctTimeout time.Duration
	var httpAddr string
	var dir string
	flag.StringVar(&ifname, "i", "wlp0s20f3", "Network interface name where the eBPF programs will be attached")
	flag.StringVar(&blockList, "block", "", "Comma-separated list of IPs/CIDRs to block (e.g. '192.168.1.5, 10.0.0.0/8')")
	flag.StringVar(&sockPath, "sock", "/var/run/ebpf-firewall.sock", "unix socket path for control")
	flag.DurationVar(&ctTimeout, "ct-timeout", 5*time.Minute, "idle timeout for conntrack entries (0 disables the reaper)")
	flag.StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "read-only HTTP stats API listen address (0 or empty disables)")
	flag.StringVar(&dir, "dir", "in", "which datapath(s) to attach and manage: in (XDP), out (TC egress), or both")
	flag.Parse()

	log := log.New(os.Stdout, "[firewall] ", log.LstdFlags)

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Attach the TC egress hook unless the operator opted into ingress-only
	// operation. Defaults to ingress-only so a kernel older than 6.6 does not
	// break the plain firewall path; `-dir out|both` is the explicit opt-in
	// and fails loudly when the kernel lacks TCX support.
	wantEgress := dir == "out" || dir == "both"
	if dir != "in" && dir != "out" && dir != "both" {
		log.Fatalf("Invalid -dir %q: use in, out, or both", dir)
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel. Loading always
	// creates both programs (firewall_prog and firewall_tc_egress) plus all 9
	// maps; the egress classifier is not attached unless -dir asks for it.
	fw, err := ebpf.NewFirewall(ifname)
	if err != nil {
		log.Fatalf("Failed to load firewall: %v", err)
	}

	// Attach the XDP program to the interface.
	if err := fw.Start(); err != nil {
		fw.Stop()
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	log.Printf("XDP (%s) attached to %s", fw.AttachMode(), ifname)

	// Attach the TC egress classifier (TCX, kernel >= 6.6).
	if wantEgress {
		if err := fw.StartEgress(); err != nil {
			fw.Stop()
			log.Fatalf("Failed to attach TC egress: %v", err)
		}
		log.Printf("TC egress (tcx) attached to %s", ifname)
	}

	// Populate the blocked IP's into the kernel map. `-block` seeds both
	// directions when -dir out/both, and ingress only otherwise.
	if blockList != "" {
		for _, ipStr := range strings.Split(blockList, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}

			if err := fw.BlockIP(ipStr); err != nil {
				log.Printf("Failed to block %s: %v", ipStr, err)
			} else {
				log.Printf("Blocked IP/CIDR (in): %s", ipStr)
			}
			if wantEgress {
				if err := fw.BlockEgressWithAction(ipStr, "drop"); err != nil {
					log.Printf("Failed to block %s (out): %v", ipStr, err)
				} else {
					log.Printf("Blocked IP/CIDR (out): %s", ipStr)
				}
			}
		}
	}

	// Conntrack is a plain (non-LRU) hash map, so a userspace reaper bounds its
	// size by deleting flows idle for ctTimeout. It scans roughly every half
	// timeout so a flow is evicted within ~1.5x the configured timeout.
	if ctTimeout > 0 {
		interval := ctTimeout / 2
		if interval < time.Second {
			interval = time.Second
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					n, err := fw.ReapConntrack(ctTimeout)
					if err != nil {
						log.Printf("conntrack reap: %v", err)
					} else if n > 0 {
						log.Printf("conntrack: reaped %d stale flow(s)", n)
					}
				}
			}
		}()
	}

	srv := server.New(sockPath, fw)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("failed to start control server: %v", err)
	}
	log.Printf("control socket listening on %s", sockPath)

	// Read-only HTTP stats API. Binding is loopback by default; warn when the
	// caller pins it to a non-local address, since /rules and /conntrack expose
	// security-relevant state even though the API never mutates policy.
	if httpAddr != "" && httpAddr != "0" {
		if host, _, err := net.SplitHostPort(httpAddr); err == nil &&
			(host == "" || host == "0.0.0.0" || host == "::") {
			log.Printf("WARNING: HTTP API bound to %s (not loopback); rule and conntrack state is exposed read-only", httpAddr)
		}
		httpSrv := &http.Server{Addr: httpAddr, Handler: api.New(fw)}
		go func() {
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("http api: %v", err)
			}
		}()
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := httpSrv.Shutdown(shutCtx); err != nil {
				log.Printf("http api shutdown: %v", err)
			}
		}()
		log.Printf("HTTP API listening on %s (read-only)", httpAddr)
	}

	defer fw.Stop()       // runs LAST (LIFO): XDP detaches after the egress link
	defer fw.StopEgress() // runs in the middle: TC egress link detaches next
	defer srv.Close()     // runs FIRST: socket closes before program detaches

	if wantEgress {
		log.Printf("Successfully attached XDP (%s) + TC egress (tcx) to %s", fw.AttachMode(), ifname)
	} else {
		log.Printf("Successfully attached XDP (%s) to %s", fw.AttachMode(), ifname)
	}
	log.Printf("Press Ctrl+C to exit and remove the program")

	<-ctx.Done()
	log.Println("Detaching and Exiting...")
}
