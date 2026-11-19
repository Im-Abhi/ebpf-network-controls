package main

import (
	"context"
	"flag"
	"fmt"
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
	"ebpf-firewall/control/rules"
	"ebpf-firewall/control/server"

	"github.com/cilium/ebpf/rlimit"
)

// version is stamped at link time for release builds via
// -ldflags "-X main.version=vX.Y.Z" (see packaging/PACKAGING.md); a plain
// `go build` or `make build` reports "dev".
var version = "dev"

func main() {
	var showVersion bool
	var ifname string
	var blockList string
	var urlBlocklist string
	var sockPath string
	var ctTimeout time.Duration
	var httpAddr string
	var dir string
	flag.StringVar(&ifname, "i", "", "Network interface to attach the eBPF programs to (required, e.g. -i eth0)")
	flag.StringVar(&blockList, "block", "", "Comma-separated list of IPs/CIDRs to block (e.g. '192.168.1.5, 10.0.0.0/8')")
	flag.StringVar(&urlBlocklist, "url-blocklist", "", "Text file of domains/URLs to block on egress: one entry per line, # comments. A bare IPv4 goes to the egress IP table; a URL's host goes to the domain blocklist. Implies the egress hook (-dir out), since URL filtering only exists there")
	flag.StringVar(&sockPath, "sock", "/var/run/ebpf-firewall.sock", "unix socket path for control")
	flag.DurationVar(&ctTimeout, "ct-timeout", 5*time.Minute, "idle timeout for conntrack entries (0 disables the reaper)")
	flag.StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "read-only HTTP stats API listen address (0 or empty disables)")
	flag.StringVar(&dir, "dir", "in", "which datapath(s) to attach and manage: in (XDP), out (TC egress), or both")
	flag.BoolVar(&showVersion, "version", false, "print the version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println("firewall", version)
		return
	}

	log := log.New(os.Stdout, "[firewall] ", log.LstdFlags)

	// The attach interface is deliberately required: silently falling back to
	// a guessed device would attach a kernel-level packet filter to the wrong
	// interface.
	if ifname == "" {
		fmt.Fprintln(os.Stderr, "firewall: -i <interface> is required (e.g. sudo firewall -i eth0)")
		flag.Usage()
		os.Exit(2)
	}

	log.Printf("ebpf-firewall %s", version)

	// Signal handling / context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Attach the TC egress hook unless the operator opted into ingress-only
	// operation. Defaults to ingress-only so a kernel older than 6.6 does not
	// break the plain firewall path; `-dir out|both` is the explicit opt-in
	// cgroup/skb egress sees every outbound packet on any kernel.
	wantEgress := dir == "out" || dir == "both"
	if dir != "in" && dir != "out" && dir != "both" {
		log.Fatalf("Invalid -dir %q: use in, out, or both", dir)
	}

	// The domain blocklist is consumed only by the TC egress datapath, so
	// asking for URL filtering implies the egress hook even under the
	// default -dir in: loading rules nothing reads would silently enforce
	// nothing.
	if urlBlocklist != "" && !wantEgress {
		wantEgress = true
		log.Printf("-url-blocklist requires the egress hook; attaching TC egress")
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

	// Attach the egress classifier (cgroup/skb).
	if wantEgress {
		if err := fw.StartEgress(); err != nil {
			fw.Stop()
			log.Fatalf("Failed to attach egress: %v", err)
		}
		log.Printf("Egress (cgroup/skb) attached for %s", ifname)
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

	// Load the URL blocklist: hostnames into the egress domain table (the
	// datapath drops any TLS ClientHello / HTTP Host matching them), bare
	// IPs into the egress IP table. A file passed explicitly must exist —
	// silently running without the promised enforcement is worse than
	// failing to start. Bad lines are warnings, not errors.
	if urlBlocklist != "" {
		bf, err := os.Open(urlBlocklist)
		if err != nil {
			log.Fatalf("opening url blocklist %q: %v", urlBlocklist, err)
		}
		res, err := rules.ParseBlocklist(bf)
		bf.Close()
		if err != nil {
			log.Fatalf("reading url blocklist %q: %v", urlBlocklist, err)
		}
		for _, w := range res.Warnings {
			log.Printf("url blocklist: %s", w)
		}
		domains, ips := 0, 0
		for _, d := range res.Domains {
			if err := fw.BlockDomain(d); err != nil {
				log.Printf("url blocklist: blocking %q: %v", d, err)
				continue
			}
			domains++
		}
		for _, ip := range res.IPs {
			if err := fw.BlockEgressWithAction(ip, "drop"); err != nil {
				log.Printf("url blocklist: blocking %q: %v", ip, err)
				continue
			}
			ips++
		}
		log.Printf("url blocklist: %d domain(s) + %d ip rule(s) loaded from %s", domains, ips, urlBlocklist)
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
		log.Printf("Successfully attached XDP (%s) + egress (cgroup/skb) for %s", fw.AttachMode(), ifname)
	} else {
		log.Printf("Successfully attached XDP (%s) to %s", fw.AttachMode(), ifname)
	}
	log.Printf("Press Ctrl+C to exit and remove the program")

	<-ctx.Done()
	log.Println("Detaching and Exiting...")
}
