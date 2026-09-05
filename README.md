# eBPF-Based Network Security & Automated Remediation Engine

A thesis project for kernel-level network security using **eBPF, XDP, and Go**.

This repository is evolving toward a full network-security-and-remediation engine. The
**current implementation** is a focused, working XDP IPv4 firewall with a live Go control
plane. Everything else described below is the roadmap the current core is built to grow
into.

---

## Current Implementation

What works today (MTP1 core — XDP firewall):

- **XDP firewall** (`bpf/firewall.c`)
- **IPv4 exact IP / CIDR filtering** via an **LPM trie**
- **Protocol + destination-port rules** (e.g. `block 1.2.3.4 --protocol tcp --dport 22`), verified end-to-end
- **Counters / telemetry** — total, drop and pass packet/byte counters (`firewallctl stats`)
- **CO-RE** (`vmlinux.h`) – portable across kernels without compile-time headers
- **Go control plane** (`control/`)
- **Unix socket API** (`control/server/`) for dynamic, runtime rule updates
- **`firewallctl`** client for live `block` / `unblock` / `list` / `listports` / `status` / `stats` / `clear`; `--protocol` / `--dport` / `-sock` work in any position (before or after the command)
- **Unit + integration tests** (`make test`, `make integration-test`)

### Default policy

```
Default policy: ALLOW

Matching blocked_ips:   DROP
No matching policy:     PASS
```

The firewall is **default-allow**: packets are passed unless they match the blocklist.

### Port rules (ingress only)

XDP is a **receive-side hook**: the program sees packets *entering* the interface
(inbound, or forwarded) and **cannot filter outbound traffic** the host itself
sends. Port rules are therefore ingress filters that protect services **on this
host**:

```bash
sudo ./bin/firewallctl block 10.0.0.1 --protocol tcp --dport 22
```

drops inbound TCP connections *to* `10.0.0.1` on port 22 (e.g. SSH attempts
from other machines). A port rule is an exact match on **dst IP (host) +
protocol + dst port**; it does not filter egress packets (for that you would
need TC egress, not yet implemented).

`clear` removes **both** the IP blocklist and all port rules in one call.
Rule maps are anonymous kernel objects tied to the running daemon — they are
reset when the daemon exits (no persistence across runs).

### Architecture (current)

```text
firewallctl
      │
      ▼
Unix socket  ─────────  control plane (Go)
      │                     │
      ▼                     ▼
  server.go ──▶  Firewall ──▶  MapManager
                                   │
                                   ▼
                              BPF map (LPM trie)
                                   │
                                   ▼
                              XDP program
```

### Structure (current)

```text
ebpf-firewall/
│
├── bpf/                 # eBPF C programs (dataplane)
│   ├── firewall.c
│   ├── helpers.h        # packet parsing helpers
│   ├── maps.h           # BPF map definitions
│   └── vmlinux.h        # GENERATED – do not edit
│
├── control/
│   ├── ebpf/            # map manager, XDP lifecycle, generated bindings
│   │   └── firewall_bpf.go   # GENERATED – do not edit
│   ├── rules/           # rule/IP parsing
│   └── server/          # Unix socket control API
│
├── cmd/
│   ├── firewall/        # daemon entry point
│   └── firewallctl/     # CLI client
│
├── scripts/             # build / vmlinux generation helpers
├── INSTALLATION.md
└── TODO.md              # milestone roadmap (MTP1 / MTP2)
```

---

## Future Extensions (roadmap)

These are **planned**, not yet implemented:

- **TC ingress / egress** (attach points beyond XDP)
- **Flow / connection state tracking**
- **Attack detection** (e.g. SYN floods)
- **Quarantine & automated remediation**
- **L7 / TLS traffic inspection**

---

## Getting Started & Installation

For full environment setup, required Linux kernel headers, build tools, and dependencies, refer to:
👉 **[INSTALLATION.md](INSTALLATION.md)**

Quick build using Makefile:
```bash
cd ebpf-firewall
make generate   # compile eBPF + generate Go bindings
make build      # build bin/firewall and bin/firewallctl
sudo ./bin/firewall -i eth0
```

---

## Performance Evaluation

The benchmarking module (`MTP1-E`) compares the eBPF/XDP firewall against
**nftables** (modern Linux baseline) using identical traffic patterns:

| Metric                    | eBPF/XDP Firewall | nftables |
| ------------------------- | ----------------- | -------- |
| Packet processing latency | ✓                 | ✓        |
| Throughput (Gbps)         | ✓                 | ✓        |
| Packets/sec               | ✓                 | ✓        |
| CPU utilization           | ✓                 | ✓        |
| Memory usage              | ✓                 | ✓        |
| Firewall rule update time | ✓                 | ✓        |

Traffic is generated with `iperf3` / `pktgen`. Results are documented in
`benchmark/results/`.

---

## Tools & Technologies

| Technology    | Purpose                                        |
| ------------- | ---------------------------------------------- |
| **eBPF**      | Kernel-level programmable packet processing    |
| **XDP**       | Early packet processing and filtering          |
| **Go**        | Control plane, map manager, CLI/client         |
| **C**         | eBPF dataplane programs                        |
| **Linux**     | Target operating system and networking stack   |
| **eBPF Maps** | Kernel–user space state and communication      |

---

## Project Status

**Status:** Academic / Research Project

<!--
## Author

Developed as an academic project under the supervision of **Dr. Rajesh Kumar Pal**.
-->
