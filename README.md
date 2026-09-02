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
- **CO-RE** (`vmlinux.h`) – portable across kernels without compile-time headers
- **Go control plane** (`control/`)
- **Unix socket API** (`control/server/`) for dynamic, runtime rule updates
- **`firewallctl`** client for live `block` / `unblock` / `list` / `status` / `clear`
- **Unit + integration tests** (`make test`, `make integration-test`)

### Default policy

```
Default policy: ALLOW

Matching blocked_ips:   DROP
No matching policy:     PASS
```

The firewall is **default-allow**: packets are passed unless they match the blocklist.

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

- **Counters / telemetry** (packet & byte stats, drop counters)
- **Protocol / port policies** (e.g. `TCP + dst port 22 → DROP`)
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

Planned work compares the eBPF pipeline against conventional Linux firewall mechanisms using:

- **Throughput**
- **Memory overhead**
- **P99 packet-processing latency**

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
