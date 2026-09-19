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
- **Protocol + destination/src-port rules** (e.g. `block 1.2.3.4 --protocol tcp --dport 22`), verified end-to-end
- **Priority-aware matching** (`--priority n`) — deterministic winner when rules overlap, including a **stateful TCP conntrack** fast-path (NEW / ESTABLISHED / CLOSED)
- **Counters / telemetry** — total, drop and pass packet/byte counters (`firewallctl stats`)
- **CO-RE** (`vmlinux.h`) – portable across kernels without compile-time headers
- **Go control plane** (`control/`)
- **Unix socket API** (`control/server/`) for dynamic, runtime rule updates
- **`firewallctl`** client for live `block` / `unblock` / `list` / `listports` / `status` / `stats` / `clear` / `default` / `conntrack`; `--protocol` / `--dport` / `--sport` / `--action` / `--priority` / `-sock` work in any position (before or after the command)
- **Unit + integration tests** (`make test`, `make integration-test`)

### Default policy, per-rule actions & priority

```
Default policy: ALLOW  (runtime-configurable)

Matching rule:          the rule with the highest --priority wins
                        (PASS or DROP action as configured)
No matching rule:       default policy (allow => PASS, deny => DROP;
                        default-deny additionally lets ESTABLISHED
                        TCP flows pass — see "Stateful (conntrack)")
```

The firewall is **default-allow** by default and can be flipped live with
`firewallctl default allow|deny`. Every block rule (IP/CIDR or port) can carry
an `-action pass|drop` qualifier — a PASS rule acts as an allowlist override
under default-deny, while a DROP rule always wins over PASS.

When rules overlap, the **highest priority wins** deterministically (`0` if
`--priority` is omitted, `4294967295` maximum). Equal-priority ties resolve to
the **most-specific** rule within the port table (an exact
`(protocol, dport, sport)` match beats partial matches) and to **DROP** in the
IP-vs-port cross table. Non-IPv4 / unparseable packets (e.g. ARP) follow the
default policy.

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
protocol + dst port + [src port]**; it does not filter egress packets (for that
you would need TC egress, not yet implemented).

A rule can also restrict the **source port** (`--sport n`), narrowing the rule
to traffic whose sending port matches — e.g. a scan/detection tool that
connects from a fixed local port. `0` means *any* in protocol, dst port and
src port, and matching is **most-specific-first**: when rules overlap, the
datapath tries an exact `(protocol, dport, sport)` match before falling back
to partial matches (`dport` only, `sport` only, then neither) and finally to
the default policy. `listports` prints the source port when a rule has one,
e.g. `tcp/22 (sport 50000) -> 1.2.3.4 [drop] prio 0`.

`clear` removes **both** the IP blocklist and all port rules in one call.
Rule maps are anonymous kernel objects tied to the running daemon — they are
reset when the daemon exits (no persistence across runs).

### Stateful (conntrack)

A TCP-only connection table lets matched/established traffic keep flowing under
a **default-deny** policy without a stateless rule for every direction:

```
first accepted SYN        -> NEW
ACK accepted on a NEW     -> ESTABLISHED
FIN or RST accepted       -> CLOSED
any accepted packet       -> refresh last_seen
no matching rule + default-deny + ESTABLISHED flow -> PASS
```

Key properties:

- State is written **only after a PASS decision** — a dropped SYN creates no
  entry, so a spoofed ACK can never fabricate an ESTABLISHED flow.
- The table is consulted **only under default-deny** (under default-allow it
  would add cost without changing any verdict).
- Rules always win: state only matters when **no** rule matches.
- Entries live in a plain hash map keyed by the 5-tuple
  (`src, dst, sport, dport, protocol`); `cmd/firewall -ct-timeout` (default
  `5m`) runs a userspace reaper that ages idle flows out — more deterministic
  than an LRU (which would keep a dying map hot).
- `firewallctl conntrack` lists live flows, and `clear` also clears the table.

```bash
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22 --action pass  # allow control connection
sudo ./bin/firewallctl default deny                                            # then deny the rest
sudo ./bin/firewallctl conntrack
```

Limitations: tracking is IPv4 + TCP only, and state is inferred from the
**forward** 5-tuple of accepted packets — asymmetric / purely ingress traffic
(the reverse direction never transits the hook) has no entry, so it stays
subject to the rule table and default policy.

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

For the full testing toolbox — unit tests, `BPF_PROG_TEST_RUN` datapath tests, the
veth/netns sandbox, and gotchas — see 👉 **[TESTING.md](ebpf-firewall/TESTING.md)**.

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
