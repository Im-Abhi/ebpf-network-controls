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
- **Direction-aware rules** — the same rule engine runs on **ingress (XDP)** and **egress (TC/TCX)**, selected per rule with `--dir in|out|both`; egress rules match the remote destination being contacted
- **Counters / telemetry** — total, drop and pass packet/byte counters (`firewallctl stats`); ingress and egress counters kept separate
- **CO-RE** (`vmlinux.h`) – portable across kernels without compile-time headers
- **Go control plane** (`control/`)
- **Unix socket API** (`control/server/`) for dynamic, runtime rule updates
- **`firewallctl`** client for live `block` / `unblock` / `list` / `listports` / `status` / `stats` / `clear` / `default` / `conntrack`; `--protocol` / `--dport` / `--sport` / `--action` / `--priority` / `--dir in|out|both` / `-sock` work in any position (before or after the command)
- **Read-only HTTP stats API** (`control/api/`) — live `status`, `stats`, `rules` and `conntrack` over HTTP JSON, loopback by default (`-http-addr`, default `127.0.0.1:8080`); the CLI stays the only way to *change* policy
- **Unit + integration tests** (`make test`, `make integration-test`)

### Default policy, per-rule actions & priority

```
Default policy: ALLOW  (runtime-configurable)

IP-table match:        kernel LPM longest-prefix match — the single most-
                       specific prefix wins; `--priority` does NOT override
                       within the IP table (least specific -> most specific)
Matching rule:         the rule with the highest --priority wins across the
                       selected IP rule and the selected port rule (PASS or
                       DROP action as configured); equal-priority ties keep
                       the port table's most-specific match, and an IP-vs-
                       port tie resolves to DROP
No matching rule:      default policy (allow => PASS, deny => DROP;
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

One deliberate contract boundary: within the **IP table itself** the kernel's
LPM trie performs a **longest-prefix match** and returns a single winning rule,
so priority is *not* compared between overlapping CIDRs — a `/32` rule always
beats a `/8` rule for the addresses it covers, regardless of their priorities.
`--priority` only arbitrates between that one IP match and the selected port
rule, and across the port table's four specificity keys. This mirrors how the
maps descend from the original most-specific-first design; see
`bpf/firewall.c` (`ip_block_action` / `port_rule_action` / `decide`) for the
exact decision table.

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
protocol + dst port + [src port]**; it does not filter egress packets.

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

### TC egress (outbound filtering)

XDP is a **receive-side hook**, so outbound traffic needs a separate attach
point. The same rule engine is additionally compiled as a **TC egress** program
attached via TCX, giving the firewall a direction-aware policy surface:

```bash
sudo ./bin/firewall -i enp3s0 -dir both            # attach XDP ingress + TC egress
sudo ./bin/firewallctl block 6.6.6.6 --dir out     # drop outbound to 6.6.6.6
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 443 --dir out
sudo ./bin/firewallctl default deny --dir out      # drop all outbound by default
```

Egress rules operate on the remote endpoint being contacted: IP/CIDR rules are
**dst-only**, and port rules match the **remote IP + remote port** of the
outbound packet (the host's own ephemeral port is ignored — a rule that would
have hit an outbound client port is not yet supported). Ingress rules still
govern traffic *into* the host; each direction keeps its own IP, port, config
and counter maps, and per-rule selection is done with `--dir in|out|both` on
the `firewallctl` commands (`list`, `listports`, `block`, `unblock`, `default`,
`clear`). Under egress default-deny, a reverse conntrack entry lets established
replies back through the same way the ingress fast-path does. The TCX hook
requires **kernel >= 6.6**.

Non-IPv4/unparseable frames (ARP, IPv6, etc.) take only the egress default
policy, exactly as on the ingress path, so an IPv4 egress rule can never drop
them. Datapath cost under the common both-defaults-`allow` configuration:
traffic that matches no rule triggers **no conntrack or policy-map operations**
(empty maps cannot match and the state gates are skipped), but the hook is not
free — every packet pays a fixed cost of two array-map reads
(`rule_presence`, `egress_config`) plus the counter updates, and every accepted
TCP packet additionally reads the ingress default once (`firewall_config`) to
evaluate the conntrack gate. An attached egress hook therefore adds a small
constant per-packet cost under allow/allow, never a policy or conntrack lookup.

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
- State is written only when a direction's default is `deny`, so under
  ingress-`allow` + egress-`deny` an established flow refreshes `last_seen`
  only on outbound traffic — replies pass (ingress is allow) but do not
  refresh it, so an alive-but-egress-idle flow could be reaped. Under
  default-deny ingress the replies refresh it too.
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

### Read-only HTTP stats API

The daemon can expose a read-only HTTP view of the live firewall state
(`control/api/`), served over the same `server.Policy` surface the Unix-socket
control plane uses — GET-only, never mutating policy:

| Endpoint   | Returns |
| --- | --- |
| `GET /health` | `{"ok":true}` |
| `GET /status` | interface, attach mode, ingress/egress default policies, IP/port rule counts |
| `GET /stats`  | `{"ingress":{...},"egress":{...}}` total / drop / pass packet+byte counters |
| `GET /rules`  | `{"blocked_rules":[…], "port_rules":[…], "egress_rules":[…], "egress_port_rules":[…], …}` |
| `GET /conntrack` | `{"flows":[…]}` live TCP flow table |

Bind it with `-http-addr` (default `127.0.0.1:8080`; `0` or empty disables it).
It is intentionally loopback-bound by default and should stay that way:
`/rules` and `/conntrack` reveal security-relevant state, and the API provides
no authentication. Example:

```bash
sudo ./bin/firewall -i wlp0s20f3 -http-addr 127.0.0.1:8080
curl -s localhost:8080/stats
curl -s localhost:8080/conntrack
```

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
│   ├── api/             # read-only HTTP stats API
│   ├── ebpf/            # map managers, XDP + TC(TCX) lifecycle, generated bindings
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

- **TC ingress** (attach points beyond XDP / TCX egress)
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
