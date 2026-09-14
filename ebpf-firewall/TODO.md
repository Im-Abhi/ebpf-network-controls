# eBPF Firewall — Milestone Roadmap

Milestone-driven tracking for the project. MTP1 is the XDP firewall core;
MTP2+ are the thesis-level extensions built on top of it.

---

## MTP1 — XDP Firewall

### MTP1-A: Dynamic IPv4 CIDR firewall ✅

- [x] XDP program (`bpf/firewall.c`)
- [x] IPv4 header parsing (`bpf/helpers.h`)
- [x] LPM policy map (`bpf/maps.h`, `blocked_ips`)
- [x] CO-RE / `vmlinux.h`
- [x] Go map manager (`control/ebpf/blocklist.go`)
- [x] XDP lifecycle (load/attach/detach) (`control/ebpf/xdp.go`, `control/ebpf/facade.go`)
- [x] Dynamic policy updates (runtime block/unblock via Unix socket)
- [x] Unix control API (`control/server/`)
- [x] `firewallctl` client
- [x] Unit + integration tests
- [x] Clean datapath (parse → packet_info → policy lookup → decision)

### MTP1-B: Observable firewall — counters ✅

- [x] Global counters map (total / dropped / passed packets + bytes)
- [x] `firewallctl stats` command with human-readable output
- [x] Counter integration tests
- [ ] Verify `make test` / `make integration-test` on a clean Linux checkout

### MTP1-C: Richer rule semantics

- [x] Protocol-based rules (`IP + protocol + destination port → DROP`)
- [x] Source-port matching (`--sport n`, 0 = any; most-specific-first across `(proto, dport, sport)`)
- [x] Explicit rule actions (PASS / DROP) — configurable per rule
- [x] Configurable default policy (ALLOW / DENY) via `firewallctl default`
- [x] Packet-level tests (BPF_PROG_TEST_RUN: blocked → DROP, allowed → PASS, CIDR → DROP, port → DROP, src-port → DROP, specificity, PASS overrides default-deny, DROP wins)
- [ ] Port-based filtering with CIDR networks (currently exact `/32` only)
- [ ] Rule priority (deterministic winner when rules overlap)
- [ ] Direction-aware rules (INGRESS / EGRESS)

### MTP1-F: Fast-path optimization

- [x] `rule_presence` maps (IP / port) gating lookups in the XDP datapath
- [x] Empty-table: lookups skipped entirely (empty map can only miss → verdict
      identical by construction; 8 → 4 map accesses per packet)
- [x] Presence bits maintained by Go managers (set before first insert, cleared
      after last delete) and wired through the facade
- [x] Verify `make test` / `make integration-test` with the fast path enabled

### MTP1-D: Stateful firewall

- [ ] Flow / connection state tracking
- [ ] NEW / ESTABLISHED / FIN / CLOSED states
- [ ] Allow established, block unexpected inbound

### MTP1-E: Benchmarking module (separate from firewall)

- [x] Benchmark harness (`benchmark/` — veth+netns sandbox, `run-bench.sh`, `make bench`)
- [x] Baseline run: XDP vs nftables full matrix (24 cells) saved + charts
- [x] Metrics: throughput, latency, CPU, memory, rule-update time
- [x] Verify measurement is the true forwarding datapath (uplink direction; XDP
      `fc_stats` counter deltas confirm data crossed the hook)
- [ ] IS_UPLOAD ⇄ future `-R` / download comparisons documented in `benchmark/README.md`
- [ ] Rerun unchanged after stateful firewall; document feature cost
- [ ] Results documentation

---

## MTP2 — Advanced Controls

- [ ] TC ingress
- [ ] TC egress
- [ ] SYN-flood detection
- [ ] Quarantine
- [ ] Automated remediation

---

## Advanced Research

- [ ] L7 / TLS instrumentation
- [ ] Adaptive policies
- [ ] Performance evaluation write-up
