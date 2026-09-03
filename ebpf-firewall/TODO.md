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
- [x] Go map manager (`control/ebpf/maps.go`)
- [x] XDP lifecycle (load/attach/detach) (`control/ebpf/xdp.go`, `control/ebpf/firewall.go`)
- [x] Dynamic policy updates (runtime block/unblock via Unix socket)
- [x] Unix control API (`control/server/`)
- [x] `firewallctl` client
- [x] Unit + integration tests
- [x] Clean datapath (parse → packet_info → policy lookup → decision)

### MTP1-B: Observable firewall — counters

- [ ] Global counters map (total / dropped / passed packets + bytes)
- [ ] `firewallctl stats` command with human-readable output
- [ ] Counter integration tests
- [ ] Verify `make test` / `make integration-test` on a clean Linux checkout

### MTP1-C: Richer rule semantics

- [ ] Protocol-based rules (`IP + protocol → DROP`)
- [ ] Port-based filtering (`TCP + dst port 22 → DROP`)
- [ ] Explicit rule actions (PASS / DROP)
- [ ] Rule priority (deterministic winner when rules overlap)
- [ ] Direction-aware rules (INGRESS / EGRESS)
- [ ] Packet-level tests (blocked → DROP, allowed → PASS, CIDR → DROP, rule removed → PASS)

### MTP1-D: Stateful firewall

- [ ] Flow / connection state tracking
- [ ] NEW / ESTABLISHED / FIN / CLOSED states
- [ ] Allow established, block unexpected inbound

### MTP1-E: Benchmarking module (separate from firewall)

- [ ] Benchmark harness (iperf3 / pktgen scripts)
- [ ] eBPF/XDP vs nftables comparison
- [ ] Metrics: throughput, latency, CPU, memory, rule-update time
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
