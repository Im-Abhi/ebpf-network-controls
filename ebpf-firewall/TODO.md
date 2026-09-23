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
- [x] Verify `make test` / `make integration-test` on a clean Linux checkout

### MTP1-C: Richer rule semantics

- [x] Protocol-based rules (`IP + protocol + destination port → DROP`)
- [x] Source-port matching (`--sport n`, 0 = any; most-specific-first across `(proto, dport, sport)`)
- [x] Explicit rule actions (PASS / DROP) — configurable per rule
- [x] Configurable default policy (ALLOW / DENY) via `firewallctl default`
- [x] Packet-level tests (BPF_PROG_TEST_RUN: blocked → DROP, allowed → PASS, CIDR → DROP, port → DROP, src-port → DROP, specificity, PASS overrides default-deny, DROP wins)
- [ ] Port-based filtering with CIDR networks (currently exact `/32` only)
- [x] Rule priority (deterministic winner when rules overlap; highest wins,
      ties: most-specific-first within the port table, IP-vs-port → DROP;
      `IP+priority` in `ldm_bindings.h`) — unit + integration tests green,
      full decision table covered live by `integration/fw-smoke.sh` (check 2)
- [ ] Direction-aware rules (INGRESS / EGRESS)

### MTP1-F: Fast-path optimization

- [x] `rule_presence` maps (IP / port) gating lookups in the XDP datapath
- [x] Empty-table: lookups skipped entirely (empty map can only miss → verdict
      identical by construction; 8 → 4 map accesses per packet)
- [x] Presence bits maintained by Go managers (set before first insert, cleared
      after last delete) and wired through the facade
- [x] Verify `make test` / `make integration-test` with the fast path enabled
- [ ] XDP hardware offload mode (offload → driver → generic cascade). Library
      exposes `link.XDPOffloadMode` (cilium/ebpf v0.22.0) but offload drivers
      don't support `BPF_MAP_TYPE_LPM_TRIE` — deferred until offload-capable NIC
      available. ~40 lines across 4 files + docs when needed.

### MTP1-D: Stateful firewall

- [x] Flow / connection state tracking (TCP-only `conntrack` hash map,
      `bpf/maps.h`; key = 5-tuple, value = `last_seen` + state)
- [x] NEW / ESTABLISHED / FIN / CLOSED states (`enum ct_state`; transitions in
      `ct_update`: first accepted SYN → NEW, ACK on NEW → ESTABLISHED,
      FIN/RST → CLOSED, mid-stream accepted packet → ESTABLISHED)
- [x] Allow established, block unexpected inbound (established flow passes
      under default-deny when no rule matches)
- [x] State written only after PASS (a dropped SYN creates nothing, so a
      spoofed ACK cannot fabricate ESTABLISHED); map consulted only under
      default-deny
- [x] Userspace reaper (`cmd/firewall -ct-timeout`, default 5m) ages out idle
      flows from the plain hash map
- [x] `firewallctl conntrack` listing; `clear` also clears conntrack
- [x] Verify `make test` / `make integration-test` on a clean Linux checkout
      (incl. the new datapath conntrack scenarios + manager tests) — plus live
      coverage in `integration/fw-smoke.sh` (checks 3–5: spoofed ACK, stateful
      fast-path after rule removal, FIN→CLOSED, clear, reaper)
- [ ] Open design note: the datapath DROPs the final teardown ACK of a flow it
      has already marked CLOSED (FIN/RST). A peer that closes cleanly therefore
      retransmits its FIN until TCP retries are exhausted, because it never
      sees an ACK for it. Verdicts are correct; the behaviour is a product
      decision to revisit (e.g. treat the ACK closing a CLOSED flow as PASS) —
      `integration/fw-smoke.sh` works around it by RST-closing clients

### MTP1-E: Benchmarking module (separate from firewall)

- [x] Benchmark harness (`benchmark/` — veth+netns sandbox, `run-bench.sh`, `make bench`)
- [x] Baseline run: XDP vs nftables full matrix (24 cells) saved + charts
- [x] Metrics: throughput, latency, CPU, memory, rule-update time
- [x] Verify measurement is the true forwarding datapath (uplink direction; XDP
      `fc_stats` counter deltas confirm data crossed the hook)
- [x] `drop` scenario: block the sandbox LAN (single `/24`), hook-side drop rate
      via XDP `fc_stats` + nft `counter` rules (exercises the DROP hot path)
- [x] Controlled (loss-free) UDP pass (`UDP_CTL_BW`, `udp2_*` columns) to isolate
      per-packet decision cost from sender saturation
- [x] Raw-UDP flood offered load for `drop` rows (`run_flood`, `flood_sent`);
      iperf3 is unusable against a DROP rule (its TCP control channel is blocked)
- [x] Preflight guard: refuse to run with a missing/stale embedded
      `firewall_bpf.o` (guards against load-time `missing map rule_presence`)
- [x] Full-matrix rerun with the drop + controlled-UDP columns; re-lock baseline
      — locked baseline is `20260914-234855` (valid TCP; supersedes
      `20260914-151138` and the TCP-invalid `20260914-230211`). Includes a
      derived CPU-cost-per-million-packets metric in `plot.py`.
- [ ] IS_UPLOAD ⇄ future `-R` / download comparisons documented in `benchmark/README.md`
- [ ] Rerun unchanged after the priority + stateful changes; document feature
      cost in `benchmark/README.md`
- [x] Results documentation — `benchmark/README.md` "Benchmark results" section
      (capture `20260914-234855`; medians + drop-path counter parity + derived
      CPU-per-M-pkts table)

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
