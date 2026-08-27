# eBPF Firewall — Roadmap & Improvement Tasks (TODO)

This document tracks upcoming architectural refactoring, feature enhancements, and modularization tasks as the project evolves toward the full architecture described in `README.md`.

---

## 1. Package Decoupling & Modularity (User-Space)

- [x] **Rules & Validation (`control/rules/`)**
  - [x] Move `ParseIPOrCIDR()` and string sanitization into `control/rules/parser.go`.
  - [ ] Add CIDR and port range validation in `control/rules/validator.go`.
  - [ ] Define rule representations (Action: `DROP`/`PASS`, Protocol: `TCP`/`UDP`/`ICMP`, Port, IP) in `control/rules/rules.go`.

- [x] **eBPF Interactions (`control/ebpf/`)**
  - [x] Move `BlockIP()`, `UnblockIP()`, and LPM trie lookups into `control/ebpf/maps.go`.
  - [x] Keep `control/ebpf/xdp.go` focused purely on loading ELF objects and XDP link attachment.
  - [ ] Implement connection tracking state map wrappers in `control/ebpf/state.go`.
  - [ ] Implement packet/byte counter map readers in `control/ebpf/counters.go`.
  - [ ] Add TC filter attachment in `control/ebpf/tc.go`.
  - [ ] Add unified lifecycle management (graceful attach/detach of both XDP and TC) in `control/ebpf/lifecycle.go`.

---

## 2. Configuration & Policy Engine

- [ ] **YAML Policy Parser (`configs/policy.yaml`)**
  - [ ] Create YAML configuration schema for static security rules:
    ```yaml
    firewall:
      interface: "eth0"
      default_action: "PASS"
      blocklist:
        - "192.168.1.50/32"
        - "10.0.0.0/8"
      port_rules:
        - port: 23
          protocol: "TCP"
          action: "DROP"
    ```
  - [ ] Integrate YAML file watcher for live-reloading rules without restarting the process.

---

## 3. Telemetry, Metrics & Events

- [ ] **Kernel Counter Maps (`bpf/maps/state_maps.bpf.h`)**
  - [ ] Add a `BPF_MAP_TYPE_PERCPU_ARRAY` in kernel space for lockless per-CPU metrics (Total Packets, Total Bytes, Dropped Packets, Passed Packets).
  - [ ] Increment counters in `firewall.bpf.c` on each decision branch.

- [ ] **User-Space Metrics Ticker (`control/events/metrics.go`)**
  - [ ] Add a background ticker in `cmd/firewall/main.go` to periodically read and display packet stats in the terminal or export to Prometheus.

- [ ] **BPF Ring Buffer / Perf Events (`control/events/consumer.go`)**
  - [ ] Send high-priority security events (e.g. dropped attack packets) to user space via `BPF_MAP_TYPE_RINGBUF` for alerting.

---

## 4. Advanced Security Controls

- [ ] **Port-based Filtering**: Extend XDP kernel logic to check destination port maps for TCP/UDP traffic.
- [ ] **SYN-Flood Mitigation**: Implement half-open connection rate-limiting using eBPF hash maps.
- [ ] **TC Ingress/Egress Programs (`bpf/tc/`)**: Add TC filters for packet inspection where XDP isn't available or for egress traffic shaping.

---

## 5. Benchmarking & Evaluation

- [ ] Measure throughput and P99 latency using `wrk` / `iperf3` / `pktgen`.
- [ ] Benchmark comparison between eBPF/XDP drop rates vs. standard Linux `iptables` / `nftables`.
