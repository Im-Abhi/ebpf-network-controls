# eBPF Firewall — Milestone Roadmap

Milestone-driven tracking for the project. MTP1 is the current XDP firewall core;
MTP2+ are the thesis-level extensions built on top of it.

---

## MTP1 — XDP Firewall (current core)

Implemented:

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

Remaining:

- [ ] `make test` / `make integration-test` workflow verified on a clean Linux checkout
- [ ] Packet-level tests (blocked → DROP, allowed → PASS, CIDR match → DROP, rule removed → PASS)
- [ ] Final README/documentation pass

## MTP2 — Advanced Controls

- [ ] Protocol/port policy (e.g. `TCP + dst port 22 → DROP`)
- [ ] TC ingress
- [ ] TC egress
- [ ] Flow/connection state tracking
- [ ] Counters / telemetry (packet & byte stats)
- [ ] SYN-flood detection
- [ ] Quarantine
- [ ] Automated remediation

## Advanced Research

- [ ] L7 / TLS instrumentation
- [ ] Performance evaluation (throughput, P99 latency) vs iptables/nftables
- [ ] Benchmarking tooling (wrk / iperf3 / pktgen)