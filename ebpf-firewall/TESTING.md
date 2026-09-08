# Testing the eBPF firewall

This repo has several testing layers, from cheap static checks up to live traffic
against a real kernel datapath. All commands assume you are in `ebpf-firewall/`.

## Prerequisites

- Linux with eBPF support (kernel BTF) — **all datapath/integration tests require root**
  (`sudo`) or `CAP_BPF` + `CAP_NET_ADMIN`.
- Toolchain: `clang`, `llvm-strip`, `bpftool`, Go (see `INSTALLATION.md`).
- Generated bindings: `make generate` (compiles `bpf/firewall.c` and produces
  `control/ebpf/firewall_bpf.o` + `firewall_bpf.go`, embedded into the binaries).

```bash
make generate && make build
```

---

## Layer 0 — static / build checks (no root required)

```bash
go build ./...       # everything compiles
go vet ./...         # code is sane
go vet -tags integration ./control/ebpf/ ./control/server/   # integration tests also compile
```

If `make generate` fails after editing the C datapath, the error is usually a
compile problem in `bpf/firewall.c` or `bpf/maps.h`.

---

## Layer 1 — unit tests (no root required)

```bash
make test
```

Runs `go test ./control/rules/ ./control/server/ ./control/ebpf/ -count=1`.
These use in-memory fakes and never touch the kernel:

| Package | What is covered |
| --- | --- |
| `control/rules` | CIDR/IP parsing and validation |
| `control/ebpf` | map managers with stubbed maps: blocklist (exact + LPM + overlap + clear), port rules, action/config parsing |
| `control/server` | socket protocol + command dispatch against a fake `Policy`: `block`/`unblock`/`list`/`clear`/`stats`/`default`/`--action`, error propagation, socket lifecycle |
| `cmd/firewallctl` | option parsing anywhere in the argument list (`-sock`, `--protocol`, `--dport`, `--action`, `key=value` forms) and port validation |

---

## Layer 2 — integration tests (root required)

```bash
sudo make integration-test
```

Runs `sudo go test -tags integration ./control/ebpf/ ./control/server/ -count=1 -v`.
This loads the real eBPF program into the kernel and exercises the **actual C
datapath** — not just Go map writes. Groups:

### Map + manager tests (map creation/lookup only, no datapath)
- `blocklist_integration_test.go` — exact IP, LPM prefixes, overlapping CIDR,
  list/clear, invalid inputs, key encoding/BTF size.
- `portpolicy_integration_test.go` — port-rule block/list/unblock/clear
  round-trip against a real hash map, invalid inputs.

### Datapath tests — `datapath_integration_test.go`
Builds **raw Ethernet/IPv4/TCP/UDP frames** and injects them through
`BPF_PROG_TEST_RUN` (`prog.Run`), asserting the returned XDP verdict and counter
deltas. The program is loaded on `lo` but **not attached** — no real traffic,
fully deterministic. The 10 scenarios:

| Test | Asserts |
| --- | --- |
| `TestDatapath_DefaultAllow_Passes` | default allow + no rules → PASS |
| `TestDatapath_DefaultDeny_Drops` | default deny + no rules → DROP |
| `TestDatapath_BlockedIP_Drops` | blocked IP matched as source **or** destination → DROP |
| `TestDatapath_CIDR_Drops` | `10.0.0.0/8` block drops in-range src or dst |
| `TestDatapath_PortRule_DropsOnlyMatching` | only exact dst+proto+port matches → DROP |
| `TestDatapath_PassRule_OverridesDefaultDeny` | a matched `--action pass` rule allows traffic even under default-deny |
| `TestDatapath_DropWinsOverPass` | a DROP port rule beats a PASS IP rule on the same packet |
| `TestDatapath_NonIPv4_UsesDefault` | ARP follows the default policy |
| `TestDatapath_Malformed_UsesDefault` | truncated/unparseable frames follow the default policy |
| `TestDatapath_CountersTrackDropsAndPasses` | total/drop/pass counters increment |

Run one group without the whole suite:

```bash
sudo go test -tags integration ./control/ebpf/ -run TestDatapath -v -count=1
```

### Lifecycle + end-to-end
- `firewall_integration_test.go` — `NewFirewall` load, attach on `lo`,
  idempotent `Start`, and `Stop` detaching the XDP program.
- `server_integration_test.go` (`TestServer_EndToEnd`) — real Unix socket +
  real firewall: block IP, add a port rule, list, clear through the daemon.

---

## Layer 3 — live end-to-end (root required)

Start the daemon on an interface, then drive it with `firewallctl`:

```bash
sudo ./bin/firewall -i wlp0s20f3        # your interface; default is wlp0s20f3
```

In another terminal:

```bash
sudo ./bin/firewallctl status                  # interface + live default policy
sudo ./bin/firewallctl listports               # port rules with [pass]/[drop]
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22 --action pass
sudo ./bin/firewallctl default deny            # fallback policy on no match
sudo ./bin/firewallctl clear                   # wipes IP blocklist + port rules
sudo ./bin/firewallctl stats                   # total / drop / pass counters
```

> Alert: the default interface is your **Wi-Fi** (`wlp0s20f3`). A `default deny` or a
> block rule matching your own IP will cut your own inbound traffic — run policy
> experiments on a disposable test interface instead.

---

## ARP / non-IPv4 behaviour (by design)

The datapath classifies **IPv4 packets only**. Every other frame — ARP (and
other ND/ARP traffic needed for link-layer resolution), VLAN-tagged frames,
unknown EtherTypes, and truncated/malformed packets — does **not** consult the
rule maps and falls straight through to the configured **default policy**:

| default policy | ARP / non-IPv4 frames | Consequence |
| --- | --- | --- |
| `allow` | PASS | host is fully reachable at L2, normal operation |
| `deny` | DROP | host ignores ARP/NDP — peers appear offline: a client cannot resolve the firewall's MAC, so connections never even start |

This is deliberate: under default-deny, **only** explicitly allowlisted traffic
(a rule set to `--action pass`) is admitted. If link-layer reachability should
survive default-deny — e.g. ARP allowed as an unavoidable exception so peers can
still resolve the host — that requires a special-case in the datapath
(`bpf/firewall.c`), which is not currently implemented.