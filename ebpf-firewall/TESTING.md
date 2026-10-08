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
| `control/ebpf` | map managers with stubbed maps: blocklist (exact + LPM + overlap + clear), port rules, egress managers (IP + port + default, presence-bit disjointness, htons port encoding), action/config parsing |
| `control/server` | socket protocol + command dispatch against a fake `Policy`: `block`/`unblock`/`list`/`clear`/`stats`/`default`/`conntrack`/`--action`/`--priority`/`--dir` (in/out/both), conntrack listing, error propagation, socket lifecycle |
| `cmd/firewallctl` | option parsing anywhere in the argument list (`-sock`, `-dir in|out|both`, `--protocol`, `--dport`, `--sport`, `--action`, `--priority`, `key=value` forms) and port/priority/direction validation |

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
- `conntrack_integration_test.go` — `ConntrackManager` List/Clear/Reap against a
  standalone 16-byte-key / 16-byte-value hash map (ages, stale reaping), using
  the same clock the datapath's `last_seen` is built on.

### Datapath tests — `datapath_integration_test.go`
Builds **raw Ethernet/IPv4/TCP/UDP frames** and injects them through
`BPF_PROG_TEST_RUN` (`prog.Run`), asserting the returned XDP verdict and counter
deltas. The program is loaded on `lo` but **not attached** — no real traffic,
fully deterministic. The 24 scenarios:

| Test | Asserts |
| --- | --- |
| `TestDatapath_DefaultAllow_Passes` | default allow + no rules → PASS |
| `TestDatapath_DefaultDeny_Drops` | default deny + no rules → DROP |
| `TestDatapath_BlockedIP_Drops` | blocked IP matched as source **or** destination → DROP |
| `TestDatapath_CIDR_Drops` | `10.0.0.0/8` block drops in-range src or dst |
| `TestDatapath_PortRule_DropsOnlyMatching` | only exact dst+proto+port matches → DROP |
| `TestDatapath_PortRule_SourcePort` | a `(dport, sport)` rule drops only exact src-port traffic; other src ports, dst ports, and UDP pass |
| `TestDatapath_PortRule_Specifity` | when a `(dport, sport)` DROP rule and a `(dport)` PASS rule overlap, the exact src-port match wins |
| `TestDatapath_PassRule_OverridesDefaultDeny` | a matched `--action pass` rule allows traffic even under default-deny |
| `TestDatapath_DropWinsOverPass` | a DROP port rule beats a PASS IP rule on the same packet |
| `TestDatapath_Priority_HigherPassOverridesBroadDrop` | higher-priority PASS beats a broad lower-priority DROP |
| `TestDatapath_Priority_HigherDropBeatsLowerPass` | higher-priority DROP beats a broader PASS |
| `TestDatapath_Priority_TieResolvesToDrop` | equal-priority IP vs port overlap → DROP |
| `TestDatapath_Priority_OverridesPortSpecificity` | higher priority beats a more-specific lower-priority rule |
| `TestDatapath_Priority_OverlappingCIDR_LongestPrefixWins` | within the IP table the LPM longest-prefix match wins: a `/32` DROP (prio 0) beats a covering `/24` PASS (prio max); priority is not compared between overlapping CIDRs |
| `TestDatapath_PortRule_EqualPriorityKeepsSpecificity` | equal-priority port overlap keeps most-specific-first matching |
| `TestDatapath_Conntrack_SpoofedAckCreatesNoState` | a dropped SYN writes no state; spoofed ACK still denied and untracked |
| `TestDatapath_Conntrack_EstablishedFlowPassesAfterRuleRemoved` | SYN→NEW, ACK→ESTABLISHED, rule removed, flow still passes via state; other flows denied |
| `TestDatapath_Conntrack_FinClosesFlow` | FIN→CLOSED; the teardown tail (a later packet on the closed flow) passes but the entry is not re-armed — it stays CLOSED |
| `TestDatapath_Conntrack_MidStreamRuleAcceptMarksEstablished` | mid-stream ACK accepted by a rule is recorded as ESTABLISHED |
| `TestDatapath_Conntrack_NotTrackedUnderDefaultAllow` | default-allow consults/never writes the conntrack map |
| `TestDatapath_Conntrack_TcpOnlyUnderDefaultDeny` | denied UDP traffic leaves no state (TCP-only) |
| `TestDatapath_NonIPv4_UsesDefault` | ARP follows the default policy |
| `TestDatapath_Malformed_UsesDefault` | truncated/unparseable frames follow the default policy |
| `TestDatapath_CountersTrackDropsAndPasses` | total/drop/pass counters increment |

Run one group without the whole suite:

```bash
sudo go test -tags integration ./control/ebpf/ -run TestDatapath -v -count=1
```

### Egress datapath tests — `egress_integration_test.go`

The same raw-frame injection through `BPF_PROG_TEST_RUN`, but against the **TC
(TCX) egress program** (loaded, not attached, on `lo`). Frames are family-swapped
so `(10.0.0.1 → 1.2.3.4)` reads as an outbound packet at the egress hook. The
scenarios mirror the ingress suite plus the hook-specific cases:

| Test | Asserts |
| --- | --- |
| `TestEgressDatapath_DefaultAllow_Passes` | default allow + no egress rules → pass |
| `TestEgressDatapath_DefaultDeny_Drops` | egress default deny + no rules → drop |
| `TestEgressDatapath_BlockedDestination_Drops` | blocked dst in egress IP LPM → drop |
| `TestEgressDatapath_CIDR_DropsByDestination` | CIDR block drops in-range dst |
| `TestEgressDatapath_PortRule_DropsOnlyMatching` | only the exact dst+proto+port (remote dst) match drops; other dsts, UDP pass |
| `TestEgressDatapath_HooksAreSeparate` | matching ingress vs egress maps: a packet passes if the *other* direction has the rule |
| `TestEgressDatapath_Conntrack_ReverseEntryPassesInboundReplies` | a reverse ESTABLISHED entry lets the reply through under egress default deny |
| `TestEgressDatapath_ClearEgress_LeavesIngress` | clearing egress maps leaves ingress rules intact |
| `TestEgressDatapath_CountersSeparate` | egress drops/passes hit the egress counter slots and ingress counters do not move |
| `TestEgressDatapath_NonIPv4FollowsDefaultPolicy` | with the egress IP presence bit primed by a `0.0.0.0/0` block, ARP/non-IPv4 frames still take only the egress default (pass under allow, drop under deny) — the IPv4 rule never catches them |

Two shared-state notes specific to the egress hook:

- **Entry age under ingress-allow + egress-deny:** an established flow refreshes
  `last_seen` on outbound packets (egress write gate) but inbound replies refresh
  it only when the *ingress* default is `deny` (ingress write gate). Under
  ingress-allow a reply-only idle flow can therefore be reaped despite being
  alive; replies still pass because ingress is allow.
- **Reverse entries start ESTABLISHED:** the first accepted outbound packet
  records its reply 5-tuple as ESTABLISHED (before the 3WHS completes) so the
  unchanged ingress exact-tuple probe passes the reply under default-deny. The
  spoofable window covers one fully-specified reply tuple that only the intended
  server can legitimately transmit.

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
sudo ./bin/firewall -i wlp0s20f3 -http-addr 127.0.0.1:8081  # HTTP API on a non-default port
sudo ./bin/firewall -i wlp0s20f3 -dir both   # also attach the TC egress hook (kernel >= 6.6)
```

In another terminal:

```bash
sudo ./bin/firewallctl status                  # interface + live default policy (ingress and egress)
sudo ./bin/firewallctl listports               # port rules with [pass]/[drop]
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22 --action pass
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22 --sport 50000   # src-port-scoped rule
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 22 --priority 100  # explicit priority
sudo ./bin/firewallctl listports               # shows tcp/22 (sport 50000) -> 1.2.3.4 [drop] prio 100
sudo ./bin/firewallctl default deny            # fallback policy on no match
sudo ./bin/firewallctl conntrack               # live TCP flow table (NEW/ESTABLISHED/CLOSED)
sudo ./bin/firewallctl clear                   # wipes IP blocklist + port rules + conntrack
sudo ./bin/firewallctl stats                   # total / drop / pass counters (ingress and egress)
```

The daemon's **egress hook** (`-dir out` / `-dir both`) runs the same rule
engine on outbound traffic via TCX — egress `block` rules match the **remote
destination** being contacted (dst-only for IP/CIDR, remote dst for port
rules):

```bash
sudo ./bin/firewallctl block 6.6.6.6 --dir out          # drop outbound to 6.6.6.6
sudo ./bin/firewallctl block 1.2.3.4 --protocol tcp --dport 443 --dir out
sudo ./bin/firewallctl list --dir both                  # ingress + egress IP rules
sudo ./bin/firewallctl default deny --dir out           # drop all outbound by default
```

The read-only HTTP API (default `127.0.0.1:8080`) mirrors the same state:

```bash
curl -s localhost:8080/health                  # {"ok":true}
curl -s localhost:8080/status                  # interface, attach mode, ingress/egress default policy + rule counts
curl -s localhost:8080/stats                   # {"ingress":{...},"egress":{...}} packet/byte counters
curl -s localhost:8080/rules                   # {"blocked_rules":[...],"port_rules":[...],"egress_rules":[...],...}
curl -s localhost:8080/conntrack               # {"flows":[...]}
```

The API is GET-only and never mutates policy — keep it loopback-bound
(`-http-addr 127.0.0.1:8080`), or disable it with `-http-addr 0`.

A daemon reaper ages idle conntrack entries out by default (`-ct-timeout 5m` in
`bin/firewall`; `-ct-timeout 0` disables it). To watch the stateful path live,
allowed a TCP connection (e.g. `ssh` to a host with a `--action pass` rule),
then `firewallctl default deny` before stopping it and reconnecting — the
established flow should keep working while a fresh connection is dropped.

> Alert: the default interface is your **Wi-Fi** (`wlp0s20f3`). A `default deny` or a
> block rule matching your own IP will cut your own inbound traffic — run policy
> experiments on a disposable test interface instead.

### Layer 3.5 — live smoke suite (root required)

`integration/fw-smoke.sh` automates the disposable-interface flow described
above. It creates a veth pair + netns, allows (and later removes) an iptables
`INPUT ACCEPT` for the host-side veth so a host firewall service (UFW) cannot
interfere, and drives real TCP through the running firewall, asserting the
documented verdicts. It also needs IPv6 disabled on the sandbox veth so netns
link-local/multicast traffic cannot inflate drop-counter deltas.

```bash
make generate && make build
sudo bash integration/fw-smoke.sh
```

Golden run: **38/38 checks**. Coverage:

| Check | What is asserted |
| --- | --- |
| 1a–1c | default-allow passthrough; conntrack empty AND skipped under allow |
| 2a–2f | full priority matrix: higher-PASS overrides broad DROP, higher-DROP beats specific PASS, equal-prio keeps the most-specific match, `listports` shows priorities |
| 3a–3c | default-deny: bare ACK denied, creates no state |
| 3d–3g | `--action pass` admits a flow; ESTABLISHED survives rule removal (stateful fast-path) |
| 3i–3j | raw SYN denied, no conntrack state |
| 3k–3l | FIN→CLOSED; the teardown tail (ACK on the CLOSED flow) passes without being dropped and without re-arming the entry (stays CLOSED) |
| 4a–4d | `clear` empties blocklist + port rules + conntrack; then a fresh SYN is denied |
| 5a–5e | `-ct-timeout 5s` reaper: flow reaped, daemon logs it, later packet denied |
| 6a–6i | egress (`-dir both`, TCX): status shows attached; default allow passes; dst-only block semantics (`block <unrelated-ip> --dir out` doesn't affect traffic; `block <dst> --dir out` fails the connection and bumps the egress drop counter); `list`/`clear --dir out` round-trip; egress `default deny` blocks outbound and `default allow` restores it. Requires kernel >= 6.6 |

The egress checks restart the daemon with `-dir both` (XDP + TCX) at the end of
the run; if the kernel lacks TCX support the daemon fails to start and CHECK 6
reports itself skipped.

Client sockets are `SO_REUSEADDR` + RST-close (`SO_LINGER=0`) so the teardown of
each connection cannot leave a TIME_WAIT port that a later check reuses. A clean
FIN teardown would also work — the datapath lets a CLOSED flow's tail pass
without re-arming it (see `ct_is_passable` / `ct_update` in `bpf/firewall.c`) —
but that keeps the negotiated 5-tuple in CLOSED until the reaper ages it out,
which could collide with a later check's ports. Hence the deliberate RST-close.

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