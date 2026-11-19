# Architecture

The firewall has two parts: an in-kernel program that filters packets, and a Go
control plane that manages it. This document explains how traffic flows through
the kernel program and how commands reach it from the command line.

---

## What this is

The kernel program does the actual filtering, packet by packet. A separate
user-space daemon runs alongside it and exposes a command API, so rules can be
added, removed and inspected at runtime without restarting or recompiling.

---

## The role of eBPF

eBPF lets a normal program run *inside the kernel* safely. The kernel verifies
the program before it runs, so it cannot crash or hang the system.

The program is attached to a hook called **XDP**, the earliest point in the
receive path — right where the NIC driver hands the packet over, **before** the
kernel builds its network-stack structures. A packet we drop at this stage never
costs the stack any work.

Because XDP sits in the receive path, it only sees packets *entering* the
interface (inbound, or forwarded through it). It cannot filter traffic the host
itself sends out. This makes the firewall an **ingress firewall by construction**
— a property of the hook, not a limitation of the implementation.

eBPF **maps** are the only memory shared between the in-kernel program and the
daemon. The datapath reads them per packet; the daemon writes to them on command.

---

## Two sides, two languages

- **Kernel-facing side — written in C.** The per-packet datapath and the
  definition of every map. It runs on *every* packet. It makes no policy
  decisions itself; it just executes the tables: parse, look up, and answer
  **DROP** or **PASS**.

- **User-facing side — written in Go.** Two programs: the long-running
  **daemon** and the short-lived **command client**. This side decides and
  applies policy. Go is used because of its mature library for loading and
  driving eBPF programs, and because spawning concurrent handlers is trivial.

- **The bridge between the sides.** The C datapath is compiled once and
  **embedded into the Go binary**, so deploying the firewall is copying a single
  executable. At build time, bindings are generated that give Go typed structs
  with a byte-identical memory layout to the C structs, so both sides agree on
  exactly what each map entry looks like. The datapath is **CO-RE**: it compiles
  against the running kernel's own type definitions (BTF), so the same binary
  works across kernels without compile-time kernel headers. Commands between the
  daemon and its client travel as **JSON over a Unix socket**.

---

## Where things live (code map)

A concept-to-file index for navigating the codebase. The kernel side is two
files; everything policy-related on the Go side funnels through one facade.

| Concept | File | Role |
|---|---|---|
| Datapath (ingress + egress) | `bpf/firewall.c` | Per-packet parse → lookup → decide, both hooks (`SEC("xdp")`, `SEC("cgroup_skb/egress")`) |
| Map definitions | `bpf/maps.h` | Every BPF map, its key/value layout, and the presence-bit contract |
| Packet parsing helpers | `bpf/helpers.h` | Ethernet/IP/TCP/UDP header stepping |
| Generated C↔Go bridge | `control/ebpf/firewall_bpf.go` | bpf2go output: embedded ELF + typed maps (regenerate via `make generate`) |
| Rule tables | `control/ebpf/tables.go` | `cidrTable` + `portTable` — the only places that encode keys and maintain presence bits; instantiated once per direction |
| Facade | `control/ebpf/facade.go` | `Firewall`: the single handle wiring four table instances, conntrack, counters, config, and both program lifecycles |
| Conntrack | `control/ebpf/conntrack.go` | Flow table listing/clearing and the idle-flow reaper |
| Counters / default policy | `control/ebpf/counters.go`, `config.go` | Reading the counter map; setting the per-direction fallback policy |
| Program lifecycle | `control/ebpf/xdp.go`, `tc.go` | Load/attach/detach of XDP (driver→generic fallback) and cgroup/skb egress |
| Control server | `control/server/server.go` | Unix-socket JSON API; one `handle*` method per command |
| Wire protocol | `control/server/protocol.go` | Request/Response JSON shapes |
| HTTP observability | `control/api/api.go` | Read-only `GET /health /status /stats /rules /conntrack` |
| CLI client | `cmd/firewallctl/main.go` | Flag-anywhere parsing (`cliOptions`), request building, human-readable output |
| Daemon entry point | `cmd/firewall/main.go` | Flags, attach, seeding, reaper, socket + HTTP startup, shutdown order |
| IP/CIDR parsing | `control/rules/parser.go` | Shared IPv4/CIDR validation |

The layering rule to keep in mind: `cmd/*` and `control/server`/`control/api`
talk only to the `Firewall` facade; the facade talks only to tables and
managers; tables (`tables.go`) are the only code that knows map key encodings;
`firewall_bpf.go` is generated and never hand-edited.

---

## How a packet is handled

The eBPF program is attached to the chosen interface and fires on every incoming
packet:

1. **Parse.** It steps through the headers and pulls out only the fields it
   cares about: source IP, destination IP, protocol (TCP/UDP/other),
   destination port, source port, and TCP flags.

2. **Look up.** It asks two tables held in kernel memory:

   - The **IP/CIDR blocklist** — "does this source address (or, as a fallback,
     the destination) fall inside a blocked prefix?"
   - The **port-rule table** — "is there a rule for this destination IP +
     protocol + destination/source port?" Here `0` in a port means *any*, so a
     single rule can cover a whole range of matching packets. Rules are probed
     most-specific first and the first hit wins: `(protocol, dport, sport)` →
     `(protocol, dport)` → `(protocol, sport)` → `(protocol)` → default policy.

   Empty tables are skipped entirely (a lookup against an empty table can only
   miss), and the daemon keeps a small flag so a map with rules in it is never
   accidentally bypassed.

3. **Decide.** A matched **DROP** always wins over a matched **PASS**. If
   nothing matched, the **default policy** applies — allow everything by default,
   which can be flipped to deny-everything at runtime. That gives two operating
   modes without reloading the program: default-allow is **blocklist mode**
   (rules forbid specific traffic), default-deny is **allowlist mode** (rules are
   explicit permits and everything else is dropped). Non-IPv4 or unparseable
   packets follow the default policy too.

4. **Act.** **DROP** throws the packet away right there, before the network
   stack ever sees it. **PASS** lets it continue into the stack normally.

## Egress: cgroup/skb and the domain blocklist

Egress enforcement does **not** ride a TC/TCX classifier: on the development
kernel TC egress never fires for TCP data packets (verified live — only
control packets reached the hook), so a TC-based egress stage silently passes
the very traffic it must filter. The egress program is therefore a
`BPF_CGROUP_INET_EGRESS` cgroup/skb program attached at the root cgroup and
scoped to the daemon's `-i` interface through the `egress_meta` map (an
unwritten 0 processes every interface — the state before attach, and under
`BPF_PROG_TEST_RUN`, whose synthetic skbs carry ifindex 0).

Two consequences of the hook shape shape the datapath:

- **The cgroup/skb context is L3** — `skb->data` starts at the IP header, no
  Ethernet — so egress parses with the L3 cursor variants.
- **Outbound TCP payload lives in paged fragments**, so
  `data_end - tcp - hlen` reads 0 for data packets; the payload length comes
  from `skb->len` and the stream is read through `bpf_skb_load_bytes`.

### Domain stage (URL filtering)

Web-bound TCP streams carry their destination name in the clear: the HTTP
`Host` header (port 80) and the TLS SNI extension (port 443, ClientHello).
The egress program extracts the name and probes the **domain blocklist**, an
LPM trie keyed by the *reversed* hostname with its length in bits — so a
parent suffix is a byte prefix of the reversed name and one longest-prefix
lookup covers subdomains (`sub.example.com` matches a stored
`example.com`). The extraction walks run over `bpf_loop()` to fit the
verifier's 1M instruction budget, and a ClientHello split across TCP segments
(modern ones are ~2 KB with post-quantum key shares) is parsed as a fragment:
the SNI sits in segment 1.

A hit is an unconditional DROP, before rules, priorities and the default
policy. Full URL *path* filtering is impossible without TLS termination
(MITM) — hostnames are the clear-text ceiling, and ECH / QUIC (HTTP/3) fail
open by design.

### Retransmission fence

Dropping the SNI segment is not enough: TCP retransmits the ClientHello
re-segmented, and the continuations fail per-packet parsing open — the blocked
handshake would complete anyway. When a ClientHello matches the blocklist the
flow is recorded in the `blocked_flows` LRU map and every later packet of that
flow is dropped without re-parsing. The fence dies with the connection: a SYN
on the tuple (fresh attempt on a recycled port) or an RST clears it, a bare
FIN passes with the fence armed, and there is **no expiry on purpose** — a TTL
would let a patient client's retransmitted ClientHello complete the blocked
handshake. Teardown is passed through so the peer can reclaim its socket (an
undelivered FIN/RST wedges a serial acceptor in `SSL_accept` forever).

---

## How a command reaches the firewall

The daemon and the client are two separate programs on the same machine. They
talk over a **Unix socket** — a file that behaves like a pipe. The flow for a
command:

```
firewallctl block 1.2.3.4 --protocol tcp --dport 22
        │
        ▼
client opens the socket, writes one JSON request
        │
        ▼
daemon (listening on that socket) reads it
        │
        ▼
daemon converts the rule into a key, writes one entry into the port-rule
table, marks the table as populated, replies {"ok":true}
        │
        ▼
client prints the reply and exits
```

The next packet arriving at the NIC immediately hits the new rule. The daemon
never touches the packet program directly — it only edits the tables the program
reads.

If the daemon is killed, everything disappears with it: the socket stops
listening, the program detaches from the interface, and the tables are gone.
There is no persistence across runs.

## The goroutine server

Once the daemon starts, several things run in parallel:

- **The listen loop** keeps watching the socket for new clients and replies to
  them as they arrive, so several clients can be served at once without blocking
  each other.
- **A single manager object** owns all the kernel tables and applies every
  incoming command to the right one — keeping the knowledge of how a rule maps
  to a table key in one place.

## Command reference

| Command | What it does |
|---|---|
| `status` | the interface, the effective attach mode, the default policy, and how many rules exist |
| `list` | blocked IPs/CIDRs with their action |
| `listports` | protocol/port rules with their action |
| `block <ip/cidr>` | add an IP rule, or with `--protocol/--dport/--sport` a port rule (default action drop) |
| `unblock <ip/cidr>` | remove an IP rule, or with the same qualifiers a port rule |
| `default allow\|deny` | switch the fallback policy live |
| `clear` | wipe every rule in one call |
| `stats` | packet and byte counters |
| `help` | usage |

A rule can also carry `--action pass` — an allow-list override that lets
specific traffic through even under a deny-by-default policy.

---

## Lifecycle

**Startup.** The daemon resolves the interface, loads the embedded datapath into
the kernel, and attaches it. It first tries **native (driver) mode** — the
program runs inside the NIC driver, which is the fast path. If the driver does
not support that (some virtual interfaces don't), it **falls back to generic
(SKB) mode**, which works everywhere but is slower. The effective mode is
reported in `status`. Then it opens the Unix socket and waits for commands.

**Shutdown.** On Ctrl+C the daemon first stops accepting new commands, then
detaches the program from the interface and releases the kernel resources — so
nothing can slip through while it is tearing down.