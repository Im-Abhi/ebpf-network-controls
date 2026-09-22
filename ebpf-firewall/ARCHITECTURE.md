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