#ifndef __POLICY_MAPS_BPF_H
#define __POLICY_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Map flags are UAPI macros (not BTF types), so vmlinux.h does not define them. */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

/* ── Rule actions ───────────────────────────────────────────────────── */
/* Values stored in rule maps encode the action to take on a match. These
 * match the Go constants in control/ebpf/action.go. */
enum rule_action {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
};

/* Value stored in both rule maps. `action` is an enum rule_action; `priority`
 * orders rules when more than one could apply to the same packet: the higher
 * priority wins. At equal priority the datapath falls back to its original
 * tie-breaks (most-specific-first within the port map; DROP across the IP and
 * port maps), so the default priority 0 reproduces the pre-priority verdicts
 * exactly. */
struct rule_value {
    __u32 action;    /* enum rule_action */
    __u32 priority;  /* higher wins; 0 = default */
};

/* ── Config map ─────────────────────────────────────────────────────── */
/* Single-entry array holding the fallback (default) policy applied when no
 * rule matches. Entry 0 of the `default_policy` sub-field is an enum
 * (0 = ALLOW/PASS, 1 = DENY/DROP). Read once per packet by the datapath. */
enum default_policy {
    DEFAULT_ALLOW = 0,
    DEFAULT_DENY  = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} firewall_config SEC(".maps");

/* ── Policy map ─────────────────────────────────────────────────────── */

struct ipv4_lpm_key {
    __u32   prefixlen;
    __u32   data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct rule_value);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 65535);
} blocked_ips SEC(".maps");

/* ── Global counters ────────────────────────────────────────────────── */

enum counter_index {
    COUNTER_TOTAL = 0,
    COUNTER_DROP  = 1,
    COUNTER_PASS  = 2,
    COUNTER_MAX   = 3,
};

struct counter_value {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct counter_value);
    __uint(max_entries, 3);
} counters SEC(".maps");

/* ── Rule-presence flags ─────────────────────────────────────────────── */
/* Single-entry array the daemon uses to tell the datapath whether each
 * policy map currently holds at least one rule. Entry 0 packs two bits:
 *   bit 0 (RULE_IP_PRESENT)   -> blocked_ips has >= 1 entry
 *   bit 1 (RULE_PORT_PRESENT) -> port_policy has >= 1 entry
 * When a bit is clear the datapath skips the (LPM/hash) lookups for that
 * map entirely, since an empty map cannot match. This preserves the exact
 * same verdicts: a lookup against an empty map can only miss, and the
 * decision falls through to the default policy in both cases.
 *
 * Ordering for correctness: the daemon SETS the relevant bit *before* the
 * first rule is inserted and CLEARS it only *after* the last entry has been
 * removed. A stale set bit costs a few lookups (all miss) but can never let
 * a live rule go unconsulted. */
#define RULE_IP_PRESENT   (1U << 0)
#define RULE_PORT_PRESENT (1U << 1)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rule_presence SEC(".maps");

/* ── Port policy map ────────────────────────────────────────────────── */
/* Finer-grained rules that combine a destination IP (exact /32), a
 * protocol, a destination port and a source port. The value is a
 * struct rule_value (action + priority). The key is the natural-alignment
 * struct below (12 bytes: proto(1) + pad(1) + dport(2) + sport(2) +
 * dst(4)), ports kept in network byte order. 0 in protocol, dport or
 * sport means "any". The datapath performs all four lookups per packet:
 *   (proto, dport, sport)  -> exact both
 *   (proto, dport, 0)      -> dport exact, sport any
 *   (proto, 0, sport)      -> dport any,  sport exact
 *   (proto, 0, 0)          -> neither restricted
 * and keeps the matching rule with the highest priority. At equal priority
 * the first (most specific) match is kept, preserving the documented
 * most-specific-first order at the default priority 0. This makes the
 * "0 = any" semantics work with an exact-key hash map while letting a
 * higher-priority rule override a more specific one (see port_rule_action
 * in firewall.c). */

struct port_rule_key {
    __u8  protocol;
    __u16 dport;   /* network byte order; 0 = any */
    __u16 sport;   /* network byte order; 0 = any */
    __u32 dst;     /* network byte order */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct rule_value);
    __uint(max_entries, 65535);
} port_policy SEC(".maps");

/* ── Conntrack map ──────────────────────────────────────────────────── */
/* TCP-only state table consulted only when the default policy is DENY, so
 * return traffic of an accepted connection keeps passing without a stateless
 * rule for every direction. Under default-allow the map is neither read nor
 * written (unmatched traffic already passes, so state would add cost for no
 * verdict change).
 *
 * Lifecycle (see ct_update in firewall.c): an entry is written ONLY after a
 * packet has been accepted, so a dropped SYN can never create state (a
 * spoofed ACK must not be able to fabricate an ESTABLISHED flow).
 *   first accepted SYN        -> NEW
 *   ACK accepted on a NEW flow-> ESTABLISHED
 *   FIN or RST accepted       -> CLOSED
 *   any accepted packet       -> last_seen refresh
 * Entries live in a plain (non-LRU) hash so the daemon can age them out
 * deterministically; cmd/firewall runs a periodic reaper keyed on last_seen
 * (control/ebpf/conntrack.go). A CLOSED entry never matches the established
 * fast-path and is removed by the reaper.
 *
 * The key/value layouts are mirrored, field for field, by ctKey/ctValue in
 * control/ebpf/values.go and must stay in sync. The explicit trailing pad
 * fields keep the byte layout identical between C and Go. */
enum ct_state {
    CT_NEW         = 1,
    CT_ESTABLISHED = 2,
    CT_CLOSED      = 3,
};

struct ct_key {
    __u32 saddr;     /* network byte order */
    __u32 daddr;     /* network byte order */
    __u16 sport;     /* network byte order */
    __u16 dport;     /* network byte order */
    __u8  protocol;  /* IPPROTO_TCP */
    __u8  _pad[3];   /* explicit padding: deterministic across C and Go */
};

struct ct_value {
    __u64 last_seen; /* bpf_ktime_get_ns() at the last accepted packet */
    __u32 state;     /* enum ct_state */
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ct_key);
    __type(value, struct ct_value);
    __uint(max_entries, 65536);
} conntrack SEC(".maps");

#endif