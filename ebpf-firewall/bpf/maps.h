#ifndef __POLICY_MAPS_BPF_H
#define __POLICY_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Map flags are UAPI macros (not BTF types), so vmlinux.h does not define them. */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

/* ── Rule actions ───────────────────────────────────────────────────── */
/* Values stored in rule maps encode the action to take on a match. These
 * match the Go constants in control/ebpf/action.go. */
enum rule_action {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
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
    __type(value, __u32);
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

/* ── Port policy map ────────────────────────────────────────────────── */
/* Finer-grained rules that combine a destination IP (exact /32), a
 * protocol, a destination port and a source port. The value is a
 * rule_action (0 = PASS, 1 = DROP). The key is the natural-alignment
 * struct below (12 bytes: proto(1) + pad(1) + dport(2) + sport(2) +
 * dst(4)), ports kept in network byte order. 0 in protocol, dport or
 * sport means "any". The datapath performs up to four lookups per packet,
 * most-specific first:
 *   (proto, dport, sport)  -> exact both
 *   (proto, dport, 0)      -> dport exact, sport any
 *   (proto, 0, sport)      -> dport any,  sport exact
 *   (proto, 0, 0)          -> neither restricted
 * The first key that exists in the map decides the rule action (see
 * port_rule_action in firewall.c). This makes the "0 = any" semantics
 * actually work with an exact-key hash map. */

struct port_rule_key {
    __u8  protocol;
    __u16 dport;   /* network byte order; 0 = any */
    __u16 sport;   /* network byte order; 0 = any */
    __u32 dst;     /* network byte order */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, __u32);
    __uint(max_entries, 65535);
} port_policy SEC(".maps");

#endif