#ifndef __POLICY_MAPS_BPF_H
#define __POLICY_MAPS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* Map flags are UAPI macros (not BTF types), so vmlinux.h does not define them. */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

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

#endif