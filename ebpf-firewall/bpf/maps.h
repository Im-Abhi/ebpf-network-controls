#ifndef __POLICY_MAPS_BPF_H
#define __POLICY_MAPS_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define the key structure for the LPM Trie (Longest Prefix Match)
// This structure is used to store IP prefixes for efficient lookups.
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

#endif