#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct bpf_lpm_trie_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_cidrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} syn_counts SEC(".maps");

SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    struct bpf_lpm_trie_key *key = data;
    key->prefixlen = 32;
    key->data[0] = ip->saddr;

    if (bpf_map_lookup_elem(&blocked_cidrs, key))
        return XDP_DROP;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        if (tcp->syn && !tcp->ack) {
            __u64 *count = bpf_map_lookup_elem(&syn_counts, &ip->saddr);
            __u64 n = count ? *count + 1 : 1;
            bpf_map_update_elem(&syn_counts, &ip->saddr, &n, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
