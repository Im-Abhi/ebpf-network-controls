#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ACTION_PASS 1
#define ACTION_REDIRECT 2
#define ACTION_DROP 3

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, __u8);
} policy_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 8);
} redirect_map SEC(".maps");

SEC("tc")
int tc_packet_policy(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return ACTION_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return ACTION_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return ACTION_PASS;

    __u8 action = ACTION_PASS;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return ACTION_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        __u8 *hit = bpf_map_lookup_elem(&policy_table, &dport);
        if (hit)
            action = *hit;
    }

    if (action == ACTION_REDIRECT)
        return bpf_redirect_map(&redirect_map, 0, 0);

    return action;
}

char _license[] SEC("license") = "GPL";
