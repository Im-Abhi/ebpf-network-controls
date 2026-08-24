//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/helpers.h"

SEC("xdp") 
int firewall_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    nh.pos = data;

    struct ethhdr *eth;
    int eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        return XDP_PASS;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) { 
        bpf_printk("We have captured an IPv4 packet");
        struct iphdr *ip;
        int ip_type = parse_iphdr(&nh, data_end, &ip);
        if (ip_type < 0) {
            return XDP_PASS;
        }

        __u32 src = bpf_ntohl(ip->saddr);
        __u32 dst = bpf_ntohl(ip->daddr);

        bpf_printk("IPv4 src: %d.%d.%d.%d",
            (src >> 24) & 0xFF,
            (src >> 16) & 0xFF,
            (src >> 8)  & 0xFF,
            src & 0xFF);

        bpf_printk("IPv4 dst: %d.%d.%d.%d",
            (dst >> 24) & 0xFF,
            (dst >> 16) & 0xFF,
            (dst >> 8)  & 0xFF,
            dst & 0xFF);

        if (ip_type == IPPROTO_ICMP) {
            bpf_printk("We have captured an ICMP packet");
            struct icmphdr *icmp;
            int icmp_type = parse_icmphdr(&nh, data_end, &icmp);
            if (icmp_type < 0) {
                return XDP_PASS;
            }

            bpf_printk("Type: %d", icmp->type);
            bpf_printk("Code: %d", icmp->code);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
