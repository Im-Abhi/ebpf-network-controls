//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helpers.h"
#include "maps.h"

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
        // Parse IPv4 header
        int ip_type = parse_iphdr(&nh, data_end, &ip);
        if (ip_type < 0) {
            return XDP_PASS;
        }

        __u32 src = bpf_ntohl(ip->saddr);
        __u32 dst = bpf_ntohl(ip->daddr);

        // instantiate the blocklist map
        struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ip->saddr,
        };

        __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &key);

        if (blocked && *blocked) {
			bpf_printk("%u.%u.%u.%u BLOCKED!",
				(src >> 24) & 0xFF,
				(src >> 16) & 0xFF,
				(src >> 8)  & 0xFF,
                src        & 0xFF);
                return XDP_DROP;
        }
            
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
            // Parse ICMP Header
            bpf_printk("We have captured an ICMP packet");
            struct icmphdr *icmp;
            int icmp_type = parse_icmphdr(&nh, data_end, &icmp);
            if (icmp_type < 0) {
                return XDP_PASS;
            }

            bpf_printk("Type: %d", icmp->type);
            bpf_printk("Code: %d", icmp->code);
            if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
			    bpf_printk("Echo id=%d seq=%d\n",
				bpf_ntohs(icmp->un.echo.id),
				bpf_ntohs(icmp->un.echo.sequence));
			}
        } else if (ip_type == IPPROTO_TCP) {
            bpf_printk("We have captured an TCP packet");
            struct tcphdr *tcp;
            // Parse TCP header
            int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
            if (tcp_type < 0) {
                return XDP_PASS;
            }

            bpf_printk("TCP Dst Port: %d", bpf_ntohs(tcp->dest));
            bpf_printk("TCP Src Port: %d", bpf_ntohs(tcp->source));
            bpf_printk("TCP Seq: %u", bpf_ntohl(tcp->seq));
            bpf_printk("TCP Ack: %u", bpf_ntohl(tcp->ack_seq));
            bpf_printk("TCP Flags: SYN=%d ACK=%d FIN=%d", tcp->syn, tcp->ack, tcp->fin);
            bpf_printk("TCP Flags: RST=%d PSH=%d URG=%d", tcp->rst, tcp->psh, tcp->urg);

        } else if (ip_type == IPPROTO_UDP) {
            bpf_printk("We have captured a UDP packet");
            // Parse UDP header
            struct udphdr *udp;
            int udp_type = parse_udphdr(&nh, data_end, &udp);
            if (udp_type < 0) {
                return XDP_PASS;
            }

            bpf_printk("Source port: %d", bpf_ntohs(udp->source));
            bpf_printk("Destination port: %d", bpf_ntohs(udp->dest));
            bpf_printk("Length of the UDP datagram: %d", bpf_ntohs(udp->len));
            bpf_printk("Checksum for error detection: %d", bpf_ntohs(udp->check));
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
