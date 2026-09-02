//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helpers.h"
#include "maps.h"

/*
 * eBPF XDP dataplane for the firewall.
 *
 * Datapath (fixed, always runs):
 *     1. parse packet headers
 *     2. build packet_info (src/dst address, protocol)
 *     3. policy lookup (blocked_ips LPM trie)
 *     4. decision: DROP if the packet matched the blocklist, else PASS
 *
 * Debugging (optional, compile-time): protocol/port inspection and
 * bpf_printk logging are compiled out unless FIREWALL_DEBUG is defined.
 * Keep debugging off for performance-sensitive measurements so tracing
 * does not pollute the datapath.
 *
 * Default policy: ALLOW
 *   matching blocked_ips: DROP
 *   no matching policy:   PASS
 */

#ifdef FIREWALL_DEBUG
#define DEBUG_PRINTK(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINTK(fmt, ...) do { } while (0)
#endif

/* Minimal parsed view of an IPv4 packet, sufficient for the current
 * IP/CIDR policy. Extended later with protocol/port/direction for richer
 * rules without touching the datapath control flow. */
struct packet_info {
    __u32 saddr;   /* network byte order */
    __u32 daddr;   /* network byte order */
    __u8  protocol;
};

static __always_inline struct packet_info parse_packet(struct hdr_cursor *nh,
                                                       void *data_end,
                                                       int *ok) {
    struct packet_info info = {};
    *ok = 0;

    struct ethhdr *eth;
    int eth_type = parse_ethhdr(nh, data_end, &eth);
    if (eth_type < 0) {
        return info;
    }

    /* Only IPv4 is policy-relevant in the current implementation. */
    if (eth_type != bpf_htons(ETH_P_IP)) {
        return info;
    }

    struct iphdr *ip;
    int protocol = parse_iphdr(nh, data_end, &ip);
    if (protocol < 0) {
        return info;
    }

    info.saddr = ip->saddr;
    info.daddr = ip->daddr;
    info.protocol = protocol;
    *ok = 1;
    return info;
}

/* Policy lookup + decision. Currently: block traffic to OR from a blocked
 * address. Checks source first, then destination. Both keys use the same
 * 8-byte LPM layout with the address in network byte order, matching the
 * Go side (control/ebpf/maps.go). */
static __always_inline int is_blocked(const struct packet_info *info) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = info->saddr,
    };

    __u32 *blocked = bpf_map_lookup_elem(&blocked_ips, &key);

    if (!(blocked && *blocked)) {
        key.data = info->daddr;
        blocked = bpf_map_lookup_elem(&blocked_ips, &key);
    }

    return blocked && *blocked;
}

static __always_inline void debug_packet(const struct packet_info *info,
                                         struct hdr_cursor *nh,
                                         void *data_end) {
    __u32 src = bpf_ntohl(info->saddr);
    __u32 dst = bpf_ntohl(info->daddr);

    DEBUG_PRINTK("IPv4 src: %d.%d.%d.%d",
        (src >> 24) & 0xFF, (src >> 16) & 0xFF,
        (src >> 8)  & 0xFF,  src        & 0xFF);
    DEBUG_PRINTK("IPv4 dst: %d.%d.%d.%d",
        (dst >> 24) & 0xFF, (dst >> 16) & 0xFF,
        (dst >> 8)  & 0xFF,  dst        & 0xFF);

    if (info->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp;
        if (parse_icmphdr(nh, data_end, &icmp) < 0) {
            return;
        }
        DEBUG_PRINTK("ICMP type: %d code: %d", icmp->type, icmp->code);
        if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
            DEBUG_PRINTK("ICMP echo id=%d seq=%d",
                bpf_ntohs(icmp->un.echo.id),
                bpf_ntohs(icmp->un.echo.sequence));
        }
    } else if (info->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (parse_tcphdr(nh, data_end, &tcp) < 0) {
            return;
        }
        DEBUG_PRINTK("TCP src port: %d dst port: %d",
            bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        DEBUG_PRINTK("TCP seq: %u ack: %u", bpf_ntohl(tcp->seq), bpf_ntohl(tcp->ack_seq));
        DEBUG_PRINTK("TCP flags: SYN=%d ACK=%d FIN=%d RST=%d", tcp->syn, tcp->ack, tcp->fin, tcp->rst);
    } else if (info->protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        if (parse_udphdr(nh, data_end, &udp) < 0) {
            return;
        }
        DEBUG_PRINTK("UDP src port: %d dst port: %d", bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
    }
}

SEC("xdp")
int firewall_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    nh.pos = data;

    /* 1. parse */
    int ok;
    struct packet_info info = parse_packet(&nh, data_end, &ok);
    if (!ok) {
        /* Unparseable or non-IPv4: default allow. */
        return XDP_PASS;
    }

    /* 2. policy lookup + decision */
    if (is_blocked(&info)) {
        DEBUG_PRINTK("packet BLOCKED");
        return XDP_DROP;
    }

    /* 3. optional debugging (compiled out with FIREWALL_DEBUG undefined) */
    debug_packet(&info, &nh, data_end);

    /* 4. default policy: allow */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
