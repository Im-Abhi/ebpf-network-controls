#ifndef __HELPERS_H
#define __HELPERS_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* vmlinux.h exposes kernel *types* but not UAPI *macros*. These constants are
 * defined by the kernel UAPI headers (<linux/if_ether.h>, <linux/in.h>,
 * <linux/icmp.h>) which are intentionally NOT included here, so that the BPF
 * program does not depend on any distribution's installed header layout. */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr) {
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);

    if ((void*)eth + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;

    return eth->h_proto;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr) {
    struct iphdr *ip = nh->pos;
    int hdrsize;

    if ((void*)ip + sizeof(*ip) > data_end)
        return -1;

    hdrsize = ip->ihl * 4;
    if (hdrsize < sizeof(*ip))
        return -1;

    if ((void*)ip + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = ip;

    return ip->protocol;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmphdr) {
    struct icmphdr *icmp = nh->pos;
    int hdrsize = sizeof(*icmp);

    if ((void*)icmp + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *icmphdr = icmp;

    return icmp->type;
}

static __always_inline int parse_tcphdr(struct hdr_cursor *nh, void *data_end, struct tcphdr **tcphdr) {
    struct tcphdr *tcp = nh->pos;
    int hdrsize = sizeof(*tcp);

    if ((void*)tcp + hdrsize > data_end) 
        return -1;

    nh->pos += hdrsize;
    *tcphdr = tcp;

    return 0;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh, void *data_end, struct udphdr **udphdr) {
    struct udphdr *udp = nh->pos;
    int hdrsize = sizeof(*udp);

    if ((void*)udp + hdrsize > data_end) 
        return -1;

    nh->pos += hdrsize;
    *udphdr = udp;

    return 0;
}

#endif
