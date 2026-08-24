#ifndef __HELPERS_H
#define __HELPERS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct hdr_cursor {
    void *pos;
};

/* 
 * Helper macro for safe boundary checks 
 */
#define __always_inline inline __attribute__((always_inline))

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

#endif
