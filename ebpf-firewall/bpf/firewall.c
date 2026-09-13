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
 *     3. policy lookups: blocked_ips LPM trie + port_policy hash,
 *        each returning a rule_action (PASS or DROP)
 *     4. decision (data-driven, see decision_table below)
 *
 * Decision table (deterministic, DROP takes precedence):
 *   any matched rule action == DROP      -> DROP
 *   else any matched rule action == PASS -> PASS
 *   else (no rule matched by any lookup) -> default policy
 *   unparseable / non-IPv4               -> default policy
 *
 * The default policy is read from the `firewall_config` map (entry 0 =
 * DEFAULT_ALLOW or DEFAULT_DENY). A matched DROP always wins, so adding an
 * explicit block stays effective even under a default-allow policy. An
 * explicit PASS rule takes effect only for traffic it matches, permitting
 * exactly that traffic under a default-deny policy.
 *
 * Debugging (optional, compile-time): protocol/port inspection and
 * bpf_printk logging are compiled out unless FIREWALL_DEBUG is defined.
 * Keep debugging off for performance-sensitive measurements so tracing
 * does not pollute the datapath.
 */

#ifdef FIREWALL_DEBUG
#define DEBUG_PRINTK(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINTK(fmt, ...) do { } while (0)
#endif

/* Minimal parsed view of an IPv4 packet, sufficient for the current
 * IP/CIDR policy plus protocol/port rules. Extended later with direction
 * for richer rules without touching the datapath control flow. */
struct packet_info {
    __u32 saddr;   /* network byte order */
    __u32 daddr;   /* network byte order */
    __u8  protocol;
    __u16 dport;   /* destination port, network byte order (0 if not TCP/UDP) */
    __u16 sport;   /* source port, network byte order (0 if not TCP/UDP) */
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

    /* Capture source/destination ports for TCP/UDP so port rules can match. */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (parse_tcphdr(nh, data_end, &tcp) == 0) {
            info.dport = tcp->dest;
            info.sport = tcp->source;
        }
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp;
        if (parse_udphdr(nh, data_end, &udp) == 0) {
            info.dport = udp->dest;
            info.sport = udp->source;
        }
    }

    *ok = 1;
    return info;
}

/* Policy lookup for the IP blocklist. Returns the rule_action stored for the
 * longest-prefix LPM match on the source address, falling back to the
 * destination address' match. Checks source first, then destination. Both keys
 * use the same 8-byte LPM layout with the address in network byte order,
 * matching the Go side (control/ebpf/blocklist.go). */
static __always_inline int ip_block_action(const struct packet_info *info,
                                           enum rule_action *out_action) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = info->saddr,
    };

    __u32 *elem = bpf_map_lookup_elem(&blocked_ips, &key);
    if (!elem) {
        key.data = info->daddr;
        elem = bpf_map_lookup_elem(&blocked_ips, &key);
    }

    if (!elem) {
        *out_action = ACTION_PASS;
        return 0;
    }

    *out_action = (enum rule_action)*elem;
    return 1;
}

/* Port-policy lookup. Matches protocol + source/destination port against
 * the destination address. Ports are optional: a stored rule with dport or
 * sport == 0 means "any" for that field, so the datapath tries the rules in
 * specificity order and returns the action of the first key that exists:
 * (proto, dport, sport) -> (proto, dport, 0) -> (proto, 0, sport) ->
 * (proto, 0, 0). The key carries addresses/ports in network byte order,
 * matching the Go side (control/ebpf/portpolicy.go). Returns 1 + action on
 * a match, 0 if no rule covers the packet. */
static __always_inline int port_rule_action(const struct packet_info *info,
                                            enum rule_action *out_action) {
    struct port_rule_key key;
    __u32 *elem;

    /* Zero the whole key, including padding. The hash comparison covers all
     * 12 bytes of the struct and the Go side stores zero padding, so any
     * stale stack bytes here (e.g. leftover from the LPM key that shares the
     * same stack slots) would make every lookup miss. */
    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = info->protocol;
    key.dport = info->dport;
    key.sport = info->sport;
    key.dst = info->daddr;

#define TRY_LOOKUP(d, s)                                        \
    do {                                                        \
        key.dport = (d);                                        \
        key.sport = (s);                                        \
        elem = bpf_map_lookup_elem(&port_policy, &key);         \
        if (elem) {                                             \
            *out_action = (enum rule_action)*elem;              \
            return 1;                                           \
        }                                                       \
    } while (0)

    TRY_LOOKUP(info->dport, info->sport);   /* exact dport + exact sport */
    TRY_LOOKUP(info->dport, 0);             /* exact dport + any sport */
    TRY_LOOKUP(0,         info->sport);     /* any dport + exact sport */
    TRY_LOOKUP(0,         0);               /* any dport + any sport */

#undef TRY_LOOKUP

    *out_action = ACTION_PASS;
    return 0;
}

/* Reads the configured default policy from the config map. Falls back to
 * DEFAULT_ALLOW if the entry is absent. */
static __always_inline enum default_policy default_policy(void) {
    __u32 key = 0;
    __u32 *policy = bpf_map_lookup_elem(&firewall_config, &key);
    if (!policy) {
        return DEFAULT_ALLOW;
    }
    return (enum default_policy)*policy;
}

/* Applies the decision table. DROP from any matched rule wins; otherwise PASS
 * from any matched rule; otherwise the configured default policy. */
static __always_inline int decide(int ip_matched, enum rule_action ip_action,
                                  int port_matched, enum rule_action port_action) {
    if (ip_matched && ip_action == ACTION_DROP) {
        return XDP_DROP;
    }
    if (port_matched && port_action == ACTION_DROP) {
        return XDP_DROP;
    }
    if (ip_matched && ip_action == ACTION_PASS) {
        return XDP_PASS;
    }
    if (port_matched && port_action == ACTION_PASS) {
        return XDP_PASS;
    }
    return default_policy() == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
}

/* Global counter increment. Looks up the counter by index and atomically
 * adds 1 packet and the given byte count. Must match struct counter_value
 * and enum counter_index in maps.h. */
static __always_inline void incr_counter(__u32 idx, __u64 bytes) {
    struct counter_value *val = bpf_map_lookup_elem(&counters, &idx);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    }
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
    __u64 pkt_len = (__u64)(data_end - data);

    /* 1. parse */
    int ok;
    struct packet_info info = parse_packet(&nh, data_end, &ok);
    if (!ok) {
        /* Unparseable or non-IPv4: apply the default policy. */
        int verdict = default_policy() == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
        incr_counter(COUNTER_TOTAL, pkt_len);
        if (verdict == XDP_DROP) {
            incr_counter(COUNTER_DROP, pkt_len);
        } else {
            incr_counter(COUNTER_PASS, pkt_len);
        }
        return verdict;
    }

    /* 2. policy lookups, each returning an action */
    enum rule_action ip_action, port_action;
    int ip_matched = ip_block_action(&info, &ip_action);
    int port_matched = port_rule_action(&info, &port_action);

    /* 3. decision (data-driven; DROP wins, else PASS, else default) */
    int verdict = decide(ip_matched, ip_action, port_matched, port_action);
    if (verdict == XDP_DROP) {
        DEBUG_PRINTK("packet DROPPED");
        incr_counter(COUNTER_TOTAL, pkt_len);
        incr_counter(COUNTER_DROP, pkt_len);
        return XDP_DROP;
    }

    /* 4. optional debugging (compiled out with FIREWALL_DEBUG undefined) */
    debug_packet(&info, &nh, data_end);

    /* 5. passed: matching PASS rule or default allow */
    incr_counter(COUNTER_TOTAL, pkt_len);
    incr_counter(COUNTER_PASS, pkt_len);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
