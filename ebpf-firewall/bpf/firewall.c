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
 *        each returning a rule_value (action + priority)
 *     4. decision (data-driven, see decision_table below)
 *
 * Decision table (deterministic, highest priority wins):
 *   matched rules exist -> action of the highest-priority match; at equal
 *                          priority the port table keeps its most specific
 *                          match, and a tie between an IP rule and a port
 *                          rule resolves to DROP
 *   no rule matched     -> default policy
 *   unparseable/non-IPv4-> default policy
 *
 * Within the IP table the kernel's LPM trie decides which entry matches
 * (longest prefix); `priority` only orders an IP match against a port
 * match, or against another port rule. Rules are stored as struct
 * rule_value (see maps.h); priority 0 is the default and reproduces the
 * pre-priority behaviour.
 *
 * The default policy is read from the `firewall_config` map (entry 0 =
 * DEFAULT_ALLOW or DEFAULT_DENY). A matched DROP can be overridden only by
 * a higher-priority PASS, so an explicit block stays effective against
 * equal- or lower-priority permits. An explicit PASS rule takes effect
 * only for traffic it matches, permitting exactly that traffic under a
 * default-deny policy.
 *
 * Stateful fast-path (TCP-only, default-deny only): an accepted TCP packet
 * records/refreshes its flow in the `conntrack` map (see ct_update), and a
 * later packet with no matching rule passes if its flow is ESTABLISHED.
 * State is written only after a PASS decision, so a dropped SYN creates
 * nothing and a spoofed ACK cannot fabricate an established flow.
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

/* TCP flag bits used for conntrack transitions. vmlinux.h exposes the
 * tcphdr flag bitfields but not these masks (UAPI macros). */
#ifndef TCP_FIN
#define TCP_FIN 0x01
#endif
#ifndef TCP_SYN
#define TCP_SYN 0x02
#endif
#ifndef TCP_RST
#define TCP_RST 0x04
#endif
#ifndef TCP_ACK
#define TCP_ACK 0x10
#endif

/* IPv4 fragment indications in iphdr.frag_off (network byte order): the MF
 * (more-fragments) bit plus the 13-bit fragment offset. The separate DF
 * (don't-fragment) bit 0x4000 is deliberately not part of the mask — a normal
 * unfragmented packet may set DF. */
#define IP_FRAG_MASK 0x3FFF

/* Minimal parsed view of an IPv4 packet, sufficient for the current
 * IP/CIDR policy plus protocol/port rules. Extended later with direction
 * for richer rules without touching the datapath control flow. */
struct packet_info {
    __u32 saddr;   /* network byte order (IPv4 only; 0 for IPv6) */
    __u32 daddr;   /* network byte order (IPv4 only; 0 for IPv6) */
    __u8  protocol;
    __u8  family;  /* 4 = IPv4, 6 = IPv6 (egress domain stage only), 0 = unknown */
    __u16 dport;   /* destination port, network byte order (0 if not TCP/UDP) */
    __u16 sport;   /* source port, network byte order (0 if not TCP/UDP) */
    __u8  tcp_flags; /* TCP_FIN/SYN/RST/ACK bits (0 if not TCP) */
};

static __always_inline struct packet_info parse_packet_x(struct hdr_cursor *nh,
                                                         void *data_end,
                                                         int *ok, bool l2) {
    struct packet_info info = {};
    *ok = 0;

    /* L2 (XDP) frames start at the Ethernet header; the cgroup/skb egress
     * hook hands the program an skb whose data points at the L3 (IP)
     * header — reached here only after the caller dispatched on the IP
     * version, so this function is the IPv4 path by construction. */
    int eth_type = bpf_htons(ETH_P_IP);
    if (l2) {
        struct ethhdr *eth;
        eth_type = parse_ethhdr(nh, data_end, &eth);
        if (eth_type < 0) {
            return info;
        }
        /* IPv6 frames at ingress stay non-policy-relevant (default
         * policy): the domain stage is egress-only, and the v4 tables
         * never matched v6 anyway. */
        if (eth_type != bpf_htons(ETH_P_IP)) {
            return info;
        }
    }

    struct iphdr *ip;
    int protocol = parse_iphdr(nh, data_end, &ip);
    if (protocol < 0) {
        return info;
    }

    info.saddr = ip->saddr;
    info.daddr = ip->daddr;
    info.protocol = protocol;
    info.family = 4;

    /* Fragmented IPv4: only the first piece carries a real L4 header, so a
     * port/state decision here would be inconsistent across the pieces.
     * Fragments are therefore not policy-relevant — like non-IPv4 frames they
     * take only the default policy and never write conntrack state. */
    if (ip->frag_off & bpf_htons(IP_FRAG_MASK)) {
        return info;
    }

    /* Capture source/destination ports for TCP/UDP so port rules can match. */
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;
        if (parse_tcphdr(nh, data_end, &tcp) == 0) {
            info.dport = tcp->dest;
            info.sport = tcp->source;
            info.tcp_flags = (tcp->fin ? TCP_FIN : 0) |
                             (tcp->syn ? TCP_SYN : 0) |
                             (tcp->rst ? TCP_RST : 0) |
                             (tcp->ack ? TCP_ACK : 0);
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

/* Locate the L4 payload offset in an IPv6 header chain (L3 context, skb
 * offsets): returns 1 with the offset of the first L4 byte and the final
 * protocol when the chain ends in TCP or UDP; 0 for fragments, AH,
 * no-next, unknown next-headers and anything unreadable — none of which
 * are policy-relevant. Bounded to 8 extension headers. Every read is a
 * helper load: runtime-checked, non-linear-safe, and free of the direct
 * pointer arithmetic this datapath must avoid (see domain_tcp_payload). */
static __always_inline int v6_l4_offset(struct __sk_buff *skb,
                                        __u32 *l4_off_out, __u8 *proto_out) {
    __u8 nhdr = 0;
    __u32 off = sizeof(struct ipv6hdr);

    if (bpf_skb_load_bytes(skb, 6, &nhdr, 1)) /* next-header of the fixed header */
        return 0;

    for (int i = 0; i < 8; i++) {
        __u8 h[2];
        if (nhdr == IPPROTO_TCP || nhdr == IPPROTO_UDP) {
            *l4_off_out = off;
            *proto_out = nhdr;
            return 1;
        }
        /* hop-by-hop(0), routing(43), destination options(60) */
        if (nhdr != 0 && nhdr != 43 && nhdr != 60)
            return 0;
        if (bpf_skb_load_bytes(skb, off, h, 2))
            return 0;
        nhdr = h[0];
        off += 8 + (__u32)h[1] * 8; /* ext len is in 8-octet units past 8 */
    }
    return 0;
}

/* IPv6 L3 parse for the cgroup/skb egress hook. Policy scope for v6 is the
 * domain stage only: the IP/CIDR and port tables (and conntrack) have
 * IPv4-shaped keys, so v6 packets carry no addresses into the policy
 * stages. Ports and TCP flags are read via helper loads after the bounded
 * extension-header walk; a truncated L4 header is not policy-relevant. */
static __always_inline struct packet_info parse_packet_l3_v6(struct __sk_buff *skb,
                                                             int *ok) {
    struct packet_info info = {};
    __u32 l4_off = 0;
    __u8 proto = 0;
    __u8 b[2];

    *ok = 0;
    if (!v6_l4_offset(skb, &l4_off, &proto)) {
        return info;
    }
    info.family = 6;
    info.protocol = proto;

    if (proto == IPPROTO_TCP) {
        __u8 flags;
        if (bpf_skb_load_bytes(skb, l4_off, b, 2))
            return info; /* truncated TCP header: not policy-relevant */
        info.sport = ((__u16)b[0] << 8) | (__u16)b[1];
        if (bpf_skb_load_bytes(skb, l4_off + 2, b, 2))
            return info;
        info.dport = ((__u16)b[0] << 8) | (__u16)b[1];
        if (bpf_skb_load_bytes(skb, l4_off + 13, &flags, 1))
            return info;
        info.tcp_flags = ((flags & 0x01) ? TCP_FIN : 0) |
                         ((flags & 0x02) ? TCP_SYN : 0) |
                         ((flags & 0x04) ? TCP_RST : 0) |
                         ((flags & 0x10) ? TCP_ACK : 0);
    } else if (proto == IPPROTO_UDP) {
        if (bpf_skb_load_bytes(skb, l4_off + 2, b, 2))
            return info;
        info.dport = ((__u16)b[0] << 8) | (__u16)b[1];
        if (bpf_skb_load_bytes(skb, l4_off, b, 2))
            return info;
        info.sport = ((__u16)b[0] << 8) | (__u16)b[1];
    }
    *ok = 1;
    return info;
}

/* L3-context dispatch for the cgroup/skb egress hook: the version nibble
 * selects the family parse. The version byte is a helper load like every
 * other read on this path — direct packet dereferences in this datapath
 * repeatedly trip the verifier (see the bcur/domain comments). The v4
 * path keeps direct header reads, which the verifier has accepted since
 * the first smoke run. */
static __always_inline struct packet_info parse_packet_l3(struct __sk_buff *skb,
                                                          void *data, void *data_end,
                                                          int *ok) {
    __u8 first = 0;

    *ok = 0;
    if (bpf_skb_load_bytes(skb, 0, &first, 1)) {
        return (struct packet_info){};
    }
    if ((first >> 4) == 6) {
        return parse_packet_l3_v6(skb, ok);
    }
    if ((first >> 4) != 4) {
        return (struct packet_info){};
    }
    struct hdr_cursor nh = { data };
    return parse_packet_x(&nh, data_end, ok, false);
}

/* Policy lookup for the IP blocklist. Returns the rule_value stored for the
 * longest-prefix LPM match on the source address, falling back to the
 * destination address' match. Checks source first, then destination. Both keys
 * use the same 8-byte LPM layout with the address in network byte order,
 * matching the Go side (control/ebpf/blocklist.go). Returns 1 and fills *out
 * on a match, 0 if neither address matched. */
static __always_inline int ip_block_action(const struct packet_info *info,
                                           struct rule_value *out) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = info->saddr,
    };

    struct rule_value *elem = bpf_map_lookup_elem(&blocked_ips, &key);
    if (!elem) {
        key.data = info->daddr;
        elem = bpf_map_lookup_elem(&blocked_ips, &key);
    }

    if (!elem) {
        return 0;
    }

    *out = *elem;
    return 1;
}

/* Port-policy lookup. Matches protocol + source/destination port against
 * the destination address. Ports are optional: a stored rule with dport or
 * sport == 0 means "any" for that field, so the datapath probes all four
 * specificity keys:
 * (proto, dport, sport) -> (proto, dport, 0) -> (proto, 0, sport) ->
 * (proto, 0, 0), and keeps the matching rule with the highest priority. At
 * equal priority the first (most specific) probed match is kept, preserving
 * the documented most-specific-first behaviour exactly at the default
 * priority 0; only a strictly higher priority replaces it. The key carries
 * addresses/ports in network byte order, matching the Go side
 * (control/ebpf/portpolicy.go). Returns 1 and fills *out on a match, 0 if
 * no rule covers the packet. */
static __always_inline int port_rule_action(const struct packet_info *info,
                                            struct rule_value *out) {
    struct port_rule_key key;
    struct rule_value *elem;
    struct rule_value best = {};
    int matched = 0;

    /* Zero the whole key, including padding. The hash comparison covers all
     * 12 bytes of the struct and the Go side stores zero padding, so any
     * stale stack bytes here (e.g. leftover from the LPM key that shares the
     * same stack slots) would make every lookup miss. */
    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = info->protocol;
    key.dport = info->dport;
    key.sport = info->sport;
    key.dst = info->daddr;

    /* Replace the current best only when the candidate has a strictly higher
     * priority. Keys are probed most-specific first, so an equal-priority
     * candidate never displaces an earlier, more specific match. */
#define TRY_LOOKUP(d, s)                                        \
    do {                                                        \
        key.dport = (d);                                        \
        key.sport = (s);                                        \
        elem = bpf_map_lookup_elem(&port_policy, &key);         \
        if (elem && (!matched || elem->priority > best.priority)) { \
            best = *elem;                                       \
            matched = 1;                                        \
        }                                                       \
    } while (0)

    TRY_LOOKUP(info->dport, info->sport);   /* exact dport + exact sport */
    TRY_LOOKUP(info->dport, 0);             /* exact dport + any sport */
    TRY_LOOKUP(0,         info->sport);     /* any dport + exact sport */
    TRY_LOOKUP(0,         0);               /* any dport + any sport */

#undef TRY_LOOKUP

    if (!matched) {
        return 0;
    }

    *out = best;
    return 1;
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

/* Applies the decision table across the (at most two) matched rules. The
 * highest priority wins; an equal-priority tie between an IP rule and a port
 * rule resolves to DROP (the pre-priority behaviour). With no match the
 * configured default policy applies. */
static __always_inline int decide(int ip_matched, const struct rule_value *ip,
                                  int port_matched, const struct rule_value *port) {
    if (ip_matched && port_matched) {
        if (ip->priority != port->priority) {
            const struct rule_value *winner =
                ip->priority > port->priority ? ip : port;
            return winner->action == ACTION_DROP ? XDP_DROP : XDP_PASS;
        }
        /* Equal priority: DROP wins if either side is a DROP. */
        if (ip->action == ACTION_DROP || port->action == ACTION_DROP) {
            return XDP_DROP;
        }
        return XDP_PASS;
    }
    if (ip_matched) {
        return ip->action == ACTION_DROP ? XDP_DROP : XDP_PASS;
    }
    if (port_matched) {
        return port->action == ACTION_DROP ? XDP_DROP : XDP_PASS;
    }
    return default_policy() == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
}

/* Builds the conntrack key for a parsed packet. Zeroes the whole struct,
 * including the padding bytes, so the hash lookup matches the key written by
 * the Go side / the previous packet. */
static __always_inline void ct_build_key(struct ct_key *key,
                                         const struct packet_info *info) {
    __builtin_memset(key, 0, sizeof(*key));
    key->saddr = info->saddr;
    key->daddr = info->daddr;
    key->sport = info->sport;
    key->dport = info->dport;
    key->protocol = info->protocol;
}

/* Read-only conntrack probe for the stateful fast-path gate. Returns 1 when
 * the packet's 5-tuple is in a passable state: ESTABLISHED (an ongoing flow
 * keeps flowing once its rule is removed) or CLOSED (the tail of a teardown —
 * the peer's closing replies and final ACKs — must not be dropped). A CLOSED
 * entry is never re-armed: it passes, but ct_update refuses to refresh it, so
 * it drains until the reaper ages it out.
 * Returns 0 for NEW, empty and never-seen tuples (a bare spoofed ACK cannot
 * fabricate a flow through this gate). */
static __always_inline int ct_is_passable(const struct packet_info *info) {
    struct ct_key key;
    ct_build_key(&key, info);
    struct ct_value *v = bpf_map_lookup_elem(&conntrack, &key);
    return v && (v->state == CT_ESTABLISHED || v->state == CT_CLOSED);
}

/* Records an accepted TCP packet. Called only after a PASS decision, so a
 * dropped SYN never creates state (and a subsequent spoofed ACK cannot
 * fabricate an ESTABLISHED flow). Transitions: SYN -> NEW, ACK on NEW ->
 * ESTABLISHED, FIN/RST -> CLOSED, every accepted packet refreshes last_seen.
 * A CLOSED entry is left completely untouched: the flow is draining (see the
 * ct_is_passable gate) and must not be re-armed or kept alive indefinitely. */
static __always_inline void ct_update(const struct packet_info *info) {
    struct ct_key key;
    ct_build_key(&key, info);
    __u64 now = bpf_ktime_get_ns();

    struct ct_value *v = bpf_map_lookup_elem(&conntrack, &key);
    if (v) {
        if (v->state == CT_CLOSED) {
            return;
        }
        v->last_seen = now;
        if (info->tcp_flags & (TCP_FIN | TCP_RST)) {
            v->state = CT_CLOSED;
        } else if (v->state == CT_NEW && (info->tcp_flags & TCP_ACK)) {
            v->state = CT_ESTABLISHED;
        }
        return;
    }

    struct ct_value nv = {};
    nv.last_seen = now;
    if (info->tcp_flags & (TCP_FIN | TCP_RST)) {
        nv.state = CT_CLOSED;
    } else if (info->tcp_flags & TCP_SYN) {
        nv.state = CT_NEW;
    } else {
        /* Mid-stream packet accepted by a rule: treat the flow as already
         * established so its return traffic is covered too. */
        nv.state = CT_ESTABLISHED;
    }
    bpf_map_update_elem(&conntrack, &key, &nv, BPF_ANY);
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
    struct packet_info info = parse_packet_x(&nh, data_end, &ok, true);
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

    /* 2. policy lookups, each returning an action. The rule_presence flags
     * short-circuit the lookups when the corresponding map is empty (an empty
     * map can only miss, so the decision is identical); the daemon keeps the
     * flags conservative (set before first insert, cleared only after the last
     * delete) so a live rule is never skipped. */
    __u32 zero = 0;
    __u32 *presence = bpf_map_lookup_elem(&rule_presence, &zero);
    __u32 flags = presence ? *presence : 0;

    struct rule_value ip_rule = {}, port_rule = {};
    int ip_matched = 0, port_matched = 0;
    if (flags & RULE_IP_PRESENT) {
        ip_matched = ip_block_action(&info, &ip_rule);
    }
    if (flags & RULE_PORT_PRESENT) {
        port_matched = port_rule_action(&info, &port_rule);
    }

    /* 3. decision (data-driven; highest priority wins, tie -> DROP, else
     * default). Under default-deny a TCP packet belonging to a passable flow
     * (ESTABLISHED, or a CLOSED flow draining out) is also let through when no
     * rule matches; the stateful fast-path is meaningless (and skipped) under
     * default-allow. */
    enum default_policy def = default_policy();
    int verdict;
    if (ip_matched || port_matched) {
        verdict = decide(ip_matched, &ip_rule, port_matched, &port_rule);
    } else if (def == DEFAULT_DENY && info.protocol == IPPROTO_TCP &&
               ct_is_passable(&info)) {
        verdict = XDP_PASS;
    } else {
        verdict = def == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
    }
    if (verdict == XDP_DROP) {
        DEBUG_PRINTK("packet DROPPED");
        incr_counter(COUNTER_TOTAL, pkt_len);
        incr_counter(COUNTER_DROP, pkt_len);
        return XDP_DROP;
    }

    /* 4. accepted: record/refresh TCP state. Must run only on PASS, never on
     * DROP, so a dropped SYN leaves no state behind. Only tracked under
     * default-deny, where the state actually changes future verdicts; a
     * CLOSED flow is skipped (draining, never re-armed). */
    if (def == DEFAULT_DENY && info.protocol == IPPROTO_TCP) {
        ct_update(&info);
    }

    /* 5. optional debugging (compiled out with FIREWALL_DEBUG undefined) */
    debug_packet(&info, &nh, data_end);

    /* 6. passed: matching PASS rule, established flow, or default allow */
    incr_counter(COUNTER_TOTAL, pkt_len);
    incr_counter(COUNTER_PASS, pkt_len);
    return XDP_PASS;
}

/* ══ Cgroup egress datapath ───────────────────────────────────────────
 * Second hook: a cgroup/skb (BPF_CGROUP_INET_EGRESS) program filtering
 * host-generated outbound traffic. The XDP program (firewall_prog) is
 * receive-side only and stays byte-for-byte unchanged; this program is a
 * separate SEC("cgroup_skb/egress") section in the same object so both
 * directions share the policy and conntrack maps.
 *
 * Why cgroup/skb and not TC (clsact/tcx): on the development kernel,
 * TC egress hooks never fire for TCP data packets (SYN/ACK/FIN and
 * ICMP/UDP do), which silently disabled URL filtering — the blocklist
 * needs the GET/ClientHello payload. The cgroup egress hook runs at L3
 * (ip_output) and sees every packet, TCP data included, on every kernel
 * (no TCX 6.6 floor either). Verified by experiment: 2 curls — tc egress
 * counters moved by 0 data bytes; cgroup egress counted 6 >100B packets
 * (the GETs and 200-OKs).
 *
 * Hook semantics (different from the old TC classifier):
 *   - the hook sees the WHOLE host's outbound traffic, so the datapath
 *     gates every packet on skb->ifindex (egress_meta entry 0, written
 *     by the daemon at attach) to stay scoped to -i <iface>; other
 *     interfaces pass untouched at zero policy cost beyond the gate;
 *   - verdicts are 1 = pass, 0 = drop (cgroup semantics), not the TC
 *     action codes.
 *
 * Direction semantics (deliberately different from ingress):
 *   - egress_blocked_ips  -> matches the packet DESTINATION only; the source
 *     is always the local host, so matching it would self-poison traffic.
 *   - egress_port_policy  -> key.dst is the remote destination being reached.
 *   - egress_config       -> independent egress default policy.
 *   - counters 3-5        -> egress total/drop/pass (ingress keeps 0-2).
 *   - rule_presence 2-3   -> egress IP/port presence (bits 0-1 are XDP's).
 *
 * Stateful fast path: the single `conntrack` map is shared with the ingress
 * program and is consulted/updated only when the gate holds (EGRESS default
 * DENY OR ingress default DENY) - i.e. only when a state change could flip a
 * future verdict. The probe looks up both the exact (outbound) tuple and its
 * reverse. New outbound flows create the REVERSE (reply) entry as ESTABLISHED
 * so that the unchanged ingress datapath - which only ever does an
 * exact-tuple lookup - passes the reply under a default-deny ingress.
 * Documented tradeoff: a reply tuple is "established" before the 3WHS ends,
 * but that window covers exactly one fully-specified reply tuple that only
 * the intended server can legitimately transmit.
 *
 * The program reads only data/data_end from __sk_buff (never skb->len or any
 * other field) so BPF_PROG_TEST_RUN can drive it with synthesized packets.
 * Non-IPv4/unparseable frames (ARP, IPv6, VLAN) take only the egress default
 * policy, exactly like the ingress program, so an IPv4 rule can never catch
 * them.
 */

/* Build the reverse (reply) conntrack key: swap src/dst address and port so
 * an outbound packet can find the entry created for its reply direction.
 * Zeroes padding exactly like ct_build_key. */
static __always_inline void ct_build_reverse_key(struct ct_key *key,
                                                 const struct packet_info *info) {
    __builtin_memset(key, 0, sizeof(*key));
    key->saddr = info->daddr;
    key->daddr = info->saddr;
    key->sport = info->dport;
    key->dport = info->sport;
    key->protocol = info->protocol;
}

/* cgroup/skb verdict mapping: 1 = pass, 0 = drop. The datapath reasons in
 * XDP verdicts internally (XDP_DROP/XDP_PASS) and maps at the exits. */
static __always_inline int cg_action(int verdict) {
    return verdict == XDP_DROP ? 0 : 1;
}

static __always_inline enum default_policy egress_default_policy(void) {
    __u32 key = 0;
    __u32 *policy = bpf_map_lookup_elem(&egress_config, &key);
    if (!policy) {
        return DEFAULT_ALLOW;
    }
    return (enum default_policy)*policy;
}

/* Egress IP blocklist: destination-only LPM lookup on egress_blocked_ips. */
static __always_inline int egress_ip_block_action(const struct packet_info *info,
                                                  struct rule_value *out) {
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = info->daddr,
    };

    struct rule_value *elem = bpf_map_lookup_elem(&egress_blocked_ips, &key);
    if (!elem) {
        return 0;
    }

    *out = *elem;
    return 1;
}

/* Egress port-policy lookup: same most-specific-first precedence and
 * priority tie-break as the ingress engine, but against egress_port_policy.
 * The probe macro is duplicated (renamed) rather than parameterized so that
 * firewall_prog's codegen is untouched. */
static __always_inline int egress_port_rule_action(const struct packet_info *info,
                                                   struct rule_value *out) {
    struct port_rule_key key;
    struct rule_value *elem;
    struct rule_value best = {};
    int matched = 0;

    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = info->protocol;
    key.dport = info->dport;
    key.sport = info->sport;
    key.dst = info->daddr;

#define TRY_EGRESS_LOOKUP(d, s)                                         \
    do {                                                                \
        key.dport = (d);                                                \
        key.sport = (s);                                                \
        elem = bpf_map_lookup_elem(&egress_port_policy, &key);          \
        if (elem && (!matched || elem->priority > best.priority)) {     \
            best = *elem;                                               \
            matched = 1;                                                \
        }                                                               \
    } while (0)

    TRY_EGRESS_LOOKUP(info->dport, info->sport);
    TRY_EGRESS_LOOKUP(info->dport, 0);
    TRY_EGRESS_LOOKUP(0,          info->sport);
    TRY_EGRESS_LOOKUP(0,          0);

#undef TRY_EGRESS_LOOKUP

    if (!matched) {
        return 0;
    }

    *out = best;
    return 1;
}

/* Shared state probe for egress: a passable state — ESTABLISHED, or CLOSED
 * draining out — on the exact (outbound) tuple or its reverse, so the tail of
 * a teardown in either direction is not dropped (see the ingress gate). */
static __always_inline int ct_is_passable_egress(const struct packet_info *info) {
    struct ct_key key;
    struct ct_value *v;

    ct_build_key(&key, info);
    v = bpf_map_lookup_elem(&conntrack, &key);
    if (v && (v->state == CT_ESTABLISHED || v->state == CT_CLOSED)) {
        return 1;
    }

    ct_build_reverse_key(&key, info);
    v = bpf_map_lookup_elem(&conntrack, &key);
    return v && (v->state == CT_ESTABLISHED || v->state == CT_CLOSED);
}

/* Gate: decide whether egress may consult/write conntrack for this packet.
 * True only for TCP when EITHER direction's default is DENY - a state change
 * could then flip some future verdict. With both defaults ALLOW no state can
 * matter and the datapath stays off the state reads/writes (mirrors the XDP
 * datapath's default-allow gate). */
static __always_inline int ct_active_egress(const struct packet_info *info,
                                            enum default_policy def_egress) {
    if (info->protocol != IPPROTO_TCP) {
        return 0;
    }
    if (def_egress == DEFAULT_DENY) {
        return 1;
    }

    __u32 key = 0;
    __u32 *policy = bpf_map_lookup_elem(&firewall_config, &key);
    return policy && *policy == DEFAULT_DENY;
}

/* Record an accepted outbound TCP packet in the shared conntrack map.
 * Orientation resolution, exact then reverse - each refreshed with the same
 * transitions as the ingress side (FIN/RST -> CLOSED, ACK on NEW ->
 * ESTABLISHED). A CLOSED entry in either orientation is left completely
 * untouched (draining flow, never re-armed). A brand-new outbound flow is
 * stored under its REVERSE (reply) tuple as ESTABLISHED so the unchanged
 * ingress path passes the reply under default-deny (see the section note). */
static __always_inline void ct_update_egress(const struct packet_info *info) {
    struct ct_key exact;
    struct ct_key rev;
    struct ct_value *v;
    struct ct_value nv = {};
    __u64 now = bpf_ktime_get_ns();
    __u32 close = info->tcp_flags & (TCP_FIN | TCP_RST);

    ct_build_key(&exact, info);
    ct_build_reverse_key(&rev, info);

    v = bpf_map_lookup_elem(&conntrack, &exact);
    if (v) {
        if (v->state == CT_CLOSED) {
            return;
        }
        v->last_seen = now;
        if (close) {
            v->state = CT_CLOSED;
        } else if (v->state == CT_NEW && (info->tcp_flags & TCP_ACK)) {
            v->state = CT_ESTABLISHED;
        }
        return;
    }

    v = bpf_map_lookup_elem(&conntrack, &rev);
    if (v) {
        if (v->state == CT_CLOSED) {
            return;
        }
        v->last_seen = now;
        if (close) {
            v->state = CT_CLOSED;
        } else if (v->state == CT_NEW && (info->tcp_flags & TCP_ACK)) {
            v->state = CT_ESTABLISHED;
        }
        return;
    }

    nv.last_seen = now;
    nv.state = close ? CT_CLOSED : CT_ESTABLISHED;
    bpf_map_update_elem(&conntrack, &rev, &nv, BPF_ANY);
}

/* Egress counter increment (indices 3-6; ingress keeps 0-2). Index 6 is
 * the domain-drop tally, a subset of the generic egress drop count. */
static __always_inline void incr_egress_counter(__u32 idx, __u64 bytes) {
    struct counter_value *val = bpf_map_lookup_elem(&counters, &idx);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, bytes);
    }
}

static __always_inline void count_egress(int verdict, __u64 bytes) {
    if (verdict == XDP_DROP) {
        incr_egress_counter(COUNTER_EGRESS_TOTAL, bytes);
        incr_egress_counter(COUNTER_EGRESS_DROP, bytes);
    } else {
        incr_egress_counter(COUNTER_EGRESS_TOTAL, bytes);
        incr_egress_counter(COUNTER_EGRESS_PASS, bytes);
    }
}

/* ══ Domain blocklist (URL filtering) — egress only ════════════════════
 * Third policy surface: hostname rules, loaded from a blocklist file by
 * the daemon into domain_blocklist (see maps.h). A destination name
 * appears in cleartext on the wire exactly once per connection — the TLS
 * ClientHello's server_name (SNI) extension on port 443, or the HTTP
 * Host header on port 80 — and this stage extracts it and probes the map.
 *
 * Scope decisions (all deliberate):
 *   - Egress only: the stage lives in firewall_cgroup_egress; the XDP
 *     (ingress) datapath is untouched.
 *   - A hit is an unconditional DROP that precedes the rule/default
 *     decision: the blocklist is an explicit deny, not a priority
 *     participant.
 *   - Suffix matching via LPM: names are stored REVERSED in an LPM trie,
 *     so a parent suffix is a byte prefix of the reversed name and one
 *     longest-prefix-match lookup covers a whole domain tree
 *     (cdn.badsite.com -> badsite.com) without data-dependent probing.
 *   - The gate (presence bit + TCP + port 443/80 + payload + !SYN) keeps
 *     the per-packet cost at zero unless web-bound traffic is on the wire
 *     with a loaded blocklist.
 * Known gaps: a ClientHello split across TCP segments, raw-IP TLS,
 * QUIC/HTTP-3 (UDP), ECH-encrypted SNI, and names beyond the scanned
 * window — those connections fail open and fall through to the ordinary
 * rule/default path; never a false drop. The stream is read by skb offset
 * through bpf_skb_load_bytes rather than by packet pointer: the payload
 * offset varies with the IP/TCP header lengths, a packet pointer with a
 * variable offset cannot be range-verified beyond one byte, and stack
 * copies hit the same wall (protocol-declared skip lengths make a stack
 * cursor's offset unbounded). Helper loads are runtime-bounds-checked, so
 * the parsing needs no verifier-visible bounds at all, and the reads also
 * reach paged fragments that direct data/data_end access cannot.
 */

/* Byte reader over the outbound stream, addressed by skb offset and read
 * through bpf_skb_load_bytes. The payload start varies with the IP/TCP
 * header lengths, so no packet pointer can carry a verifier-usable range
 * here (a packet pointer with a variable offset proves only one readable
 * byte against data_end), and stack copies hit the same wall: the skips
 * are protocol-declared lengths, which make a stack cursor's offset
 * unbounded too. Helper loads are runtime-bounds-checked, so the parsing
 * logic needs no verifier-visible bounds at all, and a load past the
 * linear area simply fails open. Every accessor proves the read against
 * `left` (the protocol + packet cap) before touching the wire. */
struct bcur {
    __u32 off;     /* absolute skb offset of the next byte */
    __u32 left;
};



static __always_inline int bcur_take8(struct __sk_buff *skb, struct bcur *c, __u8 *out) {
    if (c->left < 1)
        return 0;
    if (bpf_skb_load_bytes(skb, c->off, out, 1))
        return 0;
    c->off++;
    c->left--;
    return 1;
}

static __always_inline int bcur_take16(struct __sk_buff *skb, struct bcur *c, __u16 *out) {
    __u8 b[2];
    if (c->left < 2)
        return 0;
    if (bpf_skb_load_bytes(skb, c->off, b, 2))
        return 0;
    *out = ((__u16)b[0] << 8) | (__u16)b[1];
    c->off += 2;
    c->left -= 2;
    return 1;
}

static __always_inline int bcur_take24(struct __sk_buff *skb, struct bcur *c, __u32 *out) {
    __u8 b[3];
    if (c->left < 3)
        return 0;
    if (bpf_skb_load_bytes(skb, c->off, b, 3))
        return 0;
    *out = ((__u32)b[0] << 16) | ((__u32)b[1] << 8) | (__u32)b[2];
    c->off += 3;
    c->left -= 3;
    return 1;
}

static __always_inline int bcur_skip(struct bcur *c, __u32 n) {
    if (c->left < n)
        return 0;
    c->off += n;
    c->left -= n;
    return 1;
}

/* Match `name` (an skb-offset hostname of `len` bytes) against
 * domain_blocklist. The name is lowercased, REVERSED into the LPM key and
 * looked up once: storing names reversed makes a parent suffix a byte
 * prefix of the reversed name, so the single longest-prefix-match lookup
 * covers subdomains (see maps.h) with no data-dependent probing — the
 * verifier's state budget cannot afford a probe per possible dot position.
 * Returns 1 on a hit. */
#define DOMAIN_NAME_MAX   63   /* lpm_domain_key.name holds 64 bytes */

static __always_inline int domain_block_action(struct __sk_buff *skb, __u32 name_off, __u32 len) {
    struct lpm_domain_key key;
    __u8 ch;
    __u32 w;

    if (len == 0)
        return 0;
    if (len > DOMAIN_NAME_MAX)
        len = DOMAIN_NAME_MAX;   /* same truncation contract as the loader */

    __builtin_memset(&key, 0, sizeof(key));
    key.prefixlen = len * 8;
    /* The WRITE index is the loop induction itself (a precise value at
     * every verifier step); the mirrored read index (len-1-w) only feeds
     * the runtime-checked helper, which needs no verifier-visible bounds.
     * Writing key.name[len-1-i] instead leaves the stack-write offset
     * with a signed range dipping below zero, which the verifier rejects
     * as an unbounded variable-offset write. */
    for (w = 0; w < len; w++) {
        __u32 rd = len - 1 - w;
        if (bpf_skb_load_bytes(skb, name_off + rd, &ch, 1))
            return 0;                       /* load past the stream: fail open */
        if (ch >= 'A' && ch <= 'Z')
            ch += 32;                       /* lowercase */
        key.name[w] = ch;
    }
    return bpf_map_lookup_elem(&domain_blocklist, &key) != NULL;
}

/* Extract the server_name (SNI) from a TLS ClientHello carried whole in
 * this segment. Returns 1 and sets (*out_off, *out_len) to the name's skb
 * offset and length; 0 when anything is malformed, truncated, or simply
 * not a ClientHello. Every level of the walk is bounded by the protocol's
 * own declared lengths (record body, handshake body, extension block, name
 * list) on top of the packet bound, so bytes outside a declared structure
 * are never interpreted as part of it. */
static __always_inline int tls_sni_extract(struct __sk_buff *skb, __u32 pbase,
                                           __u32 plen, __u32 *out_off, __u32 *out_len) {
    struct bcur c = { pbase, plen };
    __u8 content, hs_type, sid_len, comp_len;
    __u16 ver, rec_len, cs_len, ext_len, ext_i;
    __u32 hs_len;

    if (!bcur_take8(skb, &c, &content) || content != 0x16)   /* handshake record */
    return 0;
    if (!bcur_take16(skb, &c, &ver))                     /* record version */
        return 0;
    if (!bcur_take16(skb, &c, &rec_len) || rec_len < 4) {
        return 0;
    }
    /* Bound what follows to the record's declared body: bytes beyond
     * rec_len belong to another record and must never be parsed as part
     * of this handshake. A record claiming more than the packet carries
     * is left alone; the handshake-length check below rejects the
     * split-ClientHello case. */
    if (rec_len < c.left)
        c.left = rec_len;
    if (!bcur_take8(skb, &c, &hs_type) || hs_type != 0x01) {  /* ClientHello */
        return 0;
    }
    if (!bcur_take24(skb, &c, &hs_len))
    return 0;
    /* The handshake body may legitimately span TCP segments (a modern
     * ClientHello with post-quantum key shares exceeds the MSS), so a
     * hs_len larger than this segment's remainder is NOT an abort: the
     * extension walk below is bounded by the segment's bytes, and the
     * SNI — almost always the FIRST extension — sits well inside the
     * first segment. Clamping to the shorter of the two keeps a short
     * record from reading into the next one; a record truncated at the
     * segment boundary fails the bcur reads later (fail open, never a
     * false drop). */
    if (hs_len < c.left)                                 /* bound to the   */
        c.left = hs_len;                                 /* handshake body */
    if (!bcur_take16(skb, &c, &ver))                     /* client version */
        return 0;
    if (!bcur_skip(&c, 32))                              /* random */
        return 0;
    if (!bcur_take8(skb, &c, &sid_len) || !bcur_skip(&c, sid_len))
        return 0;
    if (!bcur_take16(skb, &c, &cs_len) || !bcur_skip(&c, cs_len))
        return 0;
    if (!bcur_take8(skb, &c, &comp_len) || !bcur_skip(&c, comp_len))
        return 0;
    if (!bcur_take16(skb, &c, &ext_len) || ext_len > c.left)  /* ext block must
                                                                 end the body */
        return 0;
    c.left = ext_len;                                    /* walk ends where the
                                                            extension block ends */
    for (ext_i = 0; ext_i < 32; ext_i++) {
        __u16 et, el;
        if (!bcur_take16(skb, &c, &et) || !bcur_take16(skb, &c, &el))
            return 0;
        if (el > c.left) {
            return 0;
        }
        if (et == 0x0000) {                              /* server_name */
            struct bcur e = { c.off, el };
            __u16 list_len, nl;
            __u8 name_type;
            if (!bcur_take16(skb, &e, &list_len)) {
                return 0;
            }
            /* the name list must fill the extension exactly (single
             * HostName entry, as every real client encodes it) — this
             * also pins the name inside the declared list */
            if (list_len != el - 2)
            return 0;
            if (!bcur_take8(skb, &e, &name_type) || name_type != 0) {
                return 0;
            }
            if (!bcur_take16(skb, &e, &nl) || nl == 0 || nl > e.left) {
                return 0;
            }
            *out_off = e.off;
            *out_len = nl;
            return 1;
        }
        if (!bcur_skip(&c, el))
        return 0;
    }
    return 0;
}

/* Extract the Host header value from an outbound HTTP/1.x request: a
 * bounded scan of the first HTTP_HOST_SCAN_MAX bytes for a line starting
 * with "Host:" (case-insensitive, preceded by a newline or at offset 0).
 * Strips any :port suffix and one trailing dot. Reads go through
 * bpf_skb_load_bytes (see struct bcur); the value walk runs under
 * bpf_loop (host_value_cb), which needs kernel >= 5.17 — well below the
 * TCX (>= 6.6) this stage's hook already requires.
 *
 * Verifier structural rules (each was a real 1M processed-insn failure):
 *   - No comparison against plen inside any loop. An `idx >= plen` guard
 *     refines plen's minimum every iteration (taking the body proves
 *     plen > idx), so no two iterations share a state, nothing prunes and
 *     every position is simulated from scratch. Loop bounds are static
 *     constants; out-of-stream reads are the helper's own runtime check.
 *   - The value extraction stays OUTSIDE the scan and the match breaks.
 *     A match at position i otherwise lets the verifier reach the full
 *     extraction from every one of the HTTP_HOST_SCAN_MAX positions (the
 *     five compare bytes are independent unknowns), multiplying the whole
 *     walk by the scan length.
 *   - The walk itself runs under bpf_loop so its per-byte branches are
 *     verified once, not once per reaching path (see host_value_cb).
 * A load past the stream ends the scan/walk (fail open when nothing was
 * found) where the old guards returned or broke at the plen boundary; on
 * a fragmented skb the helper fails before plen, so the walk stops early
 * instead of aborting an already-found match — strictly more enforcement,
 * never less. */
#define HTTP_HOST_SCAN_MAX 128

/* Value-extraction walk for the Host header, driven through bpf_loop():
 * the helper verifies the callback body ONCE, so the whole walk costs a
 * constant ~30 processed insns regardless of trip count. This is what
 * keeps the extractor inside the kernel's 1M processed-insn budget: the
 * scan can match at any of the HTTP_HOST_SCAN_MAX positions and every
 * match reaches the walk carrying its own (hit) state — with a plain
 * loop the walk's per-byte branches were re-explored 128 times (measured:
 * 1000001 insns, max_states_per_insn 131). The callback skips leading
 * blanks, reads to the end of the line (CR/LF or payload end) and records
 * the first ':' (port separator) branchlessly. Trip cap: 16 blank slots
 * plus DOMAIN_NAME_MAX value bytes; the datapath probe truncates names to
 * DOMAIN_NAME_MAX anyway (domain_block_action), so the LPM lookup key is
 * identical to the old longer walk. */
struct host_val_ctx {
    struct __sk_buff *skb;
    __u32 pbase;     /* payload start (absolute skb offset) */
    __u32 vstart;    /* value start, relative to pbase (advances past blanks) */
    __u32 vlen;      /* value length (0 = still skipping blanks) */
    __u32 colon;     /* first ':' offset within the value, +1 (0 = none) */
};

static u64 host_value_cb(u64 index, u64 ctx_u64)
{
    struct host_val_ctx *c = (struct host_val_ctx *)(unsigned long)ctx_u64;
    __u8 b;

    if (bpf_skb_load_bytes(c->skb, c->pbase + c->vstart + c->vlen, &b, 1))
        return 1;                                    /* payload ended */
    if (c->vlen == 0 && ((b == ' ') || (b == '\t'))) {
        c->vstart += 1;                              /* skip leading blank */
        return 0;
    }
    if (b == '\r' || b == '\n')
        return 1;                                    /* end of line */
    c->colon |= (__u32)(b == ':') * (__u32)(c->colon == 0) * (c->vlen + 1);
    c->vlen += 1;
    return 0;
}

static __always_inline int http_host_extract(struct __sk_buff *skb, __u32 pbase,
                                             __u32 *out_off, __u32 *out_len) {
    __u32 i, hit = 0, vstart, vlen, k;
    int found = 0;
    __u8 b;

    /* Pass 1: locate the first line starting with "Host:". */
    for (i = 0; i < HTTP_HOST_SCAN_MAX; i++) {
        if (i != 0) {
            if (bpf_skb_load_bytes(skb, pbase + i - 1, &b, 1))
                break;                               /* past the stream */
            if (b != '\n')
                continue;                            /* not a line start */
        }
        {
            __u8 h[5];
            if (bpf_skb_load_bytes(skb, pbase + i, h, 5))
                break;                               /* past the stream */
            /* Single-branch match test: fold the five byte compares into
             * one scalar (0 only on an exact "Host:" match). A chained
             * short-circuit compare over unknown bytes forks the verifier
             * 2^5 ways per scan position and blows the 1M insn budget. */
            __u32 mm = ((__u32)(h[0] | 32) ^ 'h') | ((__u32)(h[1] | 32) ^ 'o') |
                       ((__u32)(h[2] | 32) ^ 's') | ((__u32)(h[3] | 32) ^ 't') |
                       ((__u32)h[4] ^ ':');
            if (mm)
                continue;
        }
        hit = i;
        found = 1;
        break;
    }
    if (!found)
        return 0;

    /* Pass 2: extract the value with one bpf_loop() walk (see
     * host_value_cb). Leading blanks are skipped inside the walk, the
     * value runs to the line's end, and the first ':' is recorded for the
     * port strip. An out-of-payload load ends the walk (fail open when
     * nothing was found); a fragment boundary now also stops the walk
     * instead of aborting a found match — strictly more enforcement,
     * never less. */
    {
        struct host_val_ctx ctx = {
            .skb = skb,
            .pbase = pbase,
            .vstart = hit + 5,
            .vlen = 0,
            .colon = 0,
        };

        bpf_loop(16 + DOMAIN_NAME_MAX, host_value_cb, &ctx, 0);

        vlen = ctx.vlen;
        if (ctx.colon != 0)                          /* strip :port */
            vlen = ctx.colon - 1;
        vstart = ctx.vstart;
    }
    if (vlen == 0)
        return 0;
    if (vlen > 1) {                                  /* strip trailing dot */
        if (bpf_skb_load_bytes(skb, pbase + vstart + vlen - 1, &b, 1))
            return 0;
        if (b == '.')
            vlen--;
    }

    *out_off = pbase + vstart;
    *out_len = vlen;
    return 1;
}

/* Payload position for an outbound TCP packet. parse_packet stops its cursor
 * right after the fixed 20-byte TCP header (it is shared with the XDP
 * datapath and must not change), so this re-walks L2/L3 locally and uses
 * the header's real data offset to find the first payload byte. Returns 1
 * with (*off_out, *plen_out) set to the payload start (offset from `data`)
 * and length, 0 when there is no payload.
 *
 * The offsets are u32 and pinned through volatile locals: the payload
 * offset varies with the IP/TCP header lengths, a packet pointer with a
 * variable offset cannot be range-verified beyond a single byte, and the
 * scalar forms LLVM generates when reassociating these pointer differences
 * trip the verifier ("R3 pointer arithmetic with <<= operator prohibited";
 * "math between pkt pointer and register with unbounded min value").
 * Volatile makes the results opaque to those rewrites; the callers read
 * the stream by skb offset (bpf_skb_load_bytes) instead. */
/* TCP payload offset for an IPv6 TCP stream (L3 context, skb offsets):
 * walks the header chain, then reads the TCP header's data-offset. The
 * doff byte is a helper load on purpose — the same discipline as every
 * read on this path (see domain_tcp_payload). Returns 1 with *off_out =
 * first payload byte, 0 when the chain is not TCP or headers are
 * truncated. */
static __always_inline int v6_tcp_payload_offset(struct __sk_buff *skb,
                                                 __u32 *off_out) {
    __u32 l4_off = 0;
    __u8 proto = 0;
    __u8 doff_byte;
    __u32 hlen;

    if (!v6_l4_offset(skb, &l4_off, &proto) || proto != IPPROTO_TCP)
        return 0;
    if (bpf_skb_load_bytes(skb, l4_off + 12, &doff_byte, 1))
        return 0;                                        /* truncated TCP header */
    hlen = (__u32)(doff_byte >> 4) * 4;
    if (hlen < 20 || hlen > 60)
        return 0;
    *off_out = l4_off + hlen;
    return 1;
}

static __always_inline int domain_tcp_payload(struct __sk_buff *skb, bool l2,
                                              void *data, void *data_end,
                                              __u32 *off_out, __u32 *plen_out) {
    struct hdr_cursor c = { data };
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 hlen;

    /* IPv6 (L3 context only — the domain stage is egress-only): locate the
     * L4 offset through the header chain via helper loads, then address the
     * stream by skb offset exactly like the v4 path. The v6/TCP headers are
     * always linear; the stream is read via helper loads by the extractors. */
    if (!l2) {
        __u8 first6;
        __u32 off_v, plen_v;

        if (bpf_skb_load_bytes(skb, 0, &first6, 1))
            return 0;
        if ((first6 >> 4) == 6) {
            if (!v6_tcp_payload_offset(skb, &off_v))
                return 0;
            plen_v = skb->len - off_v;
            if (plen_v == 0)
                return 0;
            *off_out = off_v;
            *plen_out = plen_v;
            return 1;
        }
    }

    if (l2 && parse_ethhdr(&c, data_end, &eth) != bpf_htons(ETH_P_IP))
        return 0;
    if (parse_iphdr(&c, data_end, &ip) < 0)
        return 0;
    if (ip->protocol != IPPROTO_TCP)
        return 0;
    if (parse_tcphdr(&c, data_end, &tcp) < 0)
        return 0;
    hlen = (__u32)tcp->doff * 4;
    if (hlen < sizeof(*tcp) || hlen > 60)
        return 0;
    volatile __u32 off_v = (__u32)((void *)tcp - (void *)data) + hlen;
    /* The payload length must come from skb->len, NOT data_end: outbound
     * TCP data skbs are non-linear (tcp_sendmsg puts the payload in paged
     * fragments), so the linear area typically ends right after the
     * headers and data_end - (tcp + hlen) is 0 for every data packet.
     * bpf_skb_load_bytes reads fragments, so the stream itself is fully
     * reachable; skb->len spans it. */
    volatile __u32 plen_v = skb->len - off_v;
    __u32 off = off_v;
    __u32 plen = plen_v;
    if (plen == 0)
        return 0;
    *off_out = off;
    *plen_out = plen;
    return 1;
}

/* QUIC detector: is this a UDP datagram addressed to port 443? Works on
 * v4 and v6 via helper loads (non-linear-safe), reading only the fixed
 * header fields. IPv6 QUIC flows carry no extension headers, so a direct
 * nexthdr == UDP test is exact for the v6 case; anything else is not
 * treated as QUIC. */
static __always_inline int is_quic_443(struct __sk_buff *skb, void *data,
                                       void *data_end) {
    __u8 first, proto, port_b[2];
    __u32 l4_off;

    if (bpf_skb_load_bytes(skb, 0, &first, 1))
        return 0;
    switch (first >> 4) {
    case 4:
        if (bpf_skb_load_bytes(skb, 9, &proto, 1))
            return 0;
        if (proto != IPPROTO_UDP)
            return 0;
        if ((first & 0xf) < 5)
            return 0;
        l4_off = (__u32)(first & 0xf) * 4;
        break;
    case 6:
        if (bpf_skb_load_bytes(skb, 6, &proto, 1))
            return 0;
        if (proto != IPPROTO_UDP)
            return 0;
        l4_off = sizeof(struct ipv6hdr);
        break;
    default:
        return 0;
    }
    if (bpf_skb_load_bytes(skb, l4_off + 2, port_b, 2))
        return 0;
    return (((__u16)port_b[0] << 8) | (__u16)port_b[1]) == bpf_htons(443);
}

SEC("cgroup_skb/egress")
int firewall_cgroup_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 pkt_len = (__u64)(data_end - data);
    int ok;
    int verdict;

    /* 0. scope: the cgroup egress hook sees the whole host's outbound
     * traffic; keep the policy on the daemon's -i interface only
     * (egress_meta entry 0, written by the daemon at attach time). An
     * unwritten (0) scope processes every interface — the state before
     * attach and under BPF_PROG_TEST_RUN, whose synthetic skbs carry
     * ifindex 0; the daemon publishes the ifindex before the link goes
     * live, so no real packet runs with an unset scope. */
    {
        __u32 zero = 0;
        __u32 *ifidx = bpf_map_lookup_elem(&egress_meta, &zero);
        if (ifidx && *ifidx != 0 && skb->ifindex != *ifidx)
            return 1;
    }

    /* 0.5 presence + QUIC fence: one presence read feeds both the fence
     * and the policy stages below. The QUIC fence closes the biggest URL
     * filtering gap: the domain stage only sees names in TCP payloads
     * (SNI / Host), while browsers happily speak QUIC/HTTP-3 (UDP/443),
     * which encrypts the name from the first byte. With the blocklist
     * loaded, UDP/443 is dropped — browsers fall back to TCP (their
     * designed fallback), where the blocklist applies. Protocol-agnostic
     * (v4 + v6); -allow-quic sets EGRESS_FLAG_ALLOW_QUIC in
     * egress_config[1] to opt out. Zero cost when no blocklist is loaded
     * or the packet is not UDP/443-shaped. */
    {
        __u32 zero = 0;
        __u32 *presence = bpf_map_lookup_elem(&rule_presence, &zero);
        __u32 flags = presence ? *presence : 0;

        if (flags & RULE_DOMAIN_PRESENT) {
            __u32 one = 1;
            __u32 *eflags = bpf_map_lookup_elem(&egress_config, &one);
            if (!(eflags && (*eflags & EGRESS_FLAG_ALLOW_QUIC)) &&
                is_quic_443(skb, data, data_end)) {
                count_egress(XDP_DROP, pkt_len);
                incr_egress_counter(COUNTER_EGRESS_QUIC_DROP, pkt_len);
                return cg_action(XDP_DROP);
            }
        }
    }

    /* 1. parse (L3: the cgroup/skb context starts at the IP header; the
     * version dispatch and all v6 reads are helper loads). */
    struct packet_info info = parse_packet_l3(skb, data, data_end, &ok);

    /* Unparseable or non-IPv4: apply the egress default policy only, exactly
     * like firewall_prog does for ingress. Without this early return a zeroed
     * packet_info would be fed to the IP / port rule lookups: an egress rule
     * covering 0.0.0.0 (e.g. a block-everything 0.0.0.0/0) would then drop
     * ARP, IPv6 and other non-IPv4 L2 frames even under an egress default
     * ALLOW. */
    if (!ok) {
        verdict = egress_default_policy() == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
        count_egress(verdict, pkt_len);
        return cg_action(verdict);
    }

    /* 1.5 retransmission fence: a flow whose ClientHello matched the
     * domain blocklist is dropped wholesale (see blocked_flows in
     * maps.h) — retransmitted segments of the dropped ClientHello may be
     * re-segmented differently, and per-packet SNI parsing fails open on
     * mid-record continuations, which would otherwise let the blocked
     * handshake complete. The fence must not black-hole the flow's own
     * teardown: a bare FIN or an RST carries no deliverable payload and
     * is let through, and an RST also clears the entry — an undelivered
     * teardown leaves the peer's acceptor wedged forever on a stream
     * that can never complete (a serial TLS server stuck in SSL_accept
     * starves every connection behind it), and the client socket would
     * linger in FIN_WAIT_1. IPv4-only for now: the fence key is the v4
     * conntrack tuple, and a re-segmented v6 ClientHello fails open
     * (documented gap). */
    if (ok && info.family == 4) {
        struct ct_key fk;
        ct_build_key(&fk, &info);
        if (info.tcp_flags & (TCP_SYN | TCP_RST)) {
            /* SYN: a fresh connection attempt on this tuple (the failed
             * connection never established, so its port returns to the
             * pool immediately) — un-fence so the new attempt is judged
             * on its own merits by the domain stage below. RST: the flow
             * is aborting; nothing follows it on this socket, so the
             * fence entry dies with the connection. */
            bpf_map_delete_elem(&blocked_flows, &fk);
        } else if (bpf_map_lookup_elem(&blocked_flows, &fk)) {
            __u32 off, plen;
            int bare_fin = (info.tcp_flags & TCP_FIN) &&
                           !domain_tcp_payload(skb, false, data, data_end,
                                               &off, &plen);
            if (!bare_fin) {
                /* Data, pure ACKs and FIN-with-payload stay dropped: a
                 * FIN can piggyback retransmitted ClientHello bytes. A
                 * bare FIN falls through to the normal pipeline (and its
                 * pass accounting) with the fence still armed for any
                 * data retransmits that follow it. */
                count_egress(XDP_DROP, pkt_len);
                return cg_action(XDP_DROP);
            }
        }
    }

    /* 2. egress policy, gated by the egress presence bits. The IP/CIDR
     * and port tables have IPv4-shaped keys, so they are v4-only — the
     * v6 policy surface is the domain stage below plus the default
     * policy. */
    __u32 zero = 0;
    __u32 *presence = bpf_map_lookup_elem(&rule_presence, &zero);
    __u32 flags = presence ? *presence : 0;

    struct rule_value ip_rule = {}, port_rule = {};
    int ip_matched = 0, port_matched = 0;
    if (info.family == 4 && (flags & RULE_EGRESS_IP_PRESENT)) {
        ip_matched = egress_ip_block_action(&info, &ip_rule);
    }
    if (info.family == 4 && (flags & RULE_EGRESS_PORT_PRESENT)) {
        port_matched = egress_port_rule_action(&info, &port_rule);
    }

    /* 2.5 domain blocklist (URL filtering). Only web-bound TCP traffic
     * with payload carries a destination name; every other packet exits
     * this stage after the presence-bit test. A hit is an unconditional
     * DROP that precedes rules, priorities and the default policy
     * (explicit blocklist semantics), counted separately so URL filtering
     * is observable on its own. A dropped stream writes no conntrack
     * state (state is only ever written after a PASS). */
    if ((flags & RULE_DOMAIN_PRESENT) && !(info.tcp_flags & TCP_SYN)) {
        __u32 off, plen;
        int blocked = 0;

        /* The stage addresses the stream by skb offset (bpf_skb_load_bytes)
         * instead of packet pointers: the payload offset varies with the
         * IP/TCP header lengths and no packet pointer with a variable
         * offset can be range-verified (see domain_tcp_payload). Helper
         * loads are runtime-checked, so a malformed stream, a split
         * ClientHello or a non-linear skb simply fails open. */
        if (domain_tcp_payload(skb, false, data, data_end, &off, &plen)) {
            __u32 name_off = 0;
            __u32 name_len = 0;

            if (info.dport == bpf_htons(443)) {
                blocked = tls_sni_extract(skb, off, plen, &name_off, &name_len) &&
                          domain_block_action(skb, name_off, name_len);
            } else if (info.dport == bpf_htons(80)) {
                blocked = http_host_extract(skb, off, &name_off, &name_len) &&
                          domain_block_action(skb, name_off, name_len);
            }
        }
        if (blocked) {
            if (info.family == 4) {
                /* v4 only: the fence key is the IPv4 conntrack tuple. A
                 * re-segmented v6 ClientHello fails open (documented
                 * gap, see the fence note above). */
                struct ct_key fk;
                __u8 one = 1;
                ct_build_key(&fk, &info);
                bpf_map_update_elem(&blocked_flows, &fk, &one, BPF_ANY);
            }
            count_egress(XDP_DROP, pkt_len);
            incr_egress_counter(COUNTER_EGRESS_DOMAIN_DROP, pkt_len);
            return cg_action(XDP_DROP);
        }
    }

    /* 3. decision: same priority table as ingress; on no rule match the
     * shared stateful fast path (ESTABLISHED, or a CLOSED flow draining out)
     * is consulted when this hook's default is DENY, then the egress default
     * applies. v6 skips the stateful path (conntrack is v4-keyed) and the
     * v4-only rule tables, so the domain stage above and the default policy
     * decide. */
    enum default_policy def_egress = egress_default_policy();
    if (ip_matched || port_matched) {
        verdict = decide(ip_matched, &ip_rule, port_matched, &port_rule);
    } else if (info.family == 4 && def_egress == DEFAULT_DENY &&
               info.protocol == IPPROTO_TCP && ct_is_passable_egress(&info)) {
        verdict = XDP_PASS;
    } else {
        verdict = def_egress == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
    }

    if (verdict == XDP_DROP) {
        count_egress(XDP_DROP, pkt_len);
        return cg_action(XDP_DROP);
    }

    /* 4. accepted: record/refresh TCP state when a direction could need it.
     * v4 only — the conntrack key is an IPv4 tuple. */
    if (info.family == 4 && ct_active_egress(&info, def_egress)) {
        ct_update_egress(&info);
    }

    /* 5. passed. */
    count_egress(XDP_PASS, pkt_len);
    return cg_action(XDP_PASS);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
