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

/* TC classifier action codes (linux/pkt_cls.h UAPI macros, not in vmlinux.h).
 * The egress program maps XDP verdicts onto these: DROP -> SHOT, PASS -> OK. */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
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
    __u8  tcp_flags; /* TCP_FIN/SYN/RST/ACK bits (0 if not TCP) */
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

/* Read-only conntrack probe. Returns 1 when an ESTABLISHED flow matches the
 * packet's 5-tuple, 0 otherwise (including NEW/CLOSED and no entry). */
static __always_inline int ct_is_established(const struct packet_info *info) {
    struct ct_key key;
    ct_build_key(&key, info);
    struct ct_value *v = bpf_map_lookup_elem(&conntrack, &key);
    return v && v->state == CT_ESTABLISHED;
}

/* Records an accepted TCP packet. Called only after a PASS decision, so a
 * dropped SYN never creates state (and a subsequent spoofed ACK cannot
 * fabricate an ESTABLISHED flow). Transitions: SYN -> NEW, ACK on NEW ->
 * ESTABLISHED, FIN/RST -> CLOSED, every accepted packet refreshes
 * last_seen. */
static __always_inline void ct_update(const struct packet_info *info) {
    struct ct_key key;
    ct_build_key(&key, info);
    __u64 now = bpf_ktime_get_ns();

    struct ct_value *v = bpf_map_lookup_elem(&conntrack, &key);
    if (v) {
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
     * default). Under default-deny a TCP packet belonging to an already
     * ESTABLISHED flow is also let through when no rule matches; the stateful
     * fast-path is meaningless (and skipped) under default-allow. */
    enum default_policy def = default_policy();
    int verdict;
    if (ip_matched || port_matched) {
        verdict = decide(ip_matched, &ip_rule, port_matched, &port_rule);
    } else if (def == DEFAULT_DENY && info.protocol == IPPROTO_TCP &&
               ct_is_established(&info)) {
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
     * default-deny, where the state actually changes future verdicts. */
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

/* ══ TC egress datapath ────────────────────────────────────────────────
 * Second hook: a SCHED_CLS classifier attached to the tc egress (clsact)
 * direction, filtering host-generated outbound traffic. The XDP program
 * (firewall_prog) is receive-side only and stays byte-for-byte unchanged;
 * this program is a separate SEC("classifier") section in the same object so
 * both directions share the policy and conntrack maps.
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

static __always_inline int tc_action(int verdict) {
    return verdict == XDP_DROP ? TC_ACT_SHOT : TC_ACT_OK;
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

/* Shared state probe for egress: ESTABLISHED on the exact (outbound) tuple
 * or its reverse. */
static __always_inline int ct_is_established_egress(const struct packet_info *info) {
    struct ct_key key;
    struct ct_value *v;

    ct_build_key(&key, info);
    v = bpf_map_lookup_elem(&conntrack, &key);
    if (v && v->state == CT_ESTABLISHED) {
        return 1;
    }

    ct_build_reverse_key(&key, info);
    v = bpf_map_lookup_elem(&conntrack, &key);
    return v && v->state == CT_ESTABLISHED;
}

/* Gate: decide whether egress may consult/write conntrack for this packet.
 * True only for TCP when EITHER direction's default is DENY - a state change
 * could then flip some future verdict. With both defaults ALLOW no state can
 * matter and the datapath stays off the state reads/writes (mirrors the XDP
 * datapath's default-allow gate). */
static __always_inline int ct_active_egress(const struct packet_info *info,
                                            enum default_policy def_egress) {
    if (info.protocol != IPPROTO_TCP) {
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
 * ESTABLISHED). A brand-new outbound flow is stored under its REVERSE (reply)
 * tuple as ESTABLISHED so the unchanged ingress path passes the reply under
 * default-deny (see the section note). */
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

/* Egress counter increment (indices 3-5; ingress keeps 0-2). */
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

SEC("classifier")
int firewall_tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u64 pkt_len = (__u64)(data_end - data);
    struct hdr_cursor nh;
    int ok;
    int verdict;

    /* 1. parse (shared with the XDP datapath). */
    nh.pos = data;
    struct packet_info info = parse_packet(&nh, data_end, &ok);

    /* 2. egress policy, gated by the egress presence bits. */
    __u32 zero = 0;
    __u32 *presence = bpf_map_lookup_elem(&rule_presence, &zero);
    __u32 flags = presence ? *presence : 0;

    struct rule_value ip_rule = {}, port_rule = {};
    int ip_matched = 0, port_matched = 0;
    if (flags & RULE_EGRESS_IP_PRESENT) {
        ip_matched = egress_ip_block_action(&info, &ip_rule);
    }
    if (flags & RULE_EGRESS_PORT_PRESENT) {
        port_matched = egress_port_rule_action(&info, &port_rule);
    }

    /* 3. decision: same priority table as ingress; on no rule match the
     * shared stateful fast path is consulted when this hook's default is
     * DENY, then the egress default applies. */
    enum default_policy def_egress = egress_default_policy();
    if (ip_matched || port_matched) {
        verdict = decide(ip_matched, &ip_rule, port_matched, &port_rule);
    } else if (def_egress == DEFAULT_DENY && info.protocol == IPPROTO_TCP &&
               ct_is_established_egress(&info)) {
        verdict = XDP_PASS;
    } else {
        verdict = def_egress == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
    }

    if (verdict == XDP_DROP) {
        count_egress(XDP_DROP, pkt_len);
        return tc_action(XDP_DROP);
    }

    /* 4. accepted: record/refresh TCP state when a direction could need it. */
    if (ct_active_egress(&info, def_egress)) {
        ct_update_egress(&info);
    }

    /* 5. passed. */
    count_egress(XDP_PASS, pkt_len);
    return tc_action(XDP_PASS);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
