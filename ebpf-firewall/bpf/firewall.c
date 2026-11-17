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
 *   - Egress only: the stage lives in firewall_tc_egress; the XDP
 *     (ingress) datapath is untouched.
 *   - A hit is an unconditional DROP that precedes the rule/default
 *     decision: the blocklist is an explicit deny, not a priority
 *     participant.
 *   - Suffix probing: the full name is probed first, then its parent
 *     labels (cdn.badsite.com -> badsite.com), so one entry covers a
 *     whole domain tree.
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

/* Probe domain_blocklist for `name` (a packet-pointer hostname of `len`
 * bytes) and, on a miss, its parent suffixes. Lowercasing happens here so
 * a ClientHello with unusual case still matches the loader's normalized
 * entries. Returns 1 on a hit. */
#define DOMAIN_MAX_PROBES 6
#define DOMAIN_NAME_MAX   63   /* domain_key.name holds 64 with padding */

static __always_inline int domain_block_action(struct __sk_buff *skb, __u32 name_off, __u32 len) {
    struct domain_key key;
    __u32 start = 0;
    __u32 probe;

    if (len == 0)
        return 0;
    if (len > DOMAIN_NAME_MAX)
        len = DOMAIN_NAME_MAX;   /* same truncation contract as the loader */

    for (probe = 0; probe < DOMAIN_MAX_PROBES; probe++) {
        __u32 sub = len - start;
        __u32 i;

        if (sub == 0)
            break;
        __builtin_memset(&key, 0, sizeof(key));
        if (bpf_skb_load_bytes(skb, name_off + start, key.name, sub))
            return 0;                       /* load past the stream: fail open */
        for (i = 0; i < sub; i++) {         /* lowercase in place */
            __u8 ch = (__u8)key.name[i];
            if (ch >= 'A' && ch <= 'Z')
                ch += 32;
            key.name[i] = ch;
        }
        if (bpf_map_lookup_elem(&domain_blocklist, &key))
            return 1;

        /* Advance `start` past the next dot to the next parent suffix. */
        {
            __u32 dot = start;
            for (; dot < len && dot < DOMAIN_NAME_MAX; dot++) {
                __u8 ch;
                if (bpf_skb_load_bytes(skb, name_off + dot, &ch, 1))
                    return 0;
                if (ch == '.')
                    break;
            }
            if (dot >= len || dot >= DOMAIN_NAME_MAX)
                break;
            start = dot + 1;
        }
    }
    return 0;
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
    if (!bcur_take16(skb, &c, &rec_len) || rec_len < 4)
        return 0;
    /* Bound what follows to the record's declared body: bytes beyond
     * rec_len belong to another record and must never be parsed as part
     * of this handshake. A record claiming more than the packet carries
     * is left alone; the handshake-length check below rejects the
     * split-ClientHello case. */
    if (rec_len < c.left)
        c.left = rec_len;
    if (!bcur_take8(skb, &c, &hs_type) || hs_type != 0x01)    /* ClientHello */
        return 0;
    if (!bcur_take24(skb, &c, &hs_len))
        return 0;
    /* The ClientHello must be whole in this segment; a handshake split
     * across TCP segments gets no verdict (documented gap). */
    if (hs_len > c.left)
        return 0;
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
        if (el > c.left)
            return 0;
        if (et == 0x0000) {                              /* server_name */
            struct bcur e = { c.off, el };
            __u16 list_len, nl;
            __u8 name_type;
            if (!bcur_take16(skb, &e, &list_len))
                return 0;
            /* the name list must fill the extension exactly (single
             * HostName entry, as every real client encodes it) — this
             * also pins the name inside the declared list */
            if (list_len != el - 2)
                return 0;
            if (!bcur_take8(skb, &e, &name_type) || name_type != 0)
                return 0;
            if (!bcur_take16(skb, &e, &nl) || nl == 0 || nl > e.left)
                return 0;
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
 * bpf_skb_load_bytes (see struct bcur). */
#define HTTP_HOST_SCAN_MAX 512

static __always_inline int http_host_extract(struct __sk_buff *skb, __u32 pbase,
                                             __u32 plen, __u32 *out_off, __u32 *out_len) {
    __u32 scan = plen < HTTP_HOST_SCAN_MAX ? plen : HTTP_HOST_SCAN_MAX;
    __u32 i;
    __u8 b;

    for (i = 0; i < scan; i++) {
        __u32 vstart, vend, k;

        if (i + 5 > plen)
            break;
        if (i != 0) {
            if (bpf_skb_load_bytes(skb, pbase + i - 1, &b, 1))
                return 0;
            if (b != '\n')
                continue;                                /* not a line start */
        }
        {
            __u8 h[5];
            if (bpf_skb_load_bytes(skb, pbase + i, h, 5))
                return 0;
            if ((h[0] | 32) != 'h' || (h[1] | 32) != 'o' ||
                (h[2] | 32) != 's' || (h[3] | 32) != 't' ||
                h[4] != ':')
                continue;
        }

        vstart = i + 5;                                  /* skip spaces/tabs */
        for (k = 0; k < 16; k++) {
            __u32 idx = vstart + k;
            if (idx >= plen)
                break;
            if (bpf_skb_load_bytes(skb, pbase + idx, &b, 1))
                return 0;
            if (b != ' ' && b != '\t')
                break;
        }
        vstart += k;

        vend = vstart;                                   /* read to end of line */
        for (k = 0; k < DOMAIN_NAME_MAX + 8; k++) {
            __u32 idx = vstart + k;
            if (idx >= plen)
                break;
            if (bpf_skb_load_bytes(skb, pbase + idx, &b, 1))
                return 0;
            if (b == '\r' || b == '\n')
                break;
            vend = idx + 1;
        }

        for (k = 0; k < DOMAIN_NAME_MAX + 8 && vstart + k < vend; k++) {
            __u32 idx = vstart + k;
            if (bpf_skb_load_bytes(skb, pbase + idx, &b, 1))
                return 0;
            if (b == ':') {                              /* strip :port */
                vend = vstart + k;
                break;
            }
        }
        if (vend == vstart)
            continue;
        if (vend - vstart > 1) {                         /* strip trailing dot */
            if (bpf_skb_load_bytes(skb, pbase + vend - 1, &b, 1))
                return 0;
            if (b == '.')
                vend--;
        }

        *out_off = pbase + vstart;
        *out_len = vend - vstart;
        return 1;
    }
    return 0;
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
static __always_inline int domain_tcp_payload(void *data, void *data_end,
                                              __u32 *off_out, __u32 *plen_out) {
    struct hdr_cursor c = { data };
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 hlen;

    if (parse_ethhdr(&c, data_end, &eth) != bpf_htons(ETH_P_IP))
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
    volatile __u32 plen_v = (__u32)((void *)data_end - (void *)tcp) - hlen;
    __u32 off = off_v;
    __u32 plen = plen_v;
    if (plen == 0)
        return 0;
    *off_out = off;
    *plen_out = plen;
    return 1;
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

    /* Unparseable or non-IPv4: apply the egress default policy only, exactly
     * like firewall_prog does for ingress. Without this early return a zeroed
     * packet_info would be fed to the IP / port rule lookups: an egress rule
     * covering 0.0.0.0 (e.g. a block-everything 0.0.0.0/0) would then drop
     * ARP, IPv6 and other non-IPv4 L2 frames even under an egress default
     * ALLOW. */
    if (!ok) {
        verdict = egress_default_policy() == DEFAULT_DENY ? XDP_DROP : XDP_PASS;
        count_egress(verdict, pkt_len);
        return tc_action(verdict);
    }

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
        if (domain_tcp_payload(data, data_end, &off, &plen)) {
            __u32 name_off = 0;
            __u32 name_len = 0;

            if (info.dport == bpf_htons(443))
                blocked = tls_sni_extract(skb, off, plen, &name_off, &name_len) &&
                          domain_block_action(skb, name_off, name_len);
            else if (info.dport == bpf_htons(80))
                blocked = http_host_extract(skb, off, plen, &name_off, &name_len) &&
                          domain_block_action(skb, name_off, name_len);
        }
        if (blocked) {
            count_egress(XDP_DROP, pkt_len);
            incr_egress_counter(COUNTER_EGRESS_DOMAIN_DROP, pkt_len);
            return tc_action(XDP_DROP);
        }
    }

    /* 3. decision: same priority table as ingress; on no rule match the
     * shared stateful fast path (ESTABLISHED, or a CLOSED flow draining out)
     * is consulted when this hook's default is DENY, then the egress default
     * applies. */
    enum default_policy def_egress = egress_default_policy();
    if (ip_matched || port_matched) {
        verdict = decide(ip_matched, &ip_rule, port_matched, &port_rule);
    } else if (def_egress == DEFAULT_DENY && info.protocol == IPPROTO_TCP &&
               ct_is_passable_egress(&info)) {
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
