#!/usr/bin/env bash
# Shared configuration and helpers for the MTP1-E benchmark harness.
#
# The harness measures the XDP firewall vs nftables on a single host using a
# disposable veth pair + network namespace, so experiments are reproducible
# without a second machine and never touch a real interface. Traffic originates
# inside `benchns` and enters the host through `veth0`, where the firewall
# (XDP) or nftables sees it — the same hook both backends filter on.
#
# Usage: source this file from benchmark scripts; it defines functions and
# variables, and does nothing on its own.

set -u

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${BENCH_DIR}/.." && pwd)"

RESULTS_ROOT="${BENCH_DIR}/results"
HOST_IP="10.200.0.1"
NS_IP="10.200.0.2"
NS_NAME="benchns"
VETH0="bench-v0"
VETH1="bench-v1"

# Backends. `make build` populates bin/; the orchestrator rebuilds to ensure
# the measured binary matches the current source.
FIREWALLD="${REPO_DIR}/bin/firewall"
CTL="${REPO_DIR}/bin/firewallctl"

XDP_PORT_RULE_IP="192.0.2.55"          # src/dst used in port-rule scenarios
FORWARD_CIDR="198.51.100.0/24"         # one matchable blocked prefix

# Scenarios. `scenario_targets <name>` must echo exactly one network/ip per
# line; every backend installs drop rules covering exactly those (and their
# mirrored source/destination form, matching the XDP datapath).
all_scenarios=(none single forward many)

scenario_targets() {
    case "$1" in
    none)   : ;;
    single) echo "198.51.100.7/32" ;;
    forward) echo "${FORWARD_CIDR}" ;;
    many)
        # 1000 distinct /30 prefixes in a 10.10.0.0/19 block. Deterministic,
        # generated once and reused for every backend so counts match exactly.
        seq 0 999 | awk '{ printf "10.10.%d.%d/30\n", ($1 / 256), ($1 % 256 * 4) }'
        ;;
    *)
        echo "bench: unknown scenario '$1'" >&2
        return 1
        ;;
    esac
}

log() { echo "[bench $(date '+%H:%M:%S')] $*"; }

require_cmds() {
    local cmd missing=0
    for cmd in "$@"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            echo "bench: missing required tool: ${cmd}" >&2
            missing=1
        fi
    done
    [ "${missing}" -eq 0 ] || return 1
}

# ---------------------------------------------------------------------------
# Sandbox: veth pair + network namespace
# ---------------------------------------------------------------------------

sandbox_up() {
    log "creating sandbox (veth pair + netns '${NS_NAME}')"
    sandbox_down   # remove any stale names from a previous run
    ip netns add "${NS_NAME}"
    ip link add "${VETH0}" type veth peer name "${VETH1}"
    ip link set "${VETH1}" netns "${NS_NAME}"
    ip addr add "${HOST_IP}/24" dev "${VETH0}"
    ip netns exec "${NS_NAME}" ip addr add "${NS_IP}/24" dev "${VETH1}"
    ip link set "${VETH0}" up
    ip netns exec "${NS_NAME}" ip link set "${VETH1}" up
    ip netns exec "${NS_NAME}" ip link set lo up
    ip netns exec "${NS_NAME}" ip route add default via "${HOST_IP}"
}

sandbox_down() {
    log "tearing down sandbox"
    ip netns del "${NS_NAME}" 2>/dev/null || true
    ip link del "${VETH0}" 2>/dev/null || true
}

ns_exec() { ip netns exec "${NS_NAME}" "$@"; }

# ---------------------------------------------------------------------------
# CPU / memory sampling (no external tooling required)
# ---------------------------------------------------------------------------

# sample_cpu <outvar> : stores aggregate (user+system+softirq) jiffies.
sample_cpu() {
    local line cpu name
    read -r -a line < /proc/stat
    # line[0]="cpu", line[1..]=user nice system idle iowait irq softirq steal
    cpu=$((line[1] + line[2] + line[3] + line[7] + line[8]))
    eval "${1}=${cpu}"
}

# cpu_delta <start> <end> : busy-jiffies between two sample_cpu snapshots.
cpu_delta() {
    local d=$(( $2 - $1 ))
    [ "${d}" -lt 0 ] && d=0
    echo "${d}"
}

# sample_rss_kb <pid> : resident set size in KiB (0 if unknowable).
sample_rss_kb() {
    [ -r "/proc/${1}/status" ] || { echo 0; return; }
    awk '/^VmRSS:/{print $2; exit}' "/proc/${1}/status"
}

# ---------------------------------------------------------------------------
# Traffic measurement (iperf3 + ping); requires `iperf3`
# ---------------------------------------------------------------------------

# start_iperf_server : host-side server bound to the sandbox veth IP.
start_iperf_server() {
    iperf3 -s -B "${HOST_IP}" -p 5201 --one-off -D --logfile /dev/null
    sleep 0.2
}

# run_iperf <udp|tcp> <duration> <json_out> : client inside the ns.
run_iperf() {
    local mode="$1" dur="$2" out="$3" extra=()
    if [ "${mode}" = udp ]; then
        extra=(-u -b 1000M)
    fi
    if ! ns_exec iperf3 -c "${HOST_IP}" -p 5201 -t "${dur}" "${extra[@]}" \
         -J > "${out}" 2>/dev/null; then
        echo "bench: iperf3 ${mode} run failed" >&2
        return 1
    fi
    # Print derived key/value lines for the summary.
    if command -v jq >/dev/null 2>&1; then
        if [ "${mode}" = udp ]; then
            jq -r '"udp_bits_per_sec=\(.end.sum.bits_per_second)\nudp_bytes=\(.end.sum.bytes)\nudp_lost_packets=\(.end.sum.lost_packets)\nudp_sent_packets=\(.end.sum.packets)\nudp_jitter_ms=\(.end.sum.jitter_ms)"' "${out}"
        else
            jq -r '"tcp_bits_per_sec=\(.end.sum_received.bits_per_second)\ntcp_bytes_retrans=\(.end.sum_received.retransmits)"' "${out}"
        fi
    else
        echo "jq_missing=1"
    fi
}

# run_ping <rounds> <out> : RTT stats from the ns to the host.
run_ping() {
    local rounds="$1" out="$2"
    ns_exec ping -c "${rounds}" -i 0.05 -q "${HOST_IP}" > "${out}" 2>&1 || true
    awk '/rtt/{split($4, a, "/"); print "rtt_min_ms=" a[1]; print "rtt_avg_ms=" a[2]; print "rtt_max_ms=" a[3]}' \
        "${out}" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Rule-update timing helpers (milliseconds)
# ---------------------------------------------------------------------------

time_ms() {  # time_ms <outvar> <cmd...>
    local out="$1"
    shift
    local ts0 ts1 me
    ts0=$(date +%s%N)
    "$@" >/dev/null 2>&1
    ts1=$(date +%s%N)
    me=$(( (ts1 - ts0) / 1000000 ))
    eval "${out}=${me}"
}

# ---------------------------------------------------------------------------
# Backend rule application
# ---------------------------------------------------------------------------

# apply_xdp_rules <scenario> : adds drop rules via firewallctl (daemon must be
# attached to ${VETH0}). Mirrors saddr+daddr semantics of the C datapath:
# blocked_ips matches source first, then destination.
apply_xdp_rules() {
    local ip
    while read -r ip; do
        [ -n "${ip}" ] || continue
        "${CTL}" block "${ip}" || return 1
    done < <(scenario_targets "$1")
}

clear_xdp_rules() { "${CTL}" clear >/dev/null 2>&1 || true; }

# apply_nft_rules <scenario> : flushes the bench table then installs an
# equivalent inet/input chain. A network m is matched on both source and
# destination, mirroring the two lookups the XDP program performs.
NFT_TABLE="benchmark"

nft_rules_up() {
    nft add table inet "${NFT_TABLE}"
    nft add chain inet "${NFT_TABLE}" input "{ type filter hook input priority 0; policy accept; }"
}

nft_rules_flush() { nft flush table inet "${NFT_TABLE}" 2>/dev/null || true; }

nft_rules_down() { nft delete table inet "${NFT_TABLE}" 2>/dev/null || true; }

apply_nft_rules() {
    local ip
    while read -r ip; do
        [ -n "${ip}" ] || continue
        nft add rule inet "${NFT_TABLE}" input ip saddr "${ip}" drop
        nft add rule inet "${NFT_TABLE}" input ip daddr "${ip}" drop
    done < <(scenario_targets "$1")
}