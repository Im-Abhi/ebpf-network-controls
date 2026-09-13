#!/usr/bin/env bash
# MTP1-E benchmark orchestrator: XDP firewall vs nftables.
#
# For every (backend x scenario) it runs, inside a disposable veth+netns
# sandbox, a deterministic traffic pass (iperf3 UDP + TCP, ping latency) while
# sampling host CPU, the firewall daemon's RSS, and single-rule add/delete
# latency. Raw per-run logs and a summary.tsv land under
# benchmark/results/<timestamp>/.
#
# Fairness: block-rule sets are identical across backends (benchmark/common.sh
# `scenario_targets`), and nftables mirrors the XDP program's two lookups by
# installing both `ip saddr <net> drop` and `ip daddr <net> drop`.
#
# Usage:
#   sudo ./benchmark/run-bench.sh [--backend all|xdp|nft]
#                                [--scenario all|none|single|forward|many]
#                                [--iterations N] [--duration S] [--help]
# Defaults: backend=all scenario=all iterations=3 duration=10.

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${BENCH_DIR}/common.sh"

BACKENDS=(xdp nft)
SCENARIOS=("${all_scenarios[@]}")
ITERATIONS=3
DURATION=10
RUN_TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RESULTS_ROOT}/${RUN_TS}"
SUMMARY="${RUN_DIR}/summary.tsv"
IPERF_PID=""

usage() {
    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# //'
    exit 0
}

while [ "$#" -gt 0 ]; do
    case "$1" in
    --backend)
        case "$2" in
        all) BACKENDS=(xdp nft) ;;
        xdp|nft) BACKENDS=("$2") ;;
        *) echo "bench: bad backend '$2'" >&2; usage ;;
        esac
        shift 2 ;;
    --scenario)
        case "$2" in
        all) SCENARIOS=("${all_scenarios[@]}") ;;
        none|single|forward|many) SCENARIOS=("$2") ;;
        *) echo "bench: bad scenario '$2'" >&2; usage ;;
        esac
        shift 2 ;;
    --iterations) ITERATIONS="$2"; shift 2 ;;
    --duration)   DURATION="$2";   shift 2 ;;
    --help|-h) usage ;;
    *) echo "bench: unknown option '$1'" >&2; usage ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "bench: run as root" >&2; exit 1; }
require_cmds ip nft iperf3 ping date || exit 1
if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "bench: iperf3 JSON parsing needs jq or python3 (neither found)" >&2
    exit 1
fi

if pgrep -f "/bin/firewall " >/dev/null 2>&1; then
    echo "bench: a firewall daemon is already running; stop it first (the benchmark starts its own on the sandbox veth)" >&2
    exit 1
fi

log "building firewall + firewallctl from current source"
(cd "${REPO_DIR}" && go build -o "${FIREWALLD}" ./cmd/firewall)
(cd "${REPO_DIR}" && go build -o "${CTL}" ./cmd/firewallctl)

log "results -> ${RUN_DIR}"
mkdir -p "${RUN_DIR}"

# Environment capture: each run is self-documenting for the thesis.
{
    echo "run: ${RUN_TS}"
    date -u '+started_utc: %Y-%m-%d %H:%M:%S'
    echo "kernel:   $(uname -srm 2>/dev/null || true)"
    echo "uname_r:  $(uname -r 2>/dev/null || true)"
    echo "iperf3:   $(iperf3 --version 2>/dev/null | head -1 || true)"
    echo "nft:      $(nft --version 2>/dev/null || true)"
    echo "go:       $(go version 2>/dev/null || true)"
    echo "jq:       $(jq --version 2>/dev/null || echo n/a)"
    echo "python3:  $(python3 --version 2>/dev/null || echo n/a)"
} > "${RUN_DIR}/meta.txt"

# kv <file> <key> : prints the value of `key=value` lines written by helpers.
kv() { awk -F= -v k="$2" '$1==k {print $2; exit}' "$1"; }

cleanup() {
    [ -n "${IPERF_PID}" ] && kill "${IPERF_PID}" 2>/dev/null || true
    clear_xdp_rules 2>/dev/null || true
    [ -n "${FW_PID:-}" ] && kill "${FW_PID}" 2>/dev/null || true
    nft_rules_down
    sandbox_down
}
trap cleanup EXIT

# --- per-backend lifecycle -------------------------------------------------

fw_start() {  # start daemon attached to ${VETH0}, default allow
    "${FIREWALLD}" -i "${VETH0}" > /dev/null 2>&1 &
    FW_PID=$!
    local i
    for i in $(seq 1 50); do
        [ -S /var/run/ebpf-firewall.sock ] && break
        sleep 0.1
    done
    sleep 0.2
    "${CTL}" default allow
}

fw_stop() { clear_xdp_rules; kill "${FW_PID}" 2>/dev/null || true; wait "${FW_PID}" 2>/dev/null || true; FW_PID=""; }

backend_up() {   # $1 = xdp|nft
    case "$1" in
    xdp) fw_start ;;
    nft) nft_rules_up ;;
    esac
}

backend_apply() { # $1 = backend, $2 = scenario
    case "$1" in
    xdp) clear_xdp_rules && apply_xdp_rules "$2" ;;
    nft) nft_rules_flush && apply_nft_rules "$2" ;;
    esac
}

backend_down() { # $1 = xdp|nft
    case "$1" in
    xdp) fw_stop ;;
    nft) nft_rules_flush ;;
    esac
}

backend_mem_kb() { # $1 = xdp|nft
    if [ "$1" = xdp ]; then
        sample_rss_kb "${FW_PID:-0}"
    else
        echo 0   # nft state lives in-kernel; not externally measurable
    fi
}

update_timing() { # $1 = backend -> prints rule_add_ms rule_del_ms
    case "$1" in
    xdp)
        local add del
        time_ms add "${CTL}" block "${FORWARD_CIDR}"
        time_ms del "${CTL}" unblock "${FORWARD_CIDR}"
        echo "${add} ${del}"
        ;;
    nft)
        local add del handle
        time_ms add nft add rule inet "${NFT_TABLE}" input ip saddr "${FORWARD_CIDR}" drop \
            || add=0
        handle="$(nft -a list chain inet "${NFT_TABLE}" input 2>/dev/null \
                    | grep "${FORWARD_CIDR}" | tail -1 | awk '{print $NF}')"
        if [ -n "${handle}" ]; then
            time_ms del nft delete rule inet "${NFT_TABLE}" input handle "${handle}" \
                || del=0
        else
            del=0
        fi
        echo "${add} ${del}"
        ;;
    esac
}

# --- measurement -----------------------------------------------------------

measure() { # $1=backend $2=scenario $3=iteration -> appends one summary row
    local backend="$1" scenario="$2" iter="$3"
    local rundir="${RUN_DIR}/${backend}-${scenario}"
    mkdir -p "${rundir}"
    log "measuring backend=${backend} scenario=${scenario} iteration=${iter} duration=${DURATION}s"

    iperf3 -s -B "${HOST_IP}" -p 5201 > /dev/null 2>&1 &
    IPERF_PID=$!

    local cpu0 cpu1
    sample_cpu cpu0

    local udp_kv tcp_kv
    if run_iperf udp "${DURATION}" "${rundir}/iperf-udp.json" > "${rundir}/udp.kv" 2>/dev/null; then
        udp_kv="${rundir}/udp.kv"
    else
        udp_kv="/dev/null"
    fi
    if run_iperf tcp "${DURATION}" "${rundir}/iperf-tcp.json" > "${rundir}/tcp.kv" 2>/dev/null; then
        tcp_kv="${rundir}/tcp.kv"
    else
        tcp_kv="/dev/null"
    fi
    run_ping 20 "${rundir}/ping.txt" > "${rundir}/rtt.kv" 2>/dev/null || true
    sample_cpu cpu1

    kill "${IPERF_PID}" 2>/dev/null || true
    IPERF_PID=""

    local bps pps loss jitter tcp_bps rtt mem addr del
    bps="$(kv "${udp_kv}" udp_bits_per_sec)";        [ -z "${bps}" ]    && bps=0
    pps="$(kv "${udp_kv}" udp_sent_packets)";         [ -z "${pps}" ]    && pps=0
    pps=$(( pps / DURATION ))
    loss="$(kv "${udp_kv}" udp_lost_packets)";        [ -z "${loss}" ]   && loss=0
    jitter="$(kv "${udp_kv}" udp_jitter_ms)";         [ -z "${jitter}" ] && jitter=0
    tcp_bps="$(kv "${tcp_kv}" tcp_bits_per_sec)";     [ -z "${tcp_bps}" ] && tcp_bps=0
    rtt="$(kv "${rundir}/rtt.kv" rtt_avg_ms)";        [ -z "${rtt}" ]    && rtt="n/a"
    mem="$(backend_mem_kb "${backend}")"
    read -r addr del <<< "$(update_timing "${backend}")"

    if [ "${bps}" -eq 0 ]; then
        log "WARN: backend=${backend} scenario=${scenario} iter=${iter}: udp_bps=0 (iperf or metric-parser problem)"
    fi

    printf '%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n' \
        "${RUN_TS}" "${backend}" "${scenario}" "${iter}" \
        "${bps}" "${pps}" "${loss}" "${jitter}" "${tcp_bps}" "${rtt}" \
        "$(cpu_delta "${cpu0}" "${cpu1}")" "${mem}" "${addr}" "${del}" \
        >> "${SUMMARY}"
    log "  udp_bps=${bps} pps=${pps} loss=${loss} tcp_bps=${tcp_bps} rtt=${rtt} mem=${mem} add=${addr}ms del=${del}ms"
}

# --- main ------------------------------------------------------------------

sandbox_up

printf 'run\tbackend\tscenario\titer\tudp_bps\tudp_pps\tudp_lost\tudp_jitter_ms\ttcp_bps\trtt_avg_ms\tcpu_jif\trss_kb\tadd_ms\tdel_ms\n' \
    > "${SUMMARY}"

for backend in "${BACKENDS[@]}"; do
    backend_up "${backend}"
    for scenario in "${SCENARIOS[@]}"; do
        backend_apply "${backend}" "${scenario}"
        for iter in $(seq 1 "${ITERATIONS}"); do
            measure "${backend}" "${scenario}" "${iter}"
        done
    done
    backend_down "${backend}"
done

sandbox_down
nft_rules_down
trap - EXIT
log "done. Summary:"
cat "${SUMMARY}" | sed 's/^/  /'
log "raw logs + summary saved under ${RUN_DIR}"