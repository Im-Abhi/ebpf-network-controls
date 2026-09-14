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
#                                [--scenario all|none|single|forward|many|drop]
#                                [--iterations N] [--duration S]
#                                [--help]
# Defaults: backend=all scenario=all iterations=5 duration=10.
# Environment knobs: ITERS (iterations), DURATION (seconds per iperf3 pass),
# UDP_BW (iperf3 -b for the saturated UDP pass; 0 = unthrottled),
# UDP_CTL_BW (controlled UDP pass rate; 1500M default, 0 disables that pass).
# The `drop` scenario cannot be driven by iperf3 (its TCP control channel is
# dropped with the workload, so no DATA ever flows): offered load comes from a
# raw-UDP flood (flood_sent column) and the hook-side DROP rate is read from
# backend counters (drop_pps).
#
# Directions: iperf3's client (run in the sandbox netns) is the sender by
# default, so bulk DATA always flows client -> server through the host-side XDP
# hook and the nft INPUT chain. tcp_bps and udp_bps measure the firewalls'
# real forwarding datapath (not the ACK echo path).

set -euo pipefail

# Any uncaught failure must say where, not die silently (stderr on the call
# sites used to swallow "unbound variable" and the like).
trap 'printf "[bench] ERR rc=%s line=%s: %s\n" "$?" "$LINENO" "$BASH_COMMAND" >&2' ERR

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${BENCH_DIR}/common.sh"

BACKENDS=(xdp nft)
SCENARIOS=("${all_scenarios[@]}")
ITERATIONS="${ITERS:-5}"
DURATION=10
RUN_TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="${RESULTS_ROOT}/${RUN_TS}"
SUMMARY="${RUN_DIR}/summary.tsv"
IPERF_PID=""

usage() {
    sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# //'
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
        none|single|forward|many|drop) SCENARIOS=("$2") ;;
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
require_cmds ip nft iperf3 ping date python3 || exit 1
if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "bench: iperf3 JSON parsing needs jq or python3 (neither found)" >&2
    exit 1
fi

if pgrep -f "/bin/firewall " >/dev/null 2>&1; then
    echo "bench: a firewall daemon is already running; stop it first (the benchmark starts its own on the sandbox veth)" >&2
    exit 1
fi

# `firewall_bpf.o` (//go:embed) is a bpf2go artifact and is NOT tracked in git;
# a missing/stale one embeds wrong maps and the daemon dies at load with
# "missing map <name>". Fail fast with a clear hint instead.
if ! check_bpf_object_fresh; then
    echo "bench: embedded eBPF object missing or stale -- run 'make generate' (or 'make bench', which regenerates first)" >&2
    exit 1
fi

log "building firewall + firewallctl from current source (-buildvcs=false: VCS stamping is invalid under sudo and unused by the daemon)"
(cd "${REPO_DIR}" && go build -buildvcs=false -o "${FIREWALLD}" ./cmd/firewall)
(cd "${REPO_DIR}" && go build -buildvcs=false -o "${CTL}" ./cmd/firewallctl)

log "results -> ${RUN_DIR}"
mkdir -p "${RUN_DIR}"

# Environment capture: each run is self-documenting for the thesis.
{
    echo "run: ${RUN_TS}"
    date -u '+started_utc: %Y-%m-%d %H:%M:%S'
    echo "kernel:   $(uname -srm 2>/dev/null || true)"
    echo "uname_r:  $(uname -r 2>/dev/null || true)"
    echo "bpf_jit:  $(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo n/a)"
    echo "iperf3:   $(iperf3 --version 2>/dev/null | head -1 || true)"
    echo "nft:      $(nft --version 2>/dev/null || true)"
    echo "go:       $(go version 2>/dev/null || true)"
    echo "jq:       $(jq --version 2>/dev/null || echo n/a)"
    echo "python3:  $(python3 --version 2>/dev/null || echo n/a)"
} > "${RUN_DIR}/meta.txt"

# kv <file> <key> : prints the value of `key=value` lines written by helpers.
kv() { [ -r "$1" ] || return 0; awk -F= -v k="$2" '$1==k {print $2; exit}' "$1"; }

# Hand the run dir back to the user that invoked us via sudo, so the non-root
# `make bench-plot` can write charts into it. No-op when not run via sudo.
reset_results_owner() {
    { [ -n "${SUDO_USER:-}" ] && [ -d "${RUN_DIR:-}" ]; } && chown -R "${SUDO_USER}" "${RUN_DIR}" 2>/dev/null || true
}

cleanup() {
    [ -n "${IPERF_PID}" ] && kill "${IPERF_PID}" 2>/dev/null || true
    clear_xdp_rules 2>/dev/null || true
    [ -n "${FW_PID:-}" ] && kill "${FW_PID}" 2>/dev/null || true
    host_firewall_close
    nft_rules_down
    sandbox_down
    reset_results_owner
}
trap cleanup EXIT INT TERM

# --- per-backend lifecycle -------------------------------------------------

# Records the XDP attach mode actually used (xdpDriver/xdpGeneric) into
# meta.txt. Only meaningful while the daemon runs, so it lives in fw_start.
record_attach_mode() {
    local am
    am="$("${CTL}" status 2>/dev/null | sed -n 's/^attach mode: //p' | head -1)"
    [ -n "${am:-}" ] && echo "xdp_attach: ${am}" >> "${RUN_DIR}/meta.txt" || true
}

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
    record_attach_mode
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

    # Reap any stale iperf3 server (e.g. from an interrupted run) that would
    # otherwise keep holding :5201 and silently starve the TCP pass of a
    # listener -- the observable symptom is an all-zero tcp_bps column.
    pkill -f 'iperf3 -s' 2>/dev/null || true
    sleep 0.3
    iperf3 -s -B "${HOST_IP}" -p 5201 > "${rundir}/iperf-server.err" 2>&1 &
    IPERF_PID=$!

    # Wait until the server is actually LISTENing (port 5201 == hex 0x1451 in
    # /proc/net/tcp) and surface a bind failure instead of zeroed TCP rows.
    for _ in $(seq 1 20); do
        awk 'NR>1{print $2}' /proc/net/tcp 2>/dev/null | grep -q ':1451' && break
        sleep 0.1
    done
    if ! awk 'NR>1{print $2}' /proc/net/tcp 2>/dev/null | grep -q ':1451'; then
        log "WARN: backend=${backend} scenario=${scenario} iter=${iter}: iperf3 server not listening on :5201 (see ${rundir}/iperf-server.err)"
    fi

    local cpu0 cpu1
    sample_cpu cpu0

    if [ "${backend}" = xdp ]; then
        snap_xdp_stats "${rundir}/stats-before.json"
    else
        snap_nft_counters "${rundir}/nft-before.json"
    fi

    local udp_kv="/dev/null" udp2_kv="/dev/null" tcp_kv="/dev/null" flood_kv="/dev/null"
    if [ "${scenario}" = drop ]; then
        # iperf3 cannot drive `drop`: its TCP control channel is dropped with
        # the workload, so no DATA would ever flow. Use a raw-UDP flood for the
        # offered load; the hook-side DROP rate below is the ground truth.
        if run_flood "${DURATION}" > "${rundir}/flood.kv" 2>>"${rundir}/flood.err"; then
            flood_kv="${rundir}/flood.kv"
        fi
    else
        if run_iperf udp "${DURATION}" "${rundir}/iperf-udp.json" \
            > "${rundir}/udp.kv" 2>>"${rundir}/udp.err"; then
            udp_kv="${rundir}/udp.kv"
        else
            udp_kv="/dev/null"
        fi
        if [ "${UDP_CTL_BW:-1500M}" != 0 ] \
            && run_iperf udp "${DURATION}" "${rundir}/iperf-udp-ctl.json" "${UDP_CTL_BW:-1500M}" \
            > "${rundir}/udp2.kv" 2>>"${rundir}/udp2.err"; then
            udp2_kv="${rundir}/udp2.kv"
        else
            udp2_kv="/dev/null"
        fi
        if run_iperf tcp "${DURATION}" "${rundir}/iperf-tcp.json" \
            > "${rundir}/tcp.kv" 2>>"${rundir}/tcp.err"; then
            tcp_kv="${rundir}/tcp.kv"
        else
            tcp_kv="/dev/null"
        fi
        run_ping 20 "${rundir}/ping.txt" > "${rundir}/rtt.kv" 2>/dev/null || true
    fi
    sample_cpu cpu1

    if [ "${backend}" = xdp ]; then
        snap_xdp_stats "${rundir}/stats-after.json"
    else
        snap_nft_counters "${rundir}/nft-after.json"
    fi

    kill "${IPERF_PID}" 2>/dev/null || true
    IPERF_PID=""

    local bps pps loss jitter tcp_bps rtt mem addr del drop_pps udp2_bps udp2_pps udp2_loss udp2_jitter flood_sent
    bps="$(kv "${udp_kv}" udp_bits_per_sec)";        [ -z "${bps}" ]    && bps=0
    pps="$(kv "${udp_kv}" udp_sent_packets)";         [ -z "${pps}" ]    && pps=0
    pps=$(( pps / DURATION ))
    loss="$(kv "${udp_kv}" udp_lost_packets)";        [ -z "${loss}" ]   && loss=0
    jitter="$(kv "${udp_kv}" udp_jitter_ms)";         [ -z "${jitter}" ] && jitter=0
    tcp_bps="$(kv "${tcp_kv}" tcp_bits_per_sec)";     [ -z "${tcp_bps}" ] && tcp_bps=0
    rtt="$(kv "${rundir}/rtt.kv" rtt_avg_ms)";        [ -z "${rtt}" ]    && rtt="n/a"
    mem="$(backend_mem_kb "${backend}")"
    read -r addr del <<< "$(update_timing "${backend}")"

    # Hook-side DROP rate: XDP from fc_stats deltas, nft from rule counters.
    if [ "${backend}" = xdp ]; then
        drop_pps="$(xdp_drop_delta "${rundir}")"
    else
        drop_pps="$(nft_drop_delta "${rundir}")"
    fi
    [ -z "${drop_pps}" ] && drop_pps=0
    drop_pps=$(( drop_pps / DURATION ))

    udp2_bps="$(kv "${udp2_kv}" udp_bits_per_sec)";      [ -z "${udp2_bps}" ]    && udp2_bps=0
    udp2_pps="$(kv "${udp2_kv}" udp_sent_packets)";      [ -z "${udp2_pps}" ]    && udp2_pps=0
    udp2_pps=$(( udp2_pps / DURATION ))
    udp2_loss="$(kv "${udp2_kv}" udp_lost_packets)";     [ -z "${udp2_loss}" ]   && udp2_loss=0
    udp2_jitter="$(kv "${udp2_kv}" udp_jitter_ms)";      [ -z "${udp2_jitter}" ] && udp2_jitter=0
    flood_sent="$(kv "${flood_kv}" flood_sent)";         [ -z "${flood_sent}" ] && flood_sent=0

    # In `drop` zero throughput is the expected success (every workload packet
    # is dropped before delivery), so those rows must not WARN.
    if [ "${scenario}" != drop ] && is_zero "${bps}"; then
        log "WARN: backend=${backend} scenario=${scenario} iter=${iter}: udp_bps=0 (iperf or metric-parser problem)"
    fi
    if [ "${scenario}" != drop ] && is_zero "${tcp_bps}"; then
        log "WARN: backend=${backend} scenario=${scenario} iter=${iter}: tcp_bps=0 (iperf server, run, or metric-parser problem; see ${rundir}/iperf-server.err)"
    fi
    if [ "${UDP_CTL_BW:-1500M}" != 0 ] && [ "${scenario}" != drop ] && is_zero "${udp2_bps}"; then
        log "WARN: backend=${backend} scenario=${scenario} iter=${iter}: udp2_bps=0 (controlled UDP pass failed)"
    fi
    if [ "${scenario}" = drop ] && is_zero "${flood_sent}"; then
        log "WARN: backend=${backend} scenario=drop iter=${iter}: flood offered 0 packets (sender or datapath problem; see ${rundir}/flood.kv)"
    fi

    [ "${backend}" = xdp ] && log_xdp_delta "${rundir}"

    printf '%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\n' \
        "${RUN_TS}" "${backend}" "${scenario}" "${iter}" \
        "${bps}" "${pps}" "${loss}" "${jitter}" "${tcp_bps}" "${rtt}" \
        "$(cpu_delta "${cpu0}" "${cpu1}")" "${mem}" "${addr}" "${del}" \
        "${drop_pps}" "${udp2_bps}" "${udp2_pps}" "${udp2_loss}" "${udp2_jitter}" \
        "${flood_sent}" \
        >> "${SUMMARY}"
    log "  udp_bps=${bps} pps=${pps} loss=${loss} tcp_bps=${tcp_bps} rtt=${rtt} mem=${mem} add=${addr}ms del=${del}ms udp2_bps=${udp2_bps} drop_pps=${drop_pps} flood_sent=${flood_sent}"
}

# --- main ------------------------------------------------------------------

sandbox_up
host_firewall_open

printf 'run\tbackend\tscenario\titer\tudp_bps\tudp_pps\tudp_lost\tudp_jitter_ms\ttcp_bps\trtt_avg_ms\tcpu_jif\trss_kb\tadd_ms\tdel_ms\tdrop_pps\tudp2_bps\tudp2_pps\tudp2_lost\tudp2_jitter_ms\tflood_sent\n' \
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
host_firewall_close
nft_rules_down
reset_results_owner
trap - EXIT
log "done. Summary:"
cat "${SUMMARY}" | sed 's/^/  /'
log "raw logs + summary saved under ${RUN_DIR}"