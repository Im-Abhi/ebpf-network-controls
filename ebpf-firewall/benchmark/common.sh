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
EBPF_DIR="${REPO_DIR}/control/ebpf"
BPF_DIR="${REPO_DIR}/bpf"
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
all_scenarios=(none single forward many drop)

scenario_targets() {
    case "$1" in
    none)   : ;;
    single) echo "198.51.100.7/32" ;;
    forward) echo "${FORWARD_CIDR}" ;;
    many)
        # 1000 distinct /30 prefixes in a 10.10.0.0/19 block. Deterministic,
        # generated once and reused for every backend so counts match exactly.
        seq 0 999 | awk '{ f = $1 * 4; printf "10.10.%d.%d/30\n", int(f / 256), f % 256 }'
        ;;
    drop)
        # The sandbox's own LAN (HOST_IP x NS_IP): every workload packet that
        # crosses the hook matches, so this exercises the DROP decision path
        # end-to-end instead of pass-through.
        echo "10.200.0.0/24"
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

# is_zero <number-or-empty> : true when the value (possibly float, possibly
# empty) numerically equals 0 — the WARN guards in the orchestrator cannot use
# `[ -eq ]` as jq may report fractional bits-per-second. Uses a BEGIN block so
# it never depends on awk receiving input (mawk runs no pattern action at EOF).
is_zero() {
    awk -v v="${1}" 'BEGIN { exit ((v + 0) == 0 ? 0 : 1) }'
}

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

# check_bpf_object_fresh : true when the embedded BPF object exists and is
# newer than every bpf/ source it is generated from. The object (//go:embed
# firewall_bpf.o) is a bpf2go artifact and is NOT tracked in git, so a clone or
# pull can leave a stale one that no longer matches the generated Go bindings
# (the daemon then fails at load with "missing map <name>"). run-bench.sh
# refuses to run until `make generate` / `make bench` has refreshed it.
check_bpf_object_fresh() {
    local obj="${EBPF_DIR}/firewall_bpf.o" src
    [ -f "${obj}" ] || return 1
    for src in "${BPF_DIR}"/*.c "${BPF_DIR}"/*.h; do
        [ -f "${src}" ] || continue
        [ "${obj}" -nt "${src}" ] || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Traffic measurement (iperf3 + python3 flood + ping)
# ---------------------------------------------------------------------------

# run_iperf <udp|tcp> <duration> <json_out> : iperf3 client inside the sandbox
# netns. The iperf3 client is the sender by default, so the bulk DATA crosses
# the host-side XDP hook / nft INPUT chain; `.end.sum_received` (populated on
# send) carries the true datapath throughput. The UDP pass is unthrottled by
# default (`UDP_BW=0`) so loss/jitter/pps at saturation discriminate the
# backends; override with UDP_BW, e.g. `UDP_BW=500M`.
run_iperf() {  # run_iperf <udp|tcp> <dur> <json_out> [bw] ; bw overrides UDP_BW
    local mode="$1" dur="$2" out="$3" bw="${4:-}" extra=()
    if [ "${mode}" = udp ]; then
        extra=(-u -b "${bw:-${UDP_BW:-0}}")
    fi
    if ! ns_exec iperf3 -c "${HOST_IP}" -p 5201 -t "${dur}" "${extra[@]}" \
         -J > "${out}" 2>/dev/null; then
        echo "bench: iperf3 ${mode} run failed" >&2
        return 1
    fi
    # Print derived key/value lines for the summary (same format either way, so
    # the kv() reader downstream never changes). jq is preferred; when it is
    # missing the stdlib json module (part of every python3) does the same job,
    # so no metric extraction tool is actually required. A JSON that cannot be
    # read yields `parse_failed=1`, which the orchestrator surfaces as a WARN.
    if command -v jq >/dev/null 2>&1; then
        if [ "${mode}" = udp ]; then
            jq -r '"udp_bits_per_sec=\(.end.sum.bits_per_second)\nudp_bytes=\(.end.sum.bytes)\nudp_lost_packets=\(.end.sum.lost_packets)\nudp_sent_packets=\(.end.sum.packets)\nudp_jitter_ms=\(.end.sum.jitter_ms)"' "${out}"
        else
            jq -r '"tcp_bits_per_sec=\(.end.sum_received.bits_per_second)\ntcp_bytes_retrans=\(.end.sum_received.retransmits)"' "${out}"
        fi
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "${out}" "${mode}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except Exception:
    print("parse_failed=1")
    sys.exit(0)

if sys.argv[2] == "udp":
    s = d["end"]["sum"]
    print("udp_bits_per_sec=%d" % s["bits_per_second"])
    print("udp_bytes=%d" % s["bytes"])
    print("udp_lost_packets=%d" % s["lost_packets"])
    print("udp_sent_packets=%d" % s["packets"])
    print("udp_jitter_ms=%s" % s["jitter_ms"])
else:
    s = d["end"]["sum_received"]
    print("tcp_bits_per_sec=%d" % s["bits_per_second"])
    print("tcp_bytes_retrans=%d" % s["retransmits"])
PY
    else
        echo "parser_missing=1 (install jq or python3)"
    fi
}

# run_ping <rounds> <out> : RTT stats from the ns to the host.
run_ping() {
    local rounds="$1" out="$2"
    ns_exec ping -c "${rounds}" -i 0.05 -q "${HOST_IP}" > "${out}" 2>&1 || true
    awk '/rtt/{split($4, a, "/"); print "rtt_min_ms=" a[1]; print "rtt_avg_ms=" a[2]; print "rtt_max_ms=" a[3]}' \
        "${out}" 2>/dev/null || true
}

# run_flood <duration> : raw-UDP offered load from inside the sandbox. iperf3
# cannot drive the `drop` scenario — every mode opens a TCP control connection
# first, and the firewall blocks that SYN with the workload, so no DATA ever
# flows. This python3 sendto loop needs no control channel: it floods 1400-byte
# datagrams at HOST_IP:5201 for <duration> seconds and prints `flood_sent=N`
# on stdout (redirected by the caller).
run_flood() {
    local dur="$1"
    ns_exec python3 - "${dur}" "${HOST_IP}" <<'PY' 2>/dev/null || { echo "flood_failed=1"; return 1; }
import socket
import sys
import time

dur = float(sys.argv[1])
host = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(False)
payload = b"\x00" * 1400
start = time.monotonic()
sent = 0
while time.monotonic() - start < dur:
    try:
        s.sendto(payload, (host, 5201))
        sent += 1
    except BlockingIOError:
        pass
print("flood_sent=%d" % sent)
PY
}

# snap_xdp_stats <json-file> : dumps the firewall's raw packet/byte counters
# (via the one-shot JSON control socket) so the orchestrator can log how much
# traffic actually crossed the XDP hook. Best-effort; writes nothing on failure.
snap_xdp_stats() {
    python3 - "$1" <<'PY'
import json
import socket
import sys

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect("/var/run/ebpf-firewall.sock")
    s.sendall(b'{"command":"stats"}\n')
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    d = json.loads(buf)
    with open(sys.argv[1], "w") as f:
        json.dump(d.get("stats", {}), f)
except Exception:
    pass
PY
}

# log_xdp_delta <rundir> : prints how many packets/bytes crossed the XDP hook
# between the rundir/stats-before and stats-after snapshots (xdp rows only).
log_xdp_delta() {
    python3 - "$1" <<'PY'
import json
import os
import sys

def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

b = load(os.path.join(sys.argv[1], "stats-before.json"))
a = load(os.path.join(sys.argv[1], "stats-after.json"))
if not b or not a:
    sys.exit(0)
def d(k):
    return a.get(k, 0) - b.get(k, 0)
    print("  fw-crossing: +pass-pkts=%d +pass-bytes=%d +drop-pkts=%d (datapath saw the traffic)" % (d("pass_packets"), d("pass_bytes"), d("drop_packets")))
PY
}

# snap_nft_counters <file> : dumps the nft benchmark table as JSON so the
# orchestrator can read hook-side drop counters (the `drop` scenario installs
# rules with a `counter` statement). Best-effort like snap_xdp_stats.
snap_nft_counters() {
    nft -j list table inet "${NFT_TABLE}" > "$1" 2>/dev/null || true
}

# xdp_drop_delta <rundir> : hook-side dropped-packet delta between the
# stats-before.json and stats-after.json snapshots (xdp rows only); empty on
# failure. DROP rate = delta / duration (computed by the orchestrator).
xdp_drop_delta() {
    python3 - "$1" <<'PY'
import json
import os
import sys

def load(p):
    try:
        with open(p) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

b = load(os.path.join(sys.argv[1], "stats-before.json"))
a = load(os.path.join(sys.argv[1], "stats-after.json"))
if not b or not a:
    raise SystemExit(0)
print(a.get("drop_packets", 0) - b.get("drop_packets", 0))
PY
}

# nft_drop_delta <rundir> : sum of `counter` packet counts across the nft
# benchmark table between the nft-before.json and nft-after.json snapshots.
nft_drop_delta() {
    python3 - "$1" <<'PY'
import json
import os
import sys

def total(p):
    try:
        with open(p) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return 0
    n = 0
    for t in d.get("nftables", []):
        rule = t.get("rule")
        if not rule:
            continue
        for e in rule.get("expr", []):
            c = e.get("counter")
            if c:
                n += int(c.get("packets", 0))
    return n

b = total(os.path.join(sys.argv[1], "nft-before.json"))
a = total(os.path.join(sys.argv[1], "nft-after.json"))
print(a - b)
PY
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

# valid_cidr <token> : accepts "A.B.C.D/len" with octets 0-255 and len 0-32.
# Guards rule installation so a buggy scenario generator fails fast with the
# offending token instead of failing silently part-way through the matrix.
valid_cidr() {
    [[ "$1" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$ ]] || return 1
    local o
    for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
             "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        [ "${o}" -le 255 ] || return 1
    done
    [ "${BASH_REMATCH[5]}" -le 32 ] || return 1
}

# apply_xdp_rules <scenario> : adds drop rules via firewallctl (daemon must be
# attached to ${VETH0}). Mirrors saddr+daddr semantics of the C datapath:
# blocked_ips matches source first, then destination.
apply_xdp_rules() {
    local ip targets
    targets="$(scenario_targets "$1")" || return 1
    while read -r ip; do
        [ -n "${ip}" ] || continue
        valid_cidr "${ip}" || { echo "bench: invalid CIDR target '${ip}' (scenario '$1')" >&2; return 1; }
        "${CTL}" block "${ip}" || return 1
    done <<< "${targets}"
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

# ---------------------------------------------------------------------------
# Host firewall exception for the sandbox link
# ---------------------------------------------------------------------------

# Host firewalls (notably ufw) default-deny INPUT: they would silently drop the
# new SYNs the iperf3 server needs, zeroing every throughput row while ping
# (ICMP) still works. The harness runs as root, so it inserts one accept rule
# for the bench veth at the top of the discovered base chain that handles
# INPUT on family inet (falling back to ip), and deletes it on teardown.
# Hosts with no such chain (no nftables firewall) get a no-op.
HOST_FW_FAM=""
HOST_FW_TAB=""
HOST_FW_CHAIN=""
HOST_FW_HANDLE=""

host_firewall_open() {
    command -v nft >/dev/null 2>&1 || return 0
    [ -z "${HOST_FW_HANDLE}" ] || return 0   # already open

    local def
    def="$(nft list ruleset 2>/dev/null | awk '
        /^table / && $2=="inet" { t=$3; fam="inet" }
        /^table / && $2=="ip"   { t=$3; fam="ip" }
        /^[[:space:]]+chain /   { c=$2 }
        /type filter hook input priority/ {
            if (fam=="inet") { print "inet", t, c; exit }
            if (!f && fam=="ip") f="ip " t " " c
        }
        END { if (f) print f }
    ' | head -1)"
    [ -n "${def}" ] || {
        log "WARN: no inet/ip INPUT base chain to open — host firewall (if any) not opened for ${VETH0}"
        return 0
    }

    read -r HOST_FW_FAM HOST_FW_TAB HOST_FW_CHAIN <<< "${def}"
    if HOST_FW_HANDLE="$(
        nft insert rule "${HOST_FW_FAM}" "${HOST_FW_TAB}" "${HOST_FW_CHAIN}" iifname "${VETH0}" accept 2>/dev/null \
            && nft -a list chain "${HOST_FW_FAM}" "${HOST_FW_TAB}" "${HOST_FW_CHAIN}" 2>/dev/null \
            | awk -v v="${VETH0}" '$0 ~ v {print $NF; exit}'
    )"; then
        if [ -n "${HOST_FW_HANDLE}" ]; then
            log "opened host firewall for ${VETH0} (nft ${HOST_FW_FAM} ${HOST_FW_TAB}/${HOST_FW_CHAIN}, handle ${HOST_FW_HANDLE})"
        else
            local __fam="${HOST_FW_FAM}" __tab="${HOST_FW_TAB}" __chn="${HOST_FW_CHAIN}"
            HOST_FW_FAM=""
            HOST_FW_TAB=""
            HOST_FW_CHAIN=""
            HOST_FW_HANDLE=""
            log "WARN: host firewall rule for ${VETH0} inserted but handle not confirmed — cannot guarantee cleanup"
            log "       discovered chain: nft ${__fam} ${__tab}/${__chn}"
        fi
    else
        local __fam="${HOST_FW_FAM}" __tab="${HOST_FW_TAB}" __chn="${HOST_FW_CHAIN}"
        HOST_FW_FAM=""
        HOST_FW_TAB=""
        HOST_FW_CHAIN=""
        HOST_FW_HANDLE=""
        log "WARN: could not insert host-firewall accept rule for ${VETH0}"
        log "       discovered chain: nft ${__fam} ${__tab}/${__chn}"
        log "       a host firewall may still block the iperf port (zeroed rows)"
    fi
}

host_firewall_close() {
    if [ -n "${HOST_FW_HANDLE}" ]; then
        nft delete rule "${HOST_FW_FAM}" "${HOST_FW_TAB}" "${HOST_FW_CHAIN}" handle "${HOST_FW_HANDLE}" 2>/dev/null || true
        log "closed host firewall (deleted handle ${HOST_FW_HANDLE} from ${HOST_FW_FAM} ${HOST_FW_TAB}/${HOST_FW_CHAIN})"
    fi
    HOST_FW_FAM=""
    HOST_FW_TAB=""
    HOST_FW_CHAIN=""
    HOST_FW_HANDLE=""
}

apply_nft_rules() {
    local ip targets counter=""
    targets="$(scenario_targets "$1")" || return 1
    # The `drop` scenario targets the sandbox LAN: XDP drops on the source
    # (src-first lookup), so nft mirrors it with a single `saddr` rule. The
    # `counter` statement gives nft a hook-side drop count (read by
    # snap_nft_counters); every other scenario stays counter-free so its rows
    # match the locked baseline exactly.
    [ "$1" = drop ] && counter=" counter"
    while read -r ip; do
        [ -n "${ip}" ] || continue
        valid_cidr "${ip}" || { echo "bench: invalid CIDR target '${ip}' (scenario '$1')" >&2; return 1; }
        if [ -n "${counter}" ]; then
            nft add rule inet "${NFT_TABLE}" input ip saddr "${ip}" counter drop
        else
            nft add rule inet "${NFT_TABLE}" input ip saddr "${ip}" drop
            nft add rule inet "${NFT_TABLE}" input ip daddr "${ip}" drop
        fi
    done <<< "${targets}"
}
