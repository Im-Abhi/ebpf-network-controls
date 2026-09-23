#!/usr/bin/env bash
# fw-smoke.sh — live smoke test for the priority + conntrack features.
# Runs the daemon on a disposable veth+netns, drives real TCP traffic through
# it from inside the namespace, and asserts the documented verdicts.
#
# Requires root (veth/netns, XDP attach, iptables). Build the binaries first:
#   make generate && make build
# then:
#   sudo bash integration/fw-smoke.sh
#
# The sandbox also adds an iptables INPUT ACCEPT on the test veth so a host
# firewalling service (e.g. UFW) cannot interfere with the checks; it is
# removed on exit.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
SOCK=/var/run/fw-smoke.sock
NS_NAME=fwtns
V0=fwtest0
V1=fwtest1
HOST_IP=10.99.0.1
NS_IP=10.99.0.2
PORT=5000
SPY=$(dirname "$0")/smoke.py
DIR=$(mktemp -d -t fw-smoke.XXXXXX)
LOG=$DIR/fw-smoke.log

CTL="$REPO/bin/firewallctl -sock $SOCK"
NS="ip netns exec $NS_NAME"

pass=0
fail=0
P() { pass=$((pass+1)); echo "PASS: $*"; }
F() { fail=$((fail+1)); echo "FAIL: $*"; }
ck() { if [ "$1" = "$2" ]; then P "$3"; else F "$3 (got '$1' want '$2')"; fi; }

ctl() { "$REPO/bin/firewallctl" -sock "$SOCK" "$@"; }

drop_cnt() { ctl stats | sed -n 's/.*Dropped:[[:space:]]*\([0-9]*\).*/\1/p' | head -1; }
pass_cnt() { ctl stats | sed -n 's/.*Passed:[[:space:]]*\([0-9]*\).*/\1/p' | head -1; }

ct_states() { ctl conntrack | grep -o '\[[a-z]*\]' | sort | uniq -c | sed 's/^ *//'; }
ct_state_for() { # $1=srcport -> established/new/closed/none
    local s
    s=$(ctl conntrack | grep ":${1} ->" | grep -o '\[[a-z]*\]' | head -1 | tr -d '[]')
    echo "${s:-none}"
}

FW_PID=
SRV_PID=

cleanup() {
    set +e
    [ -n "$FW_PID" ] && kill "$FW_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    # kill anything still running inside the namespace so `ip netns del` can proceed
    { ip netns pids "$NS_NAME" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done; }
    sleep 0.3
    ip netns del "$NS_NAME" 2>/dev/null
    ip link del "$V0" 2>/dev/null
    iptables -D INPUT -i "$V0" -j ACCEPT 2>/dev/null
    rm -f "$SOCK"
    echo "--- cleanup done ---"
}
trap 'cleanup; rm -rf "$DIR"' EXIT

# ---- bring up the sandbox --------------------------------------------------
cleanup
set -e
ip netns add "$NS_NAME"
ip link add "$V0" type veth peer name "$V1"
ip link set "$V1" netns "$NS_NAME"
ip addr add "$HOST_IP/24" dev "$V0"
ip link set "$V0" up
$NS ip addr add "$NS_IP/24" dev "$V1"
$NS ip link set lo up
$NS ip link set "$V1" up
$NS ip route add default via "$HOST_IP"

# static neighbours: default-deny drops ARP (non-IPv4 -> default policy), so
# preload neighbour entries to keep link-layer working under deny.
MAC0=$(ip link show "$V0" | awk '/link\/ether/{print $2}')
MAC1=$($NS ip link show "$V1" | awk '/link\/ether/{print $2}')
ip neigh add "$NS_IP" lladdr "$MAC1" dev "$V0" nud permanent || true
$NS ip neigh add "$HOST_IP" lladdr "$MAC0" dev "$V1" nud permanent || true

# disable IPv6 on the sandbox veth: the netns emits link-local DAD/RS/MLD
# which hits the XDP hook and, under default-deny, adds stray drops that make
# the drop-counter deltas non-deterministic.
sysctl -q -w net.ipv6.conf.$V0.disable_ipv6=1 || true
$NS sysctl -q -w net.ipv6.conf.$V1.disable_ipv6=1 || true

# host UFW (iptables-nft) drops NEW inbound TCP on the sandbox veth by
# default; allow INPUT on the sandbox interface for the duration of the test
# so the eBPF firewall alone decides connectivity. Removed in cleanup.
iptables -I INPUT 1 -i "$V0" -j ACCEPT 2>/dev/null || true

python3 "$SPY" server "$PORT" > "$DIR/srv.out" 2>&1 &
SRV_PID=$!
sleep 0.2

rm -f "$SOCK"
"$REPO/bin/firewall" -i "$V0" -sock "$SOCK" > "$LOG" 2>&1 &
FW_PID=$!
for _ in $(seq 1 20); do [ -S "$SOCK" ] && break; sleep 0.2; done
[ -S "$SOCK" ] || { echo "daemon socket never appeared"; exit 1; }
set +e

echo "=== daemon attached (status) ==="
ctl status

# ---- CHECK 1: default-allow passthrough; conntrack skipped -----------------
echo
echo "===== CHECK 1: default allow, no rules; conntrack skipped ====="
ctl conntrack | grep -q "no tracked flows" && P "1a conntrack empty with no traffic" \
    || F "1a conntrack not empty by default"
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 0 HELO > "$DIR/c1.out" 2>&1
ck "$?" "0" "1b plain TCP passthrough under default-allow works"
ctl conntrack | grep -q "no tracked flows" && P "1c conntrack stays empty under default-allow" \
    || F "1c conntrack populated under default-allow (fast-path must be skipped)"

# ---- CHECK 2: priority matrix ----------------------------------------------
echo
echo "===== CHECK 2: rule priority (highest wins; tie keeps most-specific) ====="
ctl clear
ctl block "$HOST_IP" --protocol tcp --dport "$PORT"           # broad DROP, prio 0
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --sport 40000 --action pass --priority 10
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 35002 HELO > "$DIR/c.out" 2>&1
[ $? -eq 0 ] && F "2a higher-prio PASS did NOT override broad DROP" \
              || P "2a higher-prio PASS overrides broad lower-prio DROP"
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 40000 HELO > "$DIR/c.out" 2>&1
ck "$?" "0" "2b higher-prio PASS (sport-scoped) lets the connection through"
ctl listports | grep -q "prio 10" && P "2c listports shows priorities" \
    || F "2c listports missing priority column"

ctl clear
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --action drop --priority 10
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --sport 40000 --action pass --priority 5
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 40000 HELO > "$DIR/c.out" 2>&1
[ $? -eq 0 ] && F "2d higher-prio broad DROP did not beat lower-prio PASS" \
              || P "2d higher-prio broad DROP beats more-specific lower-prio PASS"

ctl clear
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --action drop
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --sport 40000 --action pass
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 40000 HELO > "$DIR/c.out" 2>&1
ck "$?" "0" "2e equal-prio: most-specific PASS wins over broad DROP"
$NS python3 "$SPY" client "$HOST_IP" "$PORT" 35004 HELO > "$DIR/c.out" 2>&1
[ $? -eq 0 ] && F "2f equal-prio: broad DROP should apply to other src ports" \
              || P "2f equal-prio: broad DROP still applies to other src ports"

# ---- CHECK 3: conntrack ----------------------------------------------------
echo
echo "===== CHECK 3: conntrack (default-deny) ====="
ctl clear
ctl default deny
ctl conntrack | grep -q "no tracked flows" && P "3a conntrack empty after clear+deny" \
    || F "3a conntrack not empty"

D0=$(drop_cnt)
$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39001 ACK
sleep 0.2
ck "$(( $(drop_cnt) - D0 ))" "1" "3b bare ACK (no prior SYN) is denied under default-deny"
ctl conntrack | grep -q "no tracked flows" && P "3c spoofed ACK created no state" \
    || F "3c spoofed ACK fabricated state (must never happen)"

ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --action pass
rm -f "$DIR/go.39002"
$NS python3 "$SPY" keep "$HOST_IP" "$PORT" 39002 "$DIR/go.39002" MIDSTREAM > "$DIR/keep.out" 2>&1 &
KP=$!
sleep 0.8
grep -q "CONNECTED" "$DIR/keep.out" && P "3d connection allowed by --action pass rule" \
    || { F "3d connection refused under the allow rule"; kill "$KP" 2>/dev/null; }
ck "$(ct_state_for 39002)" "established" "3e flow reaches ESTABLISHED in conntrack"

# connection is now established while the allow rule is still present; drop the
# rule and let the keep-client send on the open connection.
ctl unblock "$HOST_IP" --protocol tcp --dport "$PORT"
sleep 0.3
ck "$(ct_state_for 39002)" "established" "3f established flow still tracked after rule removal"
touch "$DIR/go.39002"
wait "$KP"; KRC=$?
ck "$KRC" "0" "3g established flow passes AFTER rule removed (stateful fast-path)"
sleep 0.5

D0=$(drop_cnt)
$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39003 SYN
sleep 0.2
ck "$(( $(drop_cnt) - D0 ))" "1" "3i NEW flow (raw SYN) is denied under default-deny"
ck "$(ct_state_for 39003)" "none" "3j denied SYN created no conntrack state"

$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39002 FIN
sleep 0.2
ck "$(ct_state_for 39002)" "closed" "3k FIN transitions flow to CLOSED"
D0=$(drop_cnt)
$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39002 ACK
sleep 0.2
ck "$(( $(drop_cnt) - D0 ))" "1" "3l packet on CLOSED flow is denied again"

# ---- CHECK 4: clear wipes rules + conntrack together -----------------------
echo
echo "===== CHECK 4: clear empties rules and conntrack ====="
ctl clear
ctl list | grep -q "no blocked"  && P "4a blocklist empty after clear"  || F "4a blocklist not empty"
ctl listports | grep -q "no port rules" && P "4b port rules empty after clear" || F "4b port rules not empty"
ctl conntrack | grep -q "no tracked flows" && P "4c conntrack empty after clear" || F "4c conntrack not empty"
D0=$(drop_cnt)
$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39009 SYN
sleep 0.2
ck "$(( $(drop_cnt) - D0 ))" "1" "4d a fresh SYN under default-deny (no rules) is denied"

# ---- CHECK 5: reaper --------------------------------------------------------
echo
echo "===== CHECK 5: conntrack reaper (-ct-timeout 5s) ====="
kill "$FW_PID" 2>/dev/null; wait "$FW_PID" 2>/dev/null
FW_PID=
rm -f "$SOCK"
"$REPO/bin/firewall" -i "$V0" -sock "$SOCK" -ct-timeout 5s > "$LOG" 2>&1 &
FW_PID=$!
for _ in $(seq 1 20); do [ -S "$SOCK" ] && break; sleep 0.2; done
ctl default deny
ctl block "$HOST_IP" --protocol tcp --dport "$PORT" --action pass
rm -f "$DIR/go.39010"
$NS python3 "$SPY" keep "$HOST_IP" "$PORT" 39010 "$DIR/go.39010" IDLE > "$DIR/keep.out" 2>&1 &
KP=$!
sleep 0.8
grep -q "CONNECTED" "$DIR/keep.out" && P "5a flow established for the reaper test" \
    || F "5a failed to establish flow for reaper test"
ck "$(ct_state_for 39010)" "established" "5b tracked as established"
sleep 8
ctl conntrack | grep -q "no tracked flows" && P "5c idle flow reaped after timeout" \
    || F "5c idle flow NOT reaped ($(ctl conntrack))"
grep -q "reaped" "$LOG" && P "5d daemon logged the reap" || F "5d no reap log line in $LOG"
ctl unblock "$HOST_IP" --protocol tcp --dport "$PORT"
D0=$(drop_cnt)
$NS python3 "$SPY" raw "$HOST_IP" "$PORT" 39010 ACK
sleep 0.2
ck "$(( $(drop_cnt) - D0 ))" "1" "5e packet on reaped flow is denied (state gone)"
kill "$KP" 2>/dev/null

# ---- summary ----------------------------------------------------------------
echo
echo "================ SUMMARY ================"
echo "PASS: $pass  FAIL: $fail"
[ "$fail" -eq 0 ] && echo "ALL SMOKE CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"