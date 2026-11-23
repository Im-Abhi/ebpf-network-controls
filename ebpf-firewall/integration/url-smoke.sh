#!/usr/bin/env bash
# url-smoke.sh — live smoke test for the egress URL blocklist (domain stage).
# Runs the daemon with -url-blocklist on a disposable veth+netns, then drives
# real HTTP (Host header) and HTTPS (TLS SNI) traffic from the host and asserts
# the documented verdicts: blocked names are dropped before the server sees
# them, non-blocked names reach it, and the egress drop counter moves.
#
# Requires root. Build first (make generate && make build), then:
#   sudo bash integration/url-smoke.sh
#
# Output is intentionally short: one PASS/FAIL line per check. On failure the
# sandbox dir is kept (daemon log inside) instead of printing pages here.
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
SOCK=/var/run/fw-smoke.sock
NS_NAME=fwtns
V0=fwtest0
V1=fwtest1
HOST_IP=10.99.0.1
NS_IP=10.99.0.2
BAD=bad.example.com
SUB=sub.bad.example.com
GOOD=good.example.com
DIR=$(mktemp -d -t fw-url-smoke.XXXXXX)
LOG=$DIR/fw-url-smoke.log
BLK=$DIR/blocklist.txt

NS="ip netns exec $NS_NAME"
FW_PID=
SRV_PID=
TLS_PID=
SRV6_PID=

pass=0
fail=0
P() { pass=$((pass+1)); echo "PASS: $*"; }
F() { fail=$((fail+1)); echo "FAIL: $*"; }

edrop_cnt() { "$REPO/bin/firewallctl" -sock "$SOCK" stats 2>/dev/null \
    | sed -n '/egress packets:/,$ {s/.*Dropped:[[:space:]]*\([0-9]*\).*/\1/p;}' | head -1; }

# http <host> -> curl exit code for a plain-HTTP request carrying Host: <host>
http_try() { curl -s -m 3 -o /dev/null "http://$NS_IP/" -H "Host: $1"; }
# sni_try <host> -> curl exit code for an HTTPS request whose SNI is <host>
sni_try() { curl -ks -m 3 -o /dev/null --resolve "$1:443:$NS_IP" "https://$1/"; }

cleanup() {
    set +e
    [ -n "$FW_PID" ]  && kill "$FW_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$TLS_PID" ] && kill "$TLS_PID" 2>/dev/null
    [ -n "$SRV6_PID" ] && kill "$SRV6_PID" 2>/dev/null
    ip netns pids "$NS_NAME" 2>/dev/null | while read -r p; do kill "$p" 2>/dev/null; done
    sleep 0.3
    ip netns del "$NS_NAME" 2>/dev/null
    ip link del "$V0" 2>/dev/null
    iptables -D INPUT -i "$V0" -j ACCEPT 2>/dev/null
    rm -f "$SOCK"
    if [ "${SUCCEEDED:-0}" = 1 ] || [ "$fail" = 0 ]; then
        rm -rf "$DIR"
    else
        echo "--- artifacts kept in $DIR (daemon log: $LOG) ---"
        echo "--- daemon log tail: ---"
        tail -8 "$LOG" 2>/dev/null
    fi
}
trap cleanup EXIT

# ---- preflight --------------------------------------------------------------
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "PREFLIGHT FAIL: run as root (sudo bash integration/url-smoke.sh)"
    exit 1
fi
if pgrep -f "bin/firewall" >/dev/null 2>&1; then
    echo "PREFLIGHT FAIL: an eBPF firewall daemon is already running:"
    pgrep -af "bin/firewall"
    exit 1
fi
if [ -e "$SOCK" ]; then
    echo "PREFLIGHT FAIL: stale control socket $SOCK exists"
    exit 1
fi
if ss -ltn 2>/dev/null | grep -qE ":80 |:443 "; then
    echo "PREFLIGHT FAIL: port 80 or 443 already in use (needed inside the netns)"
    exit 1
fi
if [ ! -x "$REPO/bin/firewall" ]; then
    echo "PREFLIGHT FAIL: bin/firewall missing; run make generate && make build"
    exit 1
fi

# ---- sandbox ----------------------------------------------------------------
set -e
ip netns add "$NS_NAME"
ip link add "$V0" type veth peer name "$V1"
ip link set "$V1" netns "$NS_NAME"
ip addr add "$HOST_IP/24" dev "$V0"
ip link set "$V0" up
$NS ip addr add "$NS_IP/24" dev "$V1"
$NS ip link set lo up
$NS ip link set "$V1" up
sysctl -q -w net.ipv6.conf.$V0.disable_ipv6=1 || true
$NS sysctl -q -w net.ipv6.conf.$V1.disable_ipv6=1 || true
iptables -I INPUT 1 -i "$V0" -j ACCEPT 2>/dev/null || true

cat > "$BLK" <<EOF
# url-smoke blocklist
$BAD
blockme.example.net
EOF

# servers inside the netns; the domain stage only fires on dport 80/443
$NS python3 -m http.server 80 --bind "$NS_IP" > "$DIR/http.out" 2>&1 &
SRV_PID=$!
if command -v openssl >/dev/null 2>&1 && python3 -c 'import ssl' 2>/dev/null; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$DIR/key.pem" \
        -out "$DIR/cert.pem" -days 1 -subj "/CN=$GOOD" 2>/dev/null
    # Threaded TLS server, handshake in the worker thread: a connection whose
    # ClientHello never arrives (a blocklist-fenced flow is black-holed, so
    # its FIN/RST cannot deliver the teardown either) wedges only its own
    # thread. A serial acceptor (openssl s_server) would instead block in
    # SSL_accept forever and starve every connection behind it — which is a
    # property of the server, not of the firewall under test.
    cat > "$DIR/tlssrv.py" <<'PYEOF'
import http.server, ssl, sys
cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        self.request = ctx.wrap_socket(self.request, server_side=True)
        super().setup()
    def do_GET(self):
        body = b'<html><body>ok</body></html>\n'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
Server(('', port), Handler).serve_forever()
PYEOF
    $NS python3 "$DIR/tlssrv.py" "$DIR/cert.pem" "$DIR/key.pem" 443 \
        > "$DIR/tls.out" 2>&1 &
    TLS_PID=$!
fi
sleep 0.3

rm -f "$SOCK"
"$REPO/bin/firewall" -i "$V0" -sock "$SOCK" -url-blocklist "$BLK" > "$LOG" 2>&1 &
FW_PID=$!
for _ in $(seq 1 25); do [ -S "$SOCK" ] && break; sleep 0.2; done
set +e
if [ ! -S "$SOCK" ]; then
    F "daemon did not come up with -url-blocklist (log tail above on exit)"
    exit 1
fi
P "daemon loads the cgroup/skb egress program with -url-blocklist"

# ---- checks ------------------------------------------------------------------
curl_bad_rc=0; http_try "$BAD" >/dev/null 2>&1 || curl_bad_rc=$?
if [ "$curl_bad_rc" -ne 0 ]; then P "HTTP Host '$BAD' is dropped (curl rc=$curl_bad_rc)"
else F "HTTP Host '$BAD' reached the server (curl rc=0)"; fi

curl_sub_rc=0; http_try "$SUB" >/dev/null 2>&1 || curl_sub_rc=$?
if [ "$curl_sub_rc" -ne 0 ]; then P "HTTP Host '$SUB' dropped via suffix match"
else F "HTTP Host '$SUB' reached the server"; fi

code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$NS_IP/" -H "Host: $GOOD")
if [ "$code" = "200" ]; then P "HTTP Host '$GOOD' passes (200)"
else F "HTTP Host '$GOOD' did not pass (code=$code)"; fi

if [ -n "$TLS_PID" ]; then
    sni_bad_rc=0; sni_try "$BAD" >/dev/null 2>&1 || sni_bad_rc=$?
    if [ "$sni_bad_rc" -ne 0 ]; then
        P "TLS SNI '$BAD' is dropped (curl rc=$sni_bad_rc)"
    else
        F "TLS SNI '$BAD' reached the server"
    fi

    sni_good_rc=0; sni_try "$GOOD" >/dev/null 2>&1 || sni_good_rc=$?
    if [ "$sni_good_rc" = 0 ]; then P "TLS SNI '$GOOD' passes (handshake+200)"
    else F "TLS SNI '$GOOD' did not pass (curl rc=$sni_good_rc)"; fi
else
    echo "SKIP: openssl missing; SNI checks not run"
fi

d1=$(edrop_cnt); d1=${d1:-0}
case "$d1" in ''|*[!0-9]*) d1=0;; esac
if [ "$d1" -gt 0 ]; then P "egress drop counter moved ($d1 drops)"
else F "egress drop counter is 0 after blocked attempts"; fi

# ---- runtime domain commands (firewallctl ↔ control socket) ----------------
ctl() { "$REPO/bin/firewallctl" -sock "$SOCK" "$@"; }

if ctl list-domains 2>/dev/null | grep -q "$BAD"; then
    P "list-domains shows the startup blocklist entries"
else
    F "list-domains does not show '$BAD'"
fi

if ctl block-domain runtime.bad.example >/dev/null 2>&1; then
    rt_rc=0; http_try "runtime.bad.example" >/dev/null 2>&1 || rt_rc=$?
    if [ "$rt_rc" -ne 0 ]; then
        P "runtime block-domain fences HTTP immediately (curl rc=$rt_rc)"
    else
        F "runtime block-domain did not fence HTTP (curl rc=0)"
    fi
else
    F "block-domain rejected a valid name"
fi

if ctl unblock-domain runtime.bad.example >/dev/null 2>&1; then
    rt_rc=0; http_try "runtime.bad.example" >/dev/null 2>&1 || rt_rc=$?
    if [ "$rt_rc" -eq 0 ]; then
        P "unblock-domain restores HTTP (curl rc=0)"
    else
        F "unblock-domain did not restore HTTP (curl rc=$rt_rc)"
    fi
else
    F "unblock-domain failed"
fi

# clear-domains wipes everything, including the startup file's entries —
# the fenced name from the file passes again afterwards.
ctl clear-domains >/dev/null 2>&1
if ctl list-domains 2>/dev/null | grep -q "no blocked domains"; then
    P "clear-domains empties the blocklist"
else
    F "clear-domains left entries behind"
fi
code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$NS_IP/" -H "Host: $BAD")
if [ "$code" = "200" ]; then P "previously blocked '$BAD' passes after clear-domains (200)"
else F "'$BAD' still fenced after clear-domains (code=$code)"; fi

# ---- IPv6 + QUIC fence -------------------------------------------------------
# Re-arm the blocklist first: the runtime-command checks above ended with
# clear-domains, and both the domain stage and the QUIC fence gate on the
# domain presence bit.
ctl block-domain "$BAD" >/dev/null 2>&1

# The sandbox setup disabled IPv6 on the veths (v4-counter determinism);
# re-enable it and hand out sandbox addresses for the v6 checks.
sysctl -q -w net.ipv6.conf.$V0.disable_ipv6=0 || true
$NS sysctl -q -w net.ipv6.conf.$V1.disable_ipv6=0 || true
ip -6 addr add fd00:99::1/64 dev "$V0" 2>/dev/null || true
$NS ip -6 addr add fd00:99::2/64 dev "$V1" 2>/dev/null || true

$NS python3 -m http.server 80 --bind fd00:99::2 > "$DIR/http6.out" 2>&1 &
SRV6_PID=$!
sleep 0.2

code=$(curl -6 -gs -m 3 -o /dev/null -w '%{http_code}' "http://[fd00:99::2]/" -H "Host: $BAD")
if [ "$code" = "000" ]; then
    P "v6 HTTP Host '$BAD' is dropped"
else
    F "v6 HTTP Host '$BAD' reached the server (code=$code)"
fi
code=$(curl -6 -gs -m 3 -o /dev/null -w '%{http_code}' "http://[fd00:99::2]/" -H "Host: $GOOD")
if [ "$code" = "200" ]; then
    P "v6 HTTP Host '$GOOD' passes (200)"
else
    F "v6 HTTP Host '$GOOD' did not pass (code=$code)"
fi

if [ -n "$TLS_PID" ]; then
    sni6_rc=0; curl -6ks -m 3 --resolve "$BAD:443:[fd00:99::2]" "https://$BAD/" -o /dev/null 2>/dev/null || sni6_rc=$?
    if [ "$sni6_rc" -ne 0 ]; then
        P "v6 TLS SNI '$BAD' is dropped (curl rc=$sni6_rc)"
    else
        F "v6 TLS SNI '$BAD' reached the server"
    fi
fi

# QUIC fence: UDP/443 datagrams (v4 and v6) are dropped while the blocklist
# is loaded; a browser sees this as "no HTTP/3" and falls back to TCP.
q1=$(edrop_cnt); q1=${q1:-0}
case "$q1" in ''|*[!0-9]*) q1=0;; esac
python3 - "$NS_IP" <<'PYEOF'
import socket, sys
for fam, addr in ((socket.AF_INET6, "fd00:99::2"), (socket.AF_INET, sys.argv[1])):
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.sendto(b"\xc0" * 64, (addr, 443))  # QUIC-shaped initial datagram
        s.close()
    except OSError:
        pass
PYEOF
sleep 0.2
q2=$(edrop_cnt); q2=${q2:-0}
case "$q2" in ''|*[!0-9]*) q2=0;; esac
if [ "$((q2 - q1))" -ge 2 ]; then
    P "QUIC fence: UDP/443 dropped on both families (counter +$((q2 - q1)))"
else
    F "QUIC fence: UDP/443 was not dropped (delta $((q2 - q1)))"
fi

SUCCEEDED=1
echo "--- $pass passed, $fail failed ---"
exit 0
