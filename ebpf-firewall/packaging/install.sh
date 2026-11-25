#!/usr/bin/env bash
# ebpf-firewall installer: downloads a release tarball, verifies its checksum,
# installs the binaries, and can run the daemon on an interface right away.
#
# Usage:
#   sudo ./install.sh                                  install the latest release binaries
#   sudo ./install.sh --version v0.1.0                 install a specific release
#   sudo ./install.sh --iface eth0                     ... and run the daemon on eth0 (background)
#   sudo ./install.sh --iface eth0 --url-blocklist b.txt   ... with egress URL filtering
#   sudo ./install.sh --iface eth0 --systemd           ... managed by systemd instead (opt-in)
#   sudo ./install.sh --stop                           stop a background daemon
#   sudo ./install.sh --uninstall                      stop/remove everything installed
#
# One-line remote install:
#   curl -fsSL https://raw.githubusercontent.com/Im-Abhi/ebpf-network-controls/master/ebpf-firewall/packaging/install.sh \
#     | sudo bash -s -- --iface eth0
#
# Default mode runs the daemon in the background (nohup; pidfile
# /var/run/ebpf-firewall.pid, log /var/log/ebpf-firewall.log) with no systemd
# involvement — intended for testing-phase machines. Pass --systemd on
# production hosts to install the unit and enable it (one instance per
# interface, starts on boot, restarts on failure).
#
# The release binaries embed the compiled eBPF program (bpf2go), so no build
# toolchain is needed on the target machine — only root and a BTF-enabled
# kernel. The URL blocklist needs kernel >= 5.17 (bpf_loop) plus cgroup v2;
# ingress-only XDP works from 5.15.

set -euo pipefail

REPO="Im-Abhi/ebpf-network-controls"
BIN_DIR="/usr/local/bin"
UNIT_DIR="/etc/systemd/system"
UNIT_NAME="ebpf-firewall@.service"
CONF_DIR="/etc/ebpf-firewall"
PID_FILE="/var/run/ebpf-firewall.pid"
LOG_FILE="/var/log/ebpf-firewall.log"

VERSION=""
IFACE=""
BLOCKLIST=""
SYSTEMD=0
STOP=0
UNINSTALL=0

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
ebpf-firewall installer
  sudo ./install.sh                                    install the latest release binaries
  sudo ./install.sh --version v0.1.0                   install a specific release
  sudo ./install.sh --iface eth0                       ... and run the daemon on eth0 (background)
  sudo ./install.sh --iface eth0 --url-blocklist b.txt ... with egress URL filtering
  sudo ./install.sh --iface eth0 --systemd             ... managed by systemd (opt-in, production)
  sudo ./install.sh --stop                             stop a background daemon
  sudo ./install.sh --uninstall                        stop/remove everything installed

One-line remote install:
  curl -fsSL https://raw.githubusercontent.com/Im-Abhi/ebpf-network-controls/master/ebpf-firewall/packaging/install.sh | sudo bash -s -- --iface eth0
EOF
	exit 0
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version)        VERSION="${2:?--version needs a value}"; shift 2 ;;
	--iface)          IFACE="${2:?--iface needs a value}"; shift 2 ;;
	--url-blocklist)  BLOCKLIST="${2:?--url-blocklist needs a value}"; shift 2 ;;
	--systemd)        SYSTEMD=1; shift ;;
	--stop)           STOP=1; shift ;;
	--uninstall)      UNINSTALL=1; shift ;;
	--help|-h)        usage ;;
	*)                die "unknown option: $1 (try --help)" ;;
	esac
done

# ---- pre-flight: verify the machine can run the datapath --------------------
# Fails BEFORE anything is downloaded so a bad machine gets a precise reason
# instead of a generic daemon-load error afterwards.
ver_at_least() { # <have_major> <have_minor> <need_major> <need_minor>
	[ "$1" -gt "$3" ] || { [ "$1" -eq "$3" ] && [ "$2" -ge "$4" ]; }
}

preflight() {
	[ "$(id -u)" -eq 0 ] || die "installation needs root (sudo)"
	case "$(uname -m)" in
		x86_64)        ARCH="amd64" ;;
		aarch64|arm64) ARCH="arm64" ;;
		*) die "unsupported architecture: $(uname -m) (release binaries target amd64 and arm64)" ;;
	esac
	command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
		|| die "curl or wget is required to download the release"
	command -v tar >/dev/null 2>&1 || die "tar is required to unpack the release"
	if [ "$SYSTEMD" -eq 1 ]; then
		command -v systemctl >/dev/null 2>&1 || die "systemd is required for --systemd"
	fi
	[ -f /sys/kernel/btf/vmlinux ] \
		|| die "kernel BTF not found at /sys/kernel/btf/vmlinux (CONFIG_DEBUG_INFO_BTF=y required)"
	# shellcheck disable=SC2046  # word-splitting is the point here
	kern="$(uname -r | sed -E 's/^([0-9]+)\.([0-9]+).*/\1 \2/')"
	set -- $kern
	[ $# -eq 2 ] || die "cannot parse the kernel version from: $(uname -r)"
	ver_at_least "$1" "$2" 5 15 \
		|| die "kernel $(uname -r) is too old: >= 5.15 required for the XDP ingress firewall"
	if [ -n "$BLOCKLIST" ]; then
		ver_at_least "$1" "$2" 5 17 \
			|| die "kernel $(uname -r) is too old: >= 5.17 required for the URL blocklist (bpf_loop)"
		[ -f /sys/fs/cgroup/cgroup.controllers ] \
			|| die "cgroup v2 not mounted at /sys/fs/cgroup (required for the egress hook)"
	fi
	if [ -n "$BLOCKLIST" ] && [ ! -f "$BLOCKLIST" ]; then
		case "$BLOCKLIST" in
			http://*|https://*) : ;;          # remote blocklist, fetched below
			*) die "blocklist file not found: $BLOCKLIST" ;;
		esac
	fi
}

preflight

# ---- stop/uninstall paths ----------------------------------------------------
if [ "$STOP" -eq 1 ]; then
	if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		kill "$(cat "$PID_FILE")"
		log "daemon stopped (pid $(cat "$PID_FILE"))"
	else
		log "no running background daemon (pidfile $PID_FILE)"
	fi
	rm -f "$PID_FILE"
	exit 0
fi

if [ "$UNINSTALL" -eq 1 ]; then
	if [ -f "$PID_FILE" ]; then
		kill "$(cat "$PID_FILE")" 2>/dev/null || true
		rm -f "$PID_FILE"
	fi
	systemctl disable --now 'ebpf-firewall@*' 2>/dev/null || true
	rm -f "$UNIT_DIR/$UNIT_NAME" "$BIN_DIR/firewall" "$BIN_DIR/firewallctl"
	rm -rf /etc/systemd/system/ebpf-firewall@.service.d "$CONF_DIR"
	systemctl daemon-reload 2>/dev/null || true
	log "ebpf-firewall uninstalled (rules were kernel state and are gone with the daemon)"
	exit 0
fi

# ---- fetch, verify, unpack ---------------------------------------------------
TAG="$VERSION"
if [ -z "$TAG" ]; then
	log "resolving the latest release"
	api_json="$(mktemp)"
	fetch_failed=0
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "$api_json" || fetch_failed=1
	else
		wget -qO "$api_json" "https://api.github.com/repos/${REPO}/releases/latest" || fetch_failed=1
	fi
	[ "$fetch_failed" -eq 0 ] || die "could not reach the GitHub API (offline? no release published yet?)"
	TAG="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$api_json" | head -n1)"
	rm -f "$api_json"
	[ -n "$TAG" ] || die "could not resolve the latest release (is one published?)"
fi

BASE="https://github.com/${REPO}/releases/download/${TAG}"
ASSET="ebpf-firewall-${TAG}-linux-${ARCH}"

fetch() { # fetch <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	else
		wget -qO "$2" "$1"
	fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log "downloading ${ASSET}.tar.gz"
fetch "${BASE}/${ASSET}.tar.gz" "${TMP}/${ASSET}.tar.gz"
fetch "${BASE}/checksums.txt" "${TMP}/checksums.txt"

log "verifying the sha256 checksum"
(cd "$TMP" && grep -F "${ASSET}.tar.gz" checksums.txt | sha256sum -c -) \
	|| die "checksum verification failed for ${ASSET}.tar.gz"

log "extracting"
tar -xzf "${TMP}/${ASSET}.tar.gz" -C "$TMP"

# ---- install -----------------------------------------------------------------
log "installing binaries to ${BIN_DIR}"
install -m 0755 "${TMP}/${ASSET}/firewall"    "${BIN_DIR}/firewall"
install -m 0755 "${TMP}/${ASSET}/firewallctl" "${BIN_DIR}/firewallctl"

if [ -n "$BLOCKLIST" ]; then
	mkdir -p "$CONF_DIR"
	case "$BLOCKLIST" in
		http://*|https://*) fetch "$BLOCKLIST" "${CONF_DIR}/blocklist.txt" ;;
		*)                  install -m 0644 "$BLOCKLIST" "${CONF_DIR}/blocklist.txt" ;;
	esac
	log "blocklist installed to ${CONF_DIR}/blocklist.txt"
fi

if [ "$SYSTEMD" -eq 1 ]; then
	log "installing systemd unit to ${UNIT_DIR}"
	install -m 0644 "${TMP}/${ASSET}/${UNIT_NAME}" "${UNIT_DIR}/${UNIT_NAME}"
	if [ -n "$BLOCKLIST" ]; then
		# Drop-in on the template unit so every instance picks it up.
		mkdir -p "${UNIT_DIR}/ebpf-firewall@.service.d"
		cat > "${UNIT_DIR}/ebpf-firewall@.service.d/url-blocklist.conf" <<EOF
[Service]
ExecStart=
ExecStart=/usr/local/bin/firewall -i %i -dir both -url-blocklist ${CONF_DIR}/blocklist.txt
EOF
	fi
	systemctl daemon-reload 2>/dev/null || true
	if [ -n "$IFACE" ]; then
		log "enabling ebpf-firewall@${IFACE}"
		systemctl enable --now "ebpf-firewall@${IFACE}.service"
		systemctl --no-pager --lines=0 status "ebpf-firewall@${IFACE}.service" || true
		log "inspect it with: sudo firewallctl status"
	else
		log "start it with: sudo systemctl enable --now ebpf-firewall@<iface>"
	fi
elif [ -n "$IFACE" ]; then
	# Testing-phase default: background daemon, no systemd.
	if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		log "stopping the previously started daemon (pid $(cat "$PID_FILE"))"
		kill "$(cat "$PID_FILE")" 2>/dev/null || true
		sleep 0.5
	fi
	rm -f "$PID_FILE"

	log "starting the daemon on ${IFACE} (log: ${LOG_FILE})"
	daemon_args=(-i "$IFACE")
	[ -n "$BLOCKLIST" ] && daemon_args+=(-url-blocklist "${CONF_DIR}/blocklist.txt")
	nohup "$BIN_DIR/firewall" "${daemon_args[@]}" >> "$LOG_FILE" 2>&1 &
	echo $! > "$PID_FILE"
	sleep 1
	if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		log "daemon exited immediately - log tail:"
		tail -5 "$LOG_FILE" 2>/dev/null || true
		die "see ${LOG_FILE} for the full log"
	fi
	log "running (pid $(cat "$PID_FILE")); control it with: sudo firewallctl status"
	log "stop it with:     sudo $(basename "$0") --stop   (or: sudo kill \$(cat $PID_FILE))"
else
	log "binaries installed; run with: sudo firewall -i <iface>"
fi

log "ebpf-firewall ${TAG} (linux/${ARCH}) installed"
