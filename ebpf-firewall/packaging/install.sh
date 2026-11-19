#!/usr/bin/env bash
# ebpf-firewall installer: downloads a release tarball, verifies its checksum,
# installs the binaries and the systemd unit, and (optionally) enables the
# service on one interface.
#
# Usage:
#   sudo ./install.sh                      install the latest release binaries
#   sudo ./install.sh --version v0.1.0     install a specific release
#   sudo ./install.sh --iface eth0         ... and enable ebpf-firewall@eth0
#   sudo ./install.sh --uninstall          stop/remove everything installed
#
# One-line remote install:
#   curl -fsSL https://raw.githubusercontent.com/Im-Abhi/ebpf-network-controls/master/ebpf-firewall/packaging/install.sh \
#     | sudo bash -s -- --iface eth0
#
# The release binaries embed the compiled eBPF program (bpf2go), so no build
# toolchain is needed on the target machine — only root and a BTF-enabled
# kernel (>= 5.15 for XDP ingress; >= 6.6 for the TCX egress hook).

set -euo pipefail

REPO="Im-Abhi/ebpf-network-controls"
BIN_DIR="/usr/local/bin"
UNIT_DIR="/etc/systemd/system"
UNIT_NAME="ebpf-firewall@.service"

VERSION=""
IFACE=""
UNINSTALL=0

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,19p' "$0"; exit 0; }

while [ $# -gt 0 ]; do
	case "$1" in
	--version)   VERSION="${2:?--version needs a value}"; shift 2 ;;
	--iface)     IFACE="${2:?--iface needs a value}"; shift 2 ;;
	--uninstall) UNINSTALL=1; shift ;;
	--help|-h)   usage ;;
	*)           die "unknown option: $1 (try --help)" ;;
	esac
done

if [ "$UNINSTALL" -eq 1 ]; then
	[ "$(id -u)" -eq 0 ] || die "uninstall needs root (sudo)"
	systemctl disable --now 'ebpf-firewall@*' 2>/dev/null || true
	rm -f "$UNIT_DIR/$UNIT_NAME" "$BIN_DIR/firewall" "$BIN_DIR/firewallctl"
	systemctl daemon-reload 2>/dev/null || true
	log "ebpf-firewall uninstalled (rules were kernel state and are gone with the daemon)"
	exit 0
fi

[ "$(id -u)" -eq 0 ] || die "installation needs root (sudo)"

case "$(uname -m)" in
	x86_64)          ARCH="amd64" ;;
	aarch64|arm64)   ARCH="arm64" ;;
	*) die "unsupported architecture: $(uname -m) (release binaries target amd64 and arm64)" ;;
esac

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
	|| die "curl or wget is required to download the release"
command -v tar >/dev/null 2>&1 || die "tar is required to unpack the release"
if [ -n "$IFACE" ]; then
	command -v systemctl >/dev/null 2>&1 || die "systemd is required for --iface"
fi

fetch() { # fetch <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	else
		wget -qO "$2" "$1"
	fi
}

if [ -z "$VERSION" ]; then
	log "resolving the latest release"
	api_json="$(mktemp)"
	fetch "https://api.github.com/repos/${REPO}/releases/latest" "$api_json"
	VERSION="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$api_json" | head -n1)"
	rm -f "$api_json"
	[ -n "$VERSION" ] || die "could not resolve the latest release (is one published?)"
fi

TAG="$VERSION"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
ASSET="ebpf-firewall-${TAG}-linux-${ARCH}"

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

log "installing binaries to ${BIN_DIR}"
install -m 0755 "${TMP}/${ASSET}/firewall"    "${BIN_DIR}/firewall"
install -m 0755 "${TMP}/${ASSET}/firewallctl" "${BIN_DIR}/firewallctl"

log "installing systemd unit to ${UNIT_DIR}"
install -m 0644 "${TMP}/${ASSET}/${UNIT_NAME}" "${UNIT_DIR}/${UNIT_NAME}"
systemctl daemon-reload 2>/dev/null || true

if [ -n "$IFACE" ]; then
	log "enabling ebpf-firewall@${IFACE}"
	systemctl enable --now "ebpf-firewall@${IFACE}.service"
	systemctl --no-pager --lines=0 status "ebpf-firewall@${IFACE}.service" || true
	log "inspect it with: sudo firewallctl status"
	log "add rules with:  sudo firewallctl block <ip> --protocol tcp --dport <n>"
else
	log "start it with:  sudo systemctl enable --now ebpf-firewall@<iface>"
	log "or run it once: sudo firewall -i <iface>"
fi

log "ebpf-firewall ${TAG} (linux/${ARCH}) installed"
