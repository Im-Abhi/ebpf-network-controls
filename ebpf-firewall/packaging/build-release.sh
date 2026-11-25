#!/usr/bin/env bash
# Build one release artifact: statically linked linux/<arch> binaries plus the
# systemd unit, packed as dist/ebpf-firewall-<tag>-linux-<arch>.tar.gz.
#
# Usage: build-release.sh <tag> <arch>     (arch: amd64|arm64)
#
# Prerequisite: the bpf2go bindings must already be generated (`make generate`
# on a Linux host with clang/libbpf/bpftool) — the compiled eBPF object is
# embedded into the Go binary, which is what makes the release self-contained.
# The Go build itself is pure Go (CGO_ENABLED=0) and cross-compiles anywhere.

set -euo pipefail

TAG="${1:?usage: build-release.sh <tag> <arch>}"
ARCH="${2:?usage: build-release.sh <tag> <arch>}"

case "$ARCH" in
	amd64|arm64) ;;
	*) echo "unsupported arch: $ARCH (use amd64 or arm64)" >&2; exit 2 ;;
esac

STAGE_NAME="ebpf-firewall-${TAG}-linux-${ARCH}"
STAGE="dist/stage/${STAGE_NAME}"

mkdir -p "$STAGE"

LDFLAGS="-s -w -X main.version=${TAG}"

echo "==> Building linux/${ARCH} (tag ${TAG})"
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
	go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/firewall" ./cmd/firewall
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
	go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/firewallctl" ./cmd/firewallctl

echo "==> Staging systemd unit + install notes"
cp packaging/ebpf-firewall@.service "$STAGE/"
cp packaging/INSTALL.md "$STAGE/"

echo "==> Packing dist/${STAGE_NAME}.tar.gz"
tar -czf "dist/${STAGE_NAME}.tar.gz" -C dist/stage "$STAGE_NAME"

echo "==> Done: dist/${STAGE_NAME}.tar.gz"
