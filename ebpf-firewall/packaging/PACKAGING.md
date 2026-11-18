# Packaging & Release

How prebuilt release binaries are produced, and how to cut a release.

## Why the releases need no toolchain

The eBPF datapath is **compiled once, at build time**, and embedded into the
Go binary. `make generate` runs
[`bpf2go`](https://github.com/cilium/ebpf), which compiles `bpf/firewall.c`
with clang and emits `control/ebpf/firewall_bpf.go` containing
`//go:embed firewall_bpf.o` — the compiled eBPF ELF lives inside the `firewall`
binary from then on.

Consequences:

| | Build host (CI / developer) | Install target |
| --- | --- | --- |
| clang, llvm, libbpf headers, bpftool, Go, make | **required** | **not required** |
| Kernel with BTF (`/sys/kernel/btf/vmlinux`) | required (generate `vmlinux.h`) | required (CO-RE relocations resolve at load) |
| root / `CAP_BPF` `CAP_NET_ADMIN` `CAP_PERFMON` | — | required (attaching XDP/TC, updating maps) |

The embedded program is CO-RE based: it is compiled against the *build*
kernel's `vmlinux.h` but adapts to the *target* kernel's types at load time,
so one binary per architecture serves every BTF-enabled kernel. All release
targets (x86-64, arm64 Linux) are little-endian, and the Go side is pure Go
(`CGO_ENABLED=0`), so the binaries are fully static.

Kernel requirements on the target machine:

- **≥ 5.15** — XDP ingress firewall
- **≥ 6.6** — TCX egress hook (`-dir out|both`)

## What gets published

For a tag `vX.Y.Z`, the release workflow (`.github/workflows/release.yml`)
attaches to the GitHub Release:

```
ebpf-firewall-vX.Y.Z-linux-amd64.tar.gz
ebpf-firewall-vX.Y.Z-linux-arm64.tar.gz
checksums.txt
```

Each tarball contains:

```
firewall                      # daemon (eBPF object embedded)
firewallctl                   # CLI client
ebpf-firewall@.service        # systemd template unit (one instance per interface)
INSTALL.md                    # manual install + usage instructions
```

Both binaries are statically linked (`CGO_ENABLED=0`) and report the release
tag via `-version` (stamped with `-ldflags "-X main.version=..."`).

## Cutting a release

1. Merge the release branch into `main`.
2. Tag and push:
   ```bash
   git tag -a vX.Y.Z -m "ebpf-firewall vX.Y.Z"
   git push origin vX.Y.Z
   ```
3. The `release` workflow builds both architectures on `ubuntu-24.04`
   (its 6.8 kernel provides the BTF needed for `make generate`) and publishes
   the release with auto-generated notes.
4. Verify:
   ```bash
   # after the workflow completes
   curl -fsSL https://api.github.com/repos/Im-Abhi/ebpf-network-controls/releases/latest | grep tag_name
   ```

Users then install with `packaging/install.sh` (see its header comment) or a
manual tarball install (`packaging/INSTALL.md`).

## Testing a build without publishing

Run the `release` workflow manually (`workflow_dispatch` in the GitHub UI) —
it builds both tarballs and uploads them as a workflow artifact named
`ebpf-firewall-dist` instead of creating a release. Download, unpack on a
Linux box, and follow `INSTALL.md` inside.

## Building release artifacts locally

On a Linux machine with the build toolchain (see [`../INSTALLATION.md`](../INSTALLATION.md)):

```bash
cd ebpf-firewall
make generate                              # clang + BTF required
./packaging/build-release.sh v0.1.0 amd64  # -> dist/ebpf-firewall-v0.1.0-linux-amd64.tar.gz
./packaging/build-release.sh v0.1.0 arm64
cd dist && sha256sum ebpf-firewall-*.tar.gz > checksums.txt
```

## Files involved

```
.github/workflows/release.yml        # tag push -> build -> GitHub Release
ebpf-firewall/packaging/
├── build-release.sh                 # one arch: cross-compile, stage, tar
├── install.sh                       # user-facing: download, verify, install
├── ebpf-firewall@.service           # systemd template unit
├── INSTALL.md                       # ships in the tarball
└── PACKAGING.md                     # this file
```

## Future options (not implemented)

- **deb/rpm packages** — `nfpm` can turn the same dist/ layout into native
  packages for apt/dnf users.
- **Docker image** — `docker run --privileged --net=host` for demo runs
  without installing on the host.
- **Rules persistence** — a `-rules-file` the daemon replays on start would
  make systemd restarts keep policy (rules are currently kernel state and
  reset on restart).
