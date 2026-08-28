# Installation Guide

This page documents everything needed to build and run the eBPF firewall from
scratch on a Linux machine. All packages are installed via your distro's
package manager, so nothing here hard-codes a distribution-specific path.

## Prerequisites

- A Linux host (the eBPF program runs in the kernel, so building/attaching
  requires Linux). x86-64 and ARM64 are both supported.
- A kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`, default on modern
  kernels) so `vmlinux.h` can be generated — see
  [Generating vmlinux.h](#generating-vmlinuxh) below.
- `root`/`sudo` access: package installation and attaching the XDP program to a
  network interface both need privileges.

## Install the required packages

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
    make \
    golang \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r) \
    linux-headers-$(uname -r) \
    bpftool
```

### Fedora / RHEL

```bash
sudo dnf install -y \
    make \
    golang \
    clang \
    llvm \
    libbpf-devel \
    kernel-devel \
    kernel-headers \
    bpftool
```

### Arch Linux

```bash
sudo pacman -S --needed \
    make \
    go \
    clang \
    llvm \
    libbpf \
    linux-api-headers \
    bpftool
```

### Alpine Linux

```bash
sudo apk add \
    make \
    go \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    linux-tools
```

## What each package provides

| Package                       | Purpose                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| **make**                      | Drives the build via the `Makefile`                            |
| **golang / go**               | Compiles the user-space control plane and Go bindings          |
| **clang / llvm**              | Compiles the BPF C program to a `.bpf.o` object                |
| **libbpf-dev / libbpf-devel** | BPF helper headers (`bpf/bpf_helpers.h`, `bpf/bpf_endian.h`)   |
| **linux-headers**             | Kernel UAPI headers for the running kernel                     |
| **linux-tools / bpftool**     | `bpftool` — generates `vmlinux.h` from kernel BTF              |
| **linux-tools-common**        | Provides the `bpftool`/perf wrappers on Debian/Ubuntu          |

> Note: on Debian/Ubuntu the `bpftool` package name can vary by release. If
> `bpftool` is not found after install, the `linux-tools-$(uname -r)` package
> provides it as a wrapper; ensure the running kernel version matches.

## Verify the toolchain

```bash
make --version
go version
clang --version
llvm-strip --version
which bpftool
test -f /sys/kernel/btf/vmlinux && echo "kernel BTF available" || echo "kernel BTF missing"
```

## Generating vmlinux.h

The BPF program is CO-RE based and depends on `vmlinux.h`, which is generated
from the running kernel's BTF by `scripts/gen-vmlinux.sh`. This is handled
automatically by the Makefile:

```bash
make vmlinux      # or just make generate, which runs it first
```

It writes `bpf/vmlinux.h` from `/sys/kernel/btf/vmlinux`. If your kernel lacks
BTF (`/sys/kernel/btf/vmlinux` does not exist), enable
`CONFIG_DEBUG_INFO_BTF=y` and rebuild your kernel, or build on a BTF-capable
host.

## Build the firewall

```bash
cd ebpf-firewall
make deps       # download Go module dependencies
make generate   # generate vmlinux.h + compile BPF into Go bindings
make build      # build the firewall binary into ./bin/
```

## Run

```bash
make run                    # attach to the loopback interface (default)
make run IFACE=eth0         # attach to a specific interface
sudo ./bin/firewall -i lo -block "192.168.1.5, 10.0.0.0/8"

make trace                  # stream BPF trace pipe for bpf_printk output
make clean                  # remove build artifacts and generated files
```

## Troubleshooting

### `fatal error: 'bpf/bpf_helpers.h' file not found`

The libbpf development headers are missing. Install the distro package:
- Ubuntu/Debian: `sudo apt install libbpf-dev`
- Fedora/RHEL: `sudo dnf install libbpf-devel`
- Arch: `sudo pacman -S libbpf`

### `fatal error: 'asm/types.h' file not found`

This indicates clang could not find the kernel architecture headers. This
project does **not** depend on distribution-specific kernel header paths, so if
you see this it means either the kernel UAPI headers package is missing
(`linux-headers-$(uname -r)` on Debian/Ubuntu, `kernel-devel` on Fedora), or you
are building a BPF program that still includes `<linux/types.h>` directly
instead of `vmlinux.h`.

### `error: BTF requires pahole`

This happens when building your own kernel with BTF. Install `pahole`
(`dwarves` package) and recompile the kernel with `CONFIG_DEBUG_INFO_BTF=y`.

### Kernel BTF missing

The build needs `/sys/kernel/btf/vmlinux`. Enable `CONFIG_DEBUG_INFO_BTF=y` in
your kernel config and rebuild, or build the project on a BTF-capable machine.
