# Installing ebpf-firewall from a release tarball

This file ships inside the release tarball (`ebpf-firewall-<tag>-linux-<arch>.tar.gz`).
The binaries embed the compiled eBPF program — installing needs **no** build
toolchain, only the requirements below.

## Requirements

- Linux, amd64 or arm64
- A BTF-enabled kernel (`test -f /sys/kernel/btf/vmlinux`):
  - **≥ 5.15** for the XDP ingress firewall
  - **≥ 6.6** for the TCX egress hook (`-dir out|both`)
- root privileges (or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`)

## Manual install

```bash
tar -xzf ebpf-firewall-<tag>-linux-<arch>.tar.gz
cd ebpf-firewall-<tag>-linux-<arch>

sudo install -m 0755 firewall    /usr/local/bin/firewall
sudo install -m 0755 firewallctl /usr/local/bin/firewallctl

# Optional: systemd service (one instance per interface)
sudo install -m 0644 ebpf-firewall@.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Run

As a systemd service (starts on boot, restarts on failure):

```bash
sudo systemctl enable --now ebpf-firewall@eth0
```

Or in the foreground:

```bash
sudo firewall -i eth0            # XDP ingress only (default)
sudo firewall -i eth0 -dir both  # also attach the TC egress hook (kernel >= 6.6)
```

## Control it

```bash
sudo firewallctl status
sudo firewallctl block 10.0.0.0/8
sudo firewallctl block 1.2.3.4 --protocol tcp --dport 22
sudo firewallctl stats
sudo firewallctl --help          # full command list
```

The daemon serves a read-only HTTP stats API on `127.0.0.1:8080` by default
(`-http-addr` changes/disables it).

## Uninstall

```bash
sudo systemctl disable --now ebpf-firewall@eth0 2>/dev/null || true
sudo rm -f /etc/systemd/system/ebpf-firewall@.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/firewall /usr/local/bin/firewallctl
```

(or `install.sh --uninstall` if you used the installer).

## Notes

- Rules live in anonymous BPF maps: they are reset when the daemon stops or
  restarts. Seed rules with `sudo firewallctl block ...` after start, or via
  the `-block` flag.
- The default egress TCX hook needs kernel ≥ 6.6; on older kernels the
  ingress-only default still works.
