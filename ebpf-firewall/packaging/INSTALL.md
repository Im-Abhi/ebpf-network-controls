# Installing ebpf-firewall from a release tarball

This file ships inside the release tarball (`ebpf-firewall-<tag>-linux-<arch>.tar.gz`).
The binaries embed the compiled eBPF program — installing needs **no** build
toolchain, only the requirements below.

## Requirements

- Linux, amd64 or arm64
- A BTF-enabled kernel (`test -f /sys/kernel/btf/vmlinux`):
  - **≥ 5.15** for the XDP ingress firewall
  - **≥ 5.17** for the URL blocklist (`bpf_loop`) — plus cgroup v2 for the
    egress hook (default on current distros)
- root privileges (or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`)
- `curl` or `wget` + `tar` (the installer downloads and verifies the release)

The egress hook is a cgroup/skb classifier — it sees every outbound packet on
any modern kernel and is not tied to TCX (the old kernel >= 6.6 requirement).

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/Im-Abhi/ebpf-network-controls/master/ebpf-firewall/packaging/install.sh \
  | sudo bash -s -- --iface eth0
```

The installer pre-flights the machine (arch, BTF, kernel version, cgroup v2
when a blocklist is requested), resolves the latest release, verifies the
sha256 checksum, installs the binaries, and starts the daemon.

## Modes

**Testing-phase default — binaries + background daemon, no systemd:**

```bash
sudo ./install.sh --iface eth0                              # XDP ingress, background daemon
sudo ./install.sh --iface eth0 --url-blocklist hosts.txt    # + egress URL/domain filtering
sudo ./install.sh --stop                                    # stop the background daemon
```

- the blocklist file (local path or http(s) URL) is copied to
  `/etc/ebpf-firewall/blocklist.txt` and passed to the daemon;
- the daemon runs detached (pidfile `/var/run/ebpf-firewall.pid`, log
  `/var/log/ebpf-firewall.log`) and dies on reboot — by design at this stage.

**Production — systemd (opt-in):**

```bash
sudo ./install.sh --iface eth0 --systemd                    # starts on boot, restarts on failure
sudo ./install.sh --iface eth0 --systemd --url-blocklist hosts.txt
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
sudo ./install.sh --uninstall
```

(or manually: stop the daemon / disable the unit, then remove
`/usr/local/bin/firewall`, `/usr/local/bin/firewallctl`,
`/etc/systemd/system/ebpf-firewall@.service`, `/etc/ebpf-firewall`.)

## Notes

- Rules live in anonymous BPF maps: they are reset when the daemon stops or
  restarts. Seed rules with `sudo firewallctl block ...` after start, or via
  the `-block` flag.
- URL filtering is egress-only and matches hostnames (HTTP `Host`, TLS SNI).
  Full URL *path* filtering requires TLS termination (a MITM proxy) and is
  out of scope; ECH and QUIC/HTTP-3 fail open by design.
