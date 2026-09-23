#!/usr/bin/env python3
"""Helpers for the priority+conntrack smoke test.

Modes:
  server <port>            echo server bound to 10.99.0.1, loops accepts
  client <dst> <port> <srcport> <msg>
                           one-shot TCP (bind srcport if >0), print reply, exit 0
  keep <dst> <port> <srcport> <gofile> <msg>
                           connect, wait for gofile (up to 20s), then send+echo
  raw <dst> <dport> <srcport> <flags> [seq] [ack]
                           craft+send one raw IPv4/TCP packet from 10.99.0.2
"""
import socket
import struct
import sys
import time
import os

NSIP = "10.99.0.2"

SRC_IP_B = socket.inet_aton(NSIP)


def _try(sock, secs, fn):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            return fn()
        except socket.timeout:
            pass
    raise socket.timeout("timed out")


def mode_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    print("SERVER up on 0.0.0.0:%d" % port, flush=True)
    while True:
        c, _ = s.accept()
        c.settimeout(5)
        try:
            while True:
                try:
                    data = c.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                c.sendall(data)
        except OSError:
            pass
        finally:
            c.close()


def _client_sock(srcport):
    # SO_REUSEADDR lets a client rebind a local port that is still in TIME_WAIT
    # from an earlier run's connection (the smoke reuses srcports throughout).
    # SO_LINGER=0 makes close() send RST instead of FIN: a clean FIN teardown
    # under default-deny would transition the flow to CLOSED and the netns'
    # final ACK would be dropped, causing the host to retransmit its FIN and
    # pollute later drop-counter snapshots. RST teardown leaves no such noise.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.settimeout(5)
    if srcport:
        s.bind((NSIP, srcport))
    return s


def mode_client(dst, port, srcport, msg):
    s = _client_sock(srcport)
    s.connect((dst, port))
    s.sendall(msg.encode())
    data = s.recv(4096)
    s.close()
    print(data.decode(errors="replace"), end="")
    return 0


def mode_keep(dst, port, srcport, gofile, msg):
    s = _client_sock(srcport)
    s.connect((dst, port))
    print("CONNECTED", flush=True)
    deadline = time.time() + 20
    while not os.path.exists(gofile):
        if time.time() > deadline:
            print("HANG", flush=True)
            return 3
        time.sleep(0.1)
    s.sendall(msg.encode())
    data = s.recv(4096)
    s.close()
    print("REPLY " + data.decode(errors="replace").strip(), flush=True)
    return 0


def _csum(b):
    if len(b) % 2:
        b += b"\x00"
    res = 0
    for i in range(0, len(b), 2):
        w = (b[i] << 8) | b[i + 1]
        res += w
        res = (res & 0xFFFF) + (res >> 16)
    return (~res) & 0xFFFF


def _tcp_csum(src_b, dst_b, tcp):
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp))
    return _csum(pseudo + tcp)


def mode_raw(dst, dport, srcport, flags, seq=1000, ack=0):
    dst_b = socket.inet_aton(dst)
    tcp0 = struct.pack("!HHIIBBHHH", srcport, dport, seq, ack,
                       (5 << 4), flags, 65535, 0, 0)
    chk = _tcp_csum(SRC_IP_B, dst_b, tcp0)
    tcp = struct.pack("!HHIIBBHHH", srcport, dport, seq, ack,
                      (5 << 4), flags, 65535, chk, 0)
    total = 20 + len(tcp)
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0,
                      64, socket.IPPROTO_TCP, 0, SRC_IP_B, dst_b)
    ipc = _csum(ip0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0,
                     64, socket.IPPROTO_TCP, ipc, SRC_IP_B, dst_b)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    s.sendto(ip + tcp, (dst, dport))
    s.close()
    return 0


FLAGMAP = {
    "SYN": 0x02, "ACK": 0x10, "FIN": 0x01, "RST": 0x04,
    "SYNACK": 0x12, "FINACK": 0x11,
}


def main():
    mode = sys.argv[1]
    if mode == "server":
        return mode_server(int(sys.argv[2]))
    if mode == "client":
        return mode_client(sys.argv[2], int(sys.argv[3]),
                           int(sys.argv[4]), sys.argv[5])
    if mode == "keep":
        return mode_keep(sys.argv[2], int(sys.argv[3]),
                         int(sys.argv[4]), sys.argv[5], sys.argv[6])
    if mode == "raw":
        return mode_raw(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
                        FLAGMAP[sys.argv[5]],
                        int(sys.argv[6]) if len(sys.argv) > 6 else 1000,
                        int(sys.argv[7]) if len(sys.argv) > 7 else 0)
    print("unknown mode", mode, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())