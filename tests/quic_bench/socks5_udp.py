"""Test SOCKS5 proxy with CONNECT and UDP ASSOCIATE (RFC 1928, RFC 1929).

Every command is logged as a JSON line, so tests can check what a client asked
for: CONNECT (TCP) or UDP_ASSOCIATE (UDP relay), and which destinations an
association carried. Options emulate the differences between real relays:

  --single-target   an association only relays to the first destination it
                    carried, like soax; datagrams to any other destination are
                    dropped and counted as violations
  --batch N         hand up to N queued datagrams to the client as one UDP
                    datagram, each with its own SOCKS5 header, like a relay
                    whose GSO batches arrive unsegmented
  --bind-addr IP    BND.ADDR announced for the relay, e.g. 0.0.0.0
  --reply-src MODE  source written into relayed datagrams: "origin" (the
                    origin's address, default), "zero" (0.0.0.0:0) or "name"
                    (the name the client used, ATYP 3)
  --upstream URL    forward CONNECT and UDP through another SOCKS5 proxy, for
                    hosts without direct UDP egress

usage: socks5_udp.py PORT LOGFILE [options]
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import threading
from contextlib import suppress
from urllib.parse import unquote, urlsplit

CMD = {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}


class Log:
    def __init__(self, path: str) -> None:
        self.path = path
        self.lock = threading.Lock()

    def write(self, record: dict) -> None:
        with self.lock, open(self.path, "a") as f:
            f.write(json.dumps(record) + "\n")


def recv_exact(s: socket.socket, n: int) -> bytes:
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise ConnectionError("closed")
        b += c
    return b


def read_addr(s: socket.socket, atyp: int) -> str:
    if atyp == 1:
        return socket.inet_ntoa(recv_exact(s, 4))
    if atyp == 3:
        return recv_exact(s, recv_exact(s, 1)[0]).decode()
    return socket.inet_ntop(socket.AF_INET6, recv_exact(s, 16))


def encode_addr(host: str, port: int) -> bytes:
    try:
        return b"\x01" + socket.inet_aton(host) + struct.pack(">H", port)
    except OSError:
        pass
    try:
        return (
            b"\x04" + socket.inet_pton(socket.AF_INET6, host) + struct.pack(">H", port)
        )
    except OSError:
        name = host.encode()
        return b"\x03" + bytes([len(name)]) + name + struct.pack(">H", port)


def parse_udp_header(data: bytes) -> tuple[int, bytes, str, int] | None:
    """Return (header length, raw destination, host, port) or None."""
    if len(data) < 4 or data[0] or data[1] or data[2]:
        return None
    atyp, p = data[3], 4
    if atyp == 1:
        if len(data) < p + 6:
            return None
        host = socket.inet_ntoa(data[p : p + 4])
        p += 4
    elif atyp == 3:
        n = data[p] if len(data) > p else 0
        if not n or len(data) < p + 1 + n + 2:
            return None
        host = data[p + 1 : p + 1 + n].decode(errors="replace")
        p += 1 + n
    elif atyp == 4:
        if len(data) < p + 18:
            return None
        host = socket.inet_ntop(socket.AF_INET6, data[p : p + 16])
        p += 16
    else:
        return None
    port = struct.unpack(">H", data[p : p + 2])[0]
    p += 2
    return p, data[3:p], host, port


def split_batch(data: bytes) -> list[bytes]:
    """Split a batch of SOCKS5 UDP datagrams (see --batch) into datagrams."""
    parsed = parse_udp_header(data)
    if not parsed:
        return [data]
    hlen = parsed[0]
    head = data[:hlen]
    for seg in range(hlen + 1, len(data) - hlen + 1):
        if data[seg : seg + hlen] != head:
            continue
        offs = list(range(seg, len(data), seg))
        if all(len(data) - o >= hlen and data[o : o + hlen] == head for o in offs):
            return [data[o : o + seg] for o in range(0, len(data), seg)]
    return [data]


class Upstream:
    """Minimal SOCKS5 client for chaining through another proxy."""

    def __init__(self, url: str) -> None:
        u = urlsplit(url)
        self.host, self.port = u.hostname or "", u.port or 1080
        self.user = unquote(u.username or "")
        self.password = unquote(u.password or "")

    def _handshake(self, cmd: int, dst: bytes) -> tuple[socket.socket, str, int]:
        s = socket.create_connection((self.host, self.port), 10)
        if self.user:
            s.sendall(b"\x05\x01\x02")
            if recv_exact(s, 2)[1] != 2:
                raise ConnectionError("upstream refused user/pass auth")
            u, p = self.user.encode(), self.password.encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if recv_exact(s, 2)[1] != 0:
                raise ConnectionError("upstream auth failed")
        else:
            s.sendall(b"\x05\x01\x00")
            recv_exact(s, 2)
        s.sendall(b"\x05" + bytes([cmd]) + b"\x00" + dst)
        rep = recv_exact(s, 4)
        if rep[1] != 0:
            raise ConnectionError(f"upstream reply {rep[1]}")
        host = read_addr(s, rep[3])
        port = struct.unpack(">H", recv_exact(s, 2))[0]
        return s, host, port

    def connect(self, host: str, port: int) -> socket.socket:
        return self._handshake(1, encode_addr(host, port))[0]

    def associate(self) -> tuple[socket.socket, tuple[str, int]]:
        s, host, port = self._handshake(3, b"\x01" + b"\x00" * 6)
        if host in ("0.0.0.0", "::"):
            host = self.host
        return s, (socket.gethostbyname(host), port)


def pipe(a: socket.socket, b: socket.socket) -> None:
    try:
        while d := a.recv(65536):
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            with suppress(OSError):
                s.shutdown(socket.SHUT_RDWR)


class Proxy:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.log = Log(args.logfile)
        self.upstream = Upstream(args.upstream) if args.upstream else None

    def serve(self, srv: socket.socket) -> None:
        while True:
            c, _ = srv.accept()
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, client: socket.socket) -> None:
        try:
            recv_exact(client, 1)
            methods = recv_exact(client, recv_exact(client, 1)[0])
            if 2 in methods:
                client.sendall(b"\x05\x02")
                recv_exact(client, 1)
                user = recv_exact(client, recv_exact(client, 1)[0]).decode()
                recv_exact(client, recv_exact(client, 1)[0])
                client.sendall(b"\x01\x00")
                self.log.write({"auth": user})
            elif self.args.require_auth:
                client.sendall(b"\x05\xff")
                client.close()
                return
            else:
                client.sendall(b"\x05\x00")
            _, cmd, _, atyp = recv_exact(client, 4)
            host = read_addr(client, atyp)
            port = struct.unpack(">H", recv_exact(client, 2))[0]
            if cmd == 3:
                self.udp_associate(client, host, port)
                return
            self.log.write({"cmd": CMD.get(cmd, cmd), "host": host, "port": port})
            if cmd != 1:
                client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                client.close()
                return
            if self.upstream:
                remote = self.upstream.connect(host, port)
            else:
                remote = socket.create_connection((host, port), 10)
            client.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
            pipe(remote, client)
        except Exception as e:  # noqa: BLE001
            self.log.write({"error": repr(e)[:200]})
            client.close()

    def udp_associate(self, client: socket.socket, req_host: str, req_port: int):
        args = self.args
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(("127.0.0.1", 0))
        if self.upstream:
            up_ctrl, up_relay = self.upstream.associate()
            out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out.bind(("0.0.0.0", 0))
        else:
            up_ctrl = up_relay = None
            out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out.bind(("0.0.0.0", 0))
        bind = args.bind_addr or "127.0.0.1"
        client.sendall(
            b"\x05\x00\x00\x01"
            + socket.inet_aton(bind)
            + struct.pack(">H", relay.getsockname()[1])
        )
        st = {
            "client": None,
            "up": 0,
            "down": 0,
            "dst": [],
            "violations": 0,
            "dns": 0,
            "dropped": 0,
            "batched": 0,
        }
        locked: dict[str, bytes] = {}
        names: dict[str, str] = {}
        origin_of: dict[tuple[str, int], tuple[bytes, str]] = {}
        stop = threading.Event()

        def up() -> None:
            relay.settimeout(0.2)
            while not stop.is_set():
                try:
                    data, src = relay.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if st["client"] is None:
                    st["client"] = src
                elif src != st["client"]:
                    st["dropped"] += 1
                    continue
                parsed = parse_udp_header(data)
                if parsed is None:
                    st["dropped"] += 1
                    continue
                hlen, raw_dst, host, port = parsed
                key = f"{host}:{port}"
                if key not in st["dst"]:
                    st["dst"].append(key)
                if port == 53:
                    st["dns"] += 1
                if args.single_target:
                    first = locked.setdefault("dst", raw_dst)
                    if raw_dst != first:
                        st["violations"] += 1
                        continue
                payload = data[hlen:]
                st["up"] += 1
                if self.upstream:
                    out.sendto(b"\x00\x00\x00" + raw_dst + payload, up_relay)
                    continue
                ip = names.get(host)
                if ip is None:
                    ip = names[host] = socket.gethostbyname(host)
                origin_of[(ip, port)] = (raw_dst, host)
                out.sendto(payload, (ip, port))

        def reply_header(src: tuple[str, int]) -> bytes:
            mode = args.reply_src
            if mode == "zero":
                return b"\x00\x00\x00\x01" + b"\x00" * 6
            if mode == "name" and src in origin_of:
                return b"\x00\x00\x00" + origin_of[src][0]
            return b"\x00\x00\x00" + encode_addr(src[0], src[1])

        def down() -> None:
            out.settimeout(0.2)
            queue: list[bytes] = []
            while not stop.is_set():
                try:
                    data, src = out.recvfrom(65535)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if st["client"] is None:
                    continue
                if self.upstream:
                    for dgram in split_batch(data):
                        parsed = parse_udp_header(dgram)
                        if parsed is None:
                            continue
                        hlen, _, host, port = parsed
                        queue.append(reply_header((host, port)) + dgram[hlen:])
                else:
                    queue.append(reply_header(src) + data)
                if args.batch > 1:
                    out.settimeout(0.01)
                    while len(queue) < args.batch:
                        try:
                            more, msrc = out.recvfrom(65535)
                        except (TimeoutError, OSError):
                            break
                        if self.upstream:
                            for dgram in split_batch(more):
                                parsed = parse_udp_header(dgram)
                                if parsed:
                                    hlen, _, host, port = parsed
                                    queue.append(
                                        reply_header((host, port)) + dgram[hlen:]
                                    )
                        else:
                            queue.append(reply_header(msrc) + more)
                    out.settimeout(0.2)
                    # A GSO batch: segments of one size, then at most one
                    # shorter tail.
                    i = 0
                    while i < len(queue):
                        j = i + 1
                        while j < len(queue) and len(queue[j]) == len(queue[i]):
                            j += 1
                        if j < len(queue) and len(queue[j]) < len(queue[i]):
                            j += 1
                        relay.sendto(b"".join(queue[i:j]), st["client"])
                        st["down"] += j - i
                        if j - i > 1:
                            st["batched"] += 1
                        i = j
                else:
                    for q in queue:
                        relay.sendto(q, st["client"])
                        st["down"] += 1
                queue = []

        threads = [
            threading.Thread(target=up, daemon=True),
            threading.Thread(target=down, daemon=True),
        ]
        for t in threads:
            t.start()
        try:
            while client.recv(1024):
                pass
        except OSError:
            pass
        stop.set()
        for t in threads:
            t.join(1)
        relay.close()
        out.close()
        if up_ctrl is not None:
            up_ctrl.close()
        self.log.write(
            {
                "cmd": "UDP_ASSOCIATE",
                "request": f"{req_host}:{req_port}",
                "client": f"{st['client'][0]}:{st['client'][1]}"
                if st["client"]
                else None,
                "up": st["up"],
                "down": st["down"],
                "dst": st["dst"],
                "violations": st["violations"],
                "dns": st["dns"],
                "dropped": st["dropped"],
                "batched": st["batched"],
            }
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("port", type=int)
    p.add_argument("logfile")
    p.add_argument("--single-target", action="store_true")
    p.add_argument("--batch", type=int, default=1)
    p.add_argument("--bind-addr", default=None)
    p.add_argument("--reply-src", choices=["origin", "zero", "name"], default="origin")
    p.add_argument("--upstream", default=None)
    p.add_argument("--require-auth", action="store_true")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(64)
    print(f"listening on 127.0.0.1:{srv.getsockname()[1]}", flush=True)
    Proxy(args).serve(srv)


if __name__ == "__main__":
    main(sys.argv[1:])
