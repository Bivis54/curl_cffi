"""No CLOSE_WAIT build-up with FORBID_REUSE through a SOCKS proxy (#837).

curl 8.21 stopped polling a connection in shutdown when the TLS peer closed
without close_notify, and the socket stayed in CLOSE_WAIT for the lifetime of
the session until new connections failed.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import threading

import pytest

from curl_cffi import CurlOpt
from curl_cffi.requests import AsyncSession

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc/net/tcp"
)

CLOSE_WAIT = "08"


def close_wait_sockets() -> int:
    inodes = set()
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    count = 0
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        with open(table) as f:
            for line in f.readlines()[1:]:
                fields = line.split()
                if fields[3] == CLOSE_WAIT and fields[9] in inodes:
                    count += 1
    return count


@pytest.fixture(scope="module")
def tls_server_without_close_notify(server_ssl_context):
    ctx = server_ssl_context
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(256)

    def serve_one(conn: socket.socket) -> None:
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            # Drop the TCP connection without a TLS close_notify.
            socket.socket(fileno=tls.detach()).close()
        except OSError:
            conn.close()

    def accept_loop() -> None:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=serve_one, args=(conn,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return f"https://127.0.0.1:{srv.getsockname()[1]}/"


def test_no_close_wait_growth(tls_server_without_close_notify, socks_proxy):
    proxy = socks_proxy()

    async def main() -> list[int]:
        counts = []
        async with AsyncSession(
            max_clients=50, curl_options={CurlOpt.FORBID_REUSE: 1}
        ) as s:
            for _ in range(6):
                results = await asyncio.gather(
                    *[
                        s.get(
                            tls_server_without_close_notify,
                            proxy=proxy.url(),
                            verify=False,
                            timeout=10,
                        )
                        for _ in range(100)
                    ],
                    return_exceptions=True,
                )
                assert all(not isinstance(r, Exception) for r in results), [
                    r for r in results if isinstance(r, Exception)
                ][:3]
                await asyncio.sleep(1)
                counts.append(close_wait_sockets())
        return counts

    counts = asyncio.run(main())
    print("CLOSE_WAIT after each round of 100 requests:", counts)
    assert max(counts) <= 5, counts
