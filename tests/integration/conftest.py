"""Fixtures for the fork's integration tests: a local HTTP/3 server, test
SOCKS5 proxies and TLS WebSocket servers.

The HTTP/3 server and the proxies run as subprocesses from tests/quic_bench,
so the tests work offline and on hosts without UDP egress.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

BENCH = Path(__file__).resolve().parents[1] / "quic_bench"


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with closing(socket.socket(socket.AF_INET, kind)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def read_log(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def wait_for_line(proc: subprocess.Popen, needle: str, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if needle in line:
            return
        if proc.poll() is not None:
            break
    _stop(proc)
    raise RuntimeError(f"{proc.args} did not start")


def _stop(proc: subprocess.Popen) -> None:
    proc.kill()
    proc.wait()
    if proc.stdout is not None:
        proc.stdout.close()


@dataclass
class H3Server:
    url: str
    port: int
    log: Path

    def records(self) -> list[dict]:
        return read_log(self.log)


def _start_h3(tmp: Path, reject_early_data: bool) -> Iterator[H3Server]:
    pytest.importorskip("aioquic")
    port = free_port(socket.SOCK_DGRAM)
    log = tmp / f"h3-{port}.log"
    args = [sys.executable, str(BENCH / "h3_server.py"), str(port), "--log", str(log)]
    if reject_early_data:
        args.append("--reject-early-data")
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
    wait_for_line(proc, "listening")
    try:
        yield H3Server(url=f"https://localhost:{port}/", port=port, log=log)
    finally:
        _stop(proc)


@pytest.fixture(scope="module")
def h3_server(tmp_path_factory) -> Iterator[H3Server]:
    yield from _start_h3(tmp_path_factory.mktemp("h3"), False)


@pytest.fixture(scope="module")
def h3_server_rejecting(tmp_path_factory) -> Iterator[H3Server]:
    yield from _start_h3(tmp_path_factory.mktemp("h3r"), True)


@dataclass
class SocksProxy:
    port: int
    log: Path

    def url(self, scheme: str = "socks5h") -> str:
        return f"{scheme}://user:pass@127.0.0.1:{self.port}"

    def records(self) -> list[dict]:
        return read_log(self.log)

    def associations(self) -> list[dict]:
        return [r for r in self.records() if r.get("cmd") == "UDP_ASSOCIATE"]

    def settle(self, count: int, timeout: float = 5) -> list[dict]:
        """Wait until `count` associations have ended and were logged."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.associations()) >= count:
                break
            time.sleep(0.1)
        return self.associations()


@pytest.fixture
def socks_proxy(tmp_path) -> Iterator[Callable[..., SocksProxy]]:
    procs: list[subprocess.Popen] = []

    def start(*options: str) -> SocksProxy:
        port = free_port()
        log = tmp_path / f"socks-{port}.log"
        proc = subprocess.Popen(
            [sys.executable, str(BENCH / "socks5_udp.py"), str(port), str(log)]
            + list(options),
            stdout=subprocess.PIPE,
            text=True,
        )
        procs.append(proc)
        wait_for_line(proc, "listening")
        return SocksProxy(port=port, log=log)

    yield start
    for proc in procs:
        _stop(proc)


@pytest.fixture(scope="session")
def server_ssl_context() -> ssl.SSLContext:
    trustme = pytest.importorskip("trustme")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    trustme.CA().issue_cert("localhost", "127.0.0.1").configure_cert(ctx)
    return ctx


@pytest.fixture(scope="session")
def wss_server(
    server_ssl_context: ssl.SSLContext,
) -> Callable[..., str]:
    """Start a `websockets` server on TLS in a thread and return its wss:// URL."""
    from websockets.asyncio.server import serve

    def start(handler: Callable[[Any], Awaitable[None]], **options: Any) -> str:
        ready = threading.Event()
        ports: list[int] = []

        async def main() -> None:
            async with serve(
                handler, "127.0.0.1", 0, ssl=server_ssl_context, **options
            ) as server:
                ports.append(server.sockets[0].getsockname()[1])
                ready.set()
                await asyncio.Future()

        threading.Thread(target=asyncio.run, args=(main(),), daemon=True).start()
        assert ready.wait(10), "wss server did not start"
        return f"wss://127.0.0.1:{ports[0]}"

    return start
