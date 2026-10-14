"""The fork's WebSocket behaviour: permessage-deflate inflation and own PONGs.

Downstream code detects a patched build by WebSocket._inflate, a PONG sent
from recv_fragment() and CurlWsFlag.DEFLATE, so those are checked too.
"""

from __future__ import annotations

import asyncio
import inspect
import socket
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import closing

import pytest
from websockets.asyncio.server import ServerConnection, serve

from curl_cffi import AsyncSession, CurlECode, CurlError, CurlWsFlag, Session
from curl_cffi.requests.websockets import WebSocket

DEFLATE_HEADER = {
    "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits"
}
BIG = ("curl_cffi permessage-deflate " * 400).encode()


def free_port() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """websockets server running `handler` in a background event loop."""

    def __init__(self, handler: Callable[[ServerConnection], Awaitable[None]]):
        self.port = free_port()
        self.url = f"ws://127.0.0.1:{self.port}"
        self.events: list[str] = []
        self._handler = handler
        self._ready = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._stop: asyncio.Future[None] | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)

        async def main() -> None:
            self._stop = self._loop.create_future()
            async with serve(
                self._handler, "127.0.0.1", self.port, compression="deflate"
            ):
                self._ready.set()
                await self._stop

        try:
            self._loop.run_until_complete(main())
        finally:
            self._loop.close()

    def __enter__(self) -> Server:
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc: object) -> None:
        self._loop.call_soon_threadsafe(self._stop.set_result, None)
        self._thread.join(5)


async def send_messages(ws: ServerConnection) -> None:
    await ws.send("hello")
    await ws.send(BIG.decode())
    await ws.send(BIG.decode())  # context takeover: refers to the first copy
    await ws.send(BIG)
    await ws.send(iter([BIG[:3000], BIG[3000:6000], BIG[6000:]]))  # fragmented
    await ws.wait_closed()


EXPECTED = [b"hello", BIG, BIG, BIG, BIG]


async def ping_then_ok(ws: ServerConnection) -> None:
    for i in range(3):
        waiter = await ws.ping(f"ping-{i}".encode())
        try:
            await asyncio.wait_for(waiter, 5)
        except asyncio.TimeoutError:
            await ws.send("no pong")
            return
    await ws.send("ok")
    await ws.wait_closed()


def test_patched_build_markers():
    assert int(CurlWsFlag.DEFLATE) == 1 << 7
    assert callable(WebSocket._inflate)
    assert "CurlWsFlag.PONG" in inspect.getsource(WebSocket.recv_fragment)


def test_inflate_recv():
    with Server(send_messages) as srv, Session() as s:
        ws = s.ws_connect(srv.url, headers=DEFLATE_HEADER)
        got = []
        for _ in EXPECTED:
            msg, flags = ws.recv(timeout=5)
            assert flags & CurlWsFlag.DEFLATE
            got.append(msg)
        ws.close()
    assert got == EXPECTED


def test_inflate_run_forever():
    got: list[bytes] = []

    def on_message(ws: WebSocket, msg: bytes | str) -> None:
        got.append(msg.encode() if isinstance(msg, str) else msg)
        if len(got) == len(EXPECTED):
            ws.close()

    with Server(send_messages) as srv:
        ws = WebSocket(on_message=on_message)
        ws.run_forever(srv.url, headers=DEFLATE_HEADER)
    assert got == EXPECTED


def test_not_negotiated_is_untouched():
    with Server(send_messages) as srv, Session() as s:
        ws = s.ws_connect(srv.url)
        msg, flags = ws.recv(timeout=5)
        assert msg == b"hello"
        assert not flags & CurlWsFlag.DEFLATE
        ws.close()


def test_pong_from_recv():
    with Server(ping_then_ok) as srv, Session() as s:
        ws = s.ws_connect(srv.url)
        msg, _ = ws.recv(timeout=20)
        ws.close()
    assert msg == b"ok"


def test_pong_from_recv_fragment():
    with Server(ping_then_ok) as srv, Session() as s:
        ws = s.ws_connect(srv.url)
        chunks = []
        while not chunks or chunks[-1][1].flags & CurlWsFlag.PING:
            try:
                chunks.append(ws.recv_fragment())
            except CurlError as e:
                if e.code != CurlECode.AGAIN:
                    raise
                time.sleep(0.01)
        ws.close()
    assert chunks[-1][0] == b"ok"


def test_pong_from_run_forever():
    got: list[bytes | str] = []

    def on_message(ws: WebSocket, msg: bytes | str) -> None:
        got.append(msg)
        ws.close()

    with Server(ping_then_ok) as srv:
        WebSocket(on_message=on_message).run_forever(srv.url)
    assert got == ["ok"]


@pytest.mark.asyncio
async def test_pong_from_async_reader():
    with Server(ping_then_ok) as srv:
        async with AsyncSession() as s:
            ws = await s.ws_connect(srv.url)
            msg, _ = await ws.recv(timeout=20)
            await ws.close()
    assert msg == b"ok"
