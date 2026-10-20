"""The fork's WebSocket behaviour: permessage-deflate and own PONGs.

Downstream code detects a patched build by WebSocket._inflate, a PONG sent
from recv_fragment() and CurlWsFlag.DEFLATE, so those are checked too.
"""

from __future__ import annotations

import asyncio
import inspect
import socket
import threading
import time
import zlib
from collections.abc import Awaitable, Callable
from contextlib import closing

import pytest
from websockets.asyncio.server import ServerConnection, serve
from websockets.extensions.permessage_deflate import ServerPerMessageDeflateFactory

from curl_cffi import AsyncSession, CurlECode, CurlError, CurlWsFlag, Session
from curl_cffi.requests.websockets import WebSocket, _permessage_deflate_params

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

    def __init__(
        self,
        handler: Callable[[ServerConnection], Awaitable[None]],
        deflate: ServerPerMessageDeflateFactory | None = None,
    ):
        self.port = free_port()
        self.url = f"ws://127.0.0.1:{self.port}"
        self.events: list[str] = []
        self._handler = handler
        # None: websockets' "deflate" preset, 12-bit windows both ways
        self._deflate = deflate
        self._ready = threading.Event()
        self._loop = asyncio.new_event_loop()
        self._stop: asyncio.Future[None] | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)

        async def main() -> None:
            self._stop = self._loop.create_future()
            async with serve(
                self._handler,
                "127.0.0.1",
                self.port,
                compression=None if self._deflate else "deflate",
                extensions=[self._deflate] if self._deflate else None,
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


async def echo(ws: ServerConnection) -> None:
    async for message in ws:
        await ws.send(message)


ECHOED = ["hello", BIG.decode(), BIG.decode(), BIG, b"\x00\x01" * 70000]


@pytest.mark.parametrize(
    "deflate",
    [
        pytest.param(None, id="preset-12-bits"),
        pytest.param(ServerPerMessageDeflateFactory(), id="15-bits"),
        pytest.param(
            ServerPerMessageDeflateFactory(client_no_context_takeover=True),
            id="client-no-context-takeover",
        ),
        pytest.param(
            ServerPerMessageDeflateFactory(client_max_window_bits=10),
            id="client-10-bits",
        ),
        pytest.param(
            ServerPerMessageDeflateFactory(client_max_window_bits=8),
            id="client-8-bits",
        ),
    ],
)
def test_deflate_send(deflate: ServerPerMessageDeflateFactory | None):
    # websockets decompresses what the client sends with the window and
    # context the server asked for, and fails the connection otherwise.
    with Server(echo, deflate) as srv, Session() as s:
        ws = s.ws_connect(srv.url, headers=DEFLATE_HEADER)
        assert ws._deflate_params is not None
        got = []
        for message in ECHOED:
            if isinstance(message, str):
                ws.send_str(message)
            else:
                ws.send(message)
            msg, flags = ws.recv(timeout=5)
            assert flags & CurlWsFlag.DEFLATE
            got.append(msg.decode() if flags & CurlWsFlag.TEXT else msg)
        ws.close()
    assert got == ECHOED


def test_deflate_send_off_and_not_negotiated():
    with Server(echo) as srv, Session() as s:
        ws = s.ws_connect(srv.url)
        assert ws._deflate_params is None
        assert ws.send_str("plain") == 5
        assert ws.recv(timeout=5)[0] == b"plain"
        ws.close()
    with Server(echo) as srv:
        ws = WebSocket(compress=False)
        ws.connect(srv.url, headers=DEFLATE_HEADER)
        assert ws.send_str("plain") == 5
        assert ws.recv(timeout=5)[0] == b"plain"
        ws.close()


@pytest.mark.parametrize(
    "head, params",
    [
        (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", None),
        (
            b"HTTP/1.1 101 OK\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            (15, False),
        ),
        (
            b"HTTP/1.1 101 OK\r\nsec-websocket-extensions: permessage-deflate; "
            b"client_no_context_takeover; server_max_window_bits=12\r\n\r\n",
            (15, True),
        ),
        (
            b"HTTP/1.1 101 OK\r\nSec-WebSocket-Extensions: x-foo, "
            b'permessage-deflate; client_max_window_bits="10"\r\n\r\n',
            (10, False),
        ),
        (
            b"HTTP/1.1 200 Connection established\r\n\r\n"
            b"HTTP/1.1 101 OK\r\nSec-WebSocket-Extensions: permessage-deflate; "
            b"client_max_window_bits=9\r\n\r\n",
            (9, False),
        ),
        (
            b"HTTP/1.1 302 Found\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"
            b"\r\nHTTP/1.1 101 OK\r\nUpgrade: websocket\r\n\r\n",
            None,
        ),
    ],
)
def test_permessage_deflate_params(head: bytes, params: tuple[int, bool] | None):
    assert _permessage_deflate_params(head) == params


def inflate(payloads: list[bytes], window_bits: int, shared: bool) -> list[bytes]:
    out = []
    inflater = zlib.decompressobj(-window_bits)
    for payload in payloads:
        if not shared:
            inflater = zlib.decompressobj(-window_bits)
        data, message = payload + b"\x00\x00\xff\xff", b""
        while True:  # small pieces: back-references must fit the window
            chunk = inflater.decompress(data, 256)
            message += chunk
            data = inflater.unconsumed_tail
            if not data and len(chunk) < 256:
                break
        out.append(message)
    return out


# What Google Chrome 155.0.8059.84 sent for three such text messages, an 8-byte
# binary one and an empty one (a local browser capture).
CHROME_TEXT = b'{"type":"quote","pair":"EURUSD","bid":1.08421,"ask":1.08425}' * 4
CHROME_FIRST = bytes.fromhex(
    "aa562aa92c4855b2522a2ccd2f4955d2512a48cc2c52b252720d0d0a0d7651d2514aca4c51"
    "b232d433b0303132d4514a2cce86f14c6bab87a05e0000"
)
CHROME_REPEAT = bytes.fromhex("1a697a0100")
CHROME_BINARY = bytes.fromhex("62646266616563e70000")


@pytest.mark.parametrize(
    "params, payloads",
    [
        ((15, False), [CHROME_FIRST, CHROME_REPEAT, CHROME_REPEAT]),
        ((15, True), [CHROME_FIRST, CHROME_FIRST, CHROME_FIRST]),
        ((10, False), [CHROME_FIRST, CHROME_REPEAT, CHROME_REPEAT]),
    ],
)
def test_deflate_like_chrome(params: tuple[int, bool], payloads: list[bytes]):
    ws = WebSocket()
    ws._deflate_params = params
    messages = [CHROME_TEXT] * 3 + [bytes(range(1, 9)), b""]
    got = [ws._deflate(m) for m in messages]
    assert got == payloads + [CHROME_BINARY, b"\x00"]


@pytest.mark.parametrize("window_bits", [8, 10, 15])
@pytest.mark.parametrize("no_context_takeover", [False, True])
def test_deflate_streams(window_bits: int, no_context_takeover: bool):
    ws = WebSocket()
    ws._deflate_params = (window_bits, no_context_takeover)
    # No repeats inside, so only the previous message can shorten the second;
    # 200 bytes fit even the smallest window zlib compresses with (2**9 - 262).
    text = b"".join(zlib.crc32(bytes([i])).to_bytes(4, "big") for i in range(50))
    messages = [text, text, b"", BIG]
    payloads = [ws._deflate(m) for m in messages]
    assert not any(p.endswith(b"\x00\x00\xff\xff") for p in payloads)
    assert inflate(payloads, window_bits, not no_context_takeover) == messages
    if no_context_takeover:
        assert payloads[0] == payloads[1]
    else:
        assert len(payloads[1]) < len(payloads[0]) / 4
