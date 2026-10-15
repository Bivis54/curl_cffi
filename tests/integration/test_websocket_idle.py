"""An idle secure WebSocket survives the server's ping timeout.

The server pings every 20 s and drops clients that do not answer within
10 s. With libcurl's stranded auto-PONG that killed idle connections at the
first ping deadline (~61 s with common exchange settings). Connections that
only receive pings must stay open for 70 s. Set RUN_SLOW_TESTS=1 to run.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time

import pytest

from curl_cffi import AsyncSession, Session
from curl_cffi.requests.websockets import WebSocket, WebSocketTimeout

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_SLOW_TESTS"), reason="set RUN_SLOW_TESTS=1"
)

IDLE = 70.0


async def wait_closed(ws) -> None:
    await ws.wait_closed()


@pytest.fixture(scope="module")
def wss_url(wss_server) -> str:
    return wss_server(wait_closed, ping_interval=20, ping_timeout=10)


def idle_recv(url: str, out: dict) -> None:
    with Session() as s:
        ws = s.ws_connect(url, verify=False)
        started = time.monotonic()
        try:
            ws.recv(timeout=IDLE)
        except WebSocketTimeout:
            out["recv"] = ("alive", time.monotonic() - started)
        except Exception as e:  # noqa: BLE001
            out["recv"] = (f"dropped: {e!r}", time.monotonic() - started)
        else:
            out["recv"] = ("unexpected message", time.monotonic() - started)
        ws.close()


def idle_run_forever(url: str, out: dict) -> None:
    started = time.monotonic()
    closed: list[tuple[int, float]] = []

    def on_open(ws: WebSocket) -> None:
        threading.Timer(IDLE, ws.close).start()

    def on_close(ws: WebSocket, code: int, reason: str) -> None:
        closed.append((code, time.monotonic() - started))

    ws = WebSocket(on_open=on_open, on_close=on_close)
    try:
        ws.run_forever(url, verify=False)
    except Exception as e:  # noqa: BLE001
        out["run_forever"] = (f"dropped: {e!r}", time.monotonic() - started)
        return
    elapsed = time.monotonic() - started
    out["run_forever"] = ("alive" if elapsed >= IDLE - 1 else "dropped", elapsed)


def idle_async(url: str, out: dict) -> None:
    async def main():
        async with AsyncSession() as s:
            ws = await s.ws_connect(url, verify=False)
            started = time.monotonic()
            try:
                await ws.recv(timeout=IDLE)
            except WebSocketTimeout:
                out["async"] = ("alive", time.monotonic() - started)
            except Exception as e:  # noqa: BLE001
                out["async"] = (f"dropped: {e!r}", time.monotonic() - started)
            else:
                out["async"] = ("unexpected message", time.monotonic() - started)
            await ws.close()

    asyncio.run(main())


def test_idle_secure_websocket_survives_server_pings(wss_url):
    out: dict[str, tuple[str, float]] = {}
    threads = [
        threading.Thread(target=fn, args=(wss_url, out))
        for fn in (idle_recv, idle_run_forever, idle_async)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(IDLE + 30)
    print(out)
    assert set(out) == {"recv", "run_forever", "async"}
    for name, (state, elapsed) in out.items():
        assert state == "alive", (name, state, elapsed)
        assert elapsed >= IDLE - 1, (name, elapsed)
