"""WebSockets stay on TCP when HTTP/3 is requested.

curl bootstraps WebSockets over HTTP/1.1 only (RFC 6455), so through a SOCKS5
proxy they must use CONNECT and never open a UDP association, whatever
http_version the session asks for.
"""

from __future__ import annotations

import asyncio

import pytest

from curl_cffi import AsyncSession, Session


async def echo(ws) -> None:
    async for message in ws:
        await ws.send(message)


@pytest.fixture(scope="module")
def echo_url(wss_server) -> str:
    return wss_server(echo)


def commands(proxy) -> list[str]:
    return [r["cmd"] for r in proxy.records() if "cmd" in r]


@pytest.mark.parametrize("version", ["v3", "v3only"])
@pytest.mark.parametrize("scheme", ["socks5", "socks5h"])
def test_websocket_uses_connect(echo_url, socks_proxy, scheme, version):
    proxy = socks_proxy()
    with Session(impersonate="chrome", http_version=version) as s:
        ws = s.ws_connect(echo_url, proxy=proxy.url(scheme), verify=False)
        ws.send(b"over tcp")
        assert ws.recv()[0] == b"over tcp"
        ws.close()
    assert commands(proxy) == ["CONNECT"]


@pytest.mark.parametrize("version", ["v3", "v3only"])
def test_async_websocket_uses_connect(echo_url, socks_proxy, version):
    proxy = socks_proxy()

    async def main() -> bytes:
        async with AsyncSession(impersonate="chrome", http_version=version) as s:
            ws = await s.ws_connect(echo_url, proxy=proxy.url(), verify=False)
            await ws.send(b"over tcp")
            data, _ = await ws.recv()
            await ws.close()
            return data

    assert asyncio.run(main()) == b"over tcp"
    assert commands(proxy) == ["CONNECT"]
