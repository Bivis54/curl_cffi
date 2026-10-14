"""HTTP/3 through SOCKS5 UDP ASSOCIATE (#842, #843, #743).

The local proxy emulates the ways real relays differ, including soax, which
only relays an association to a single destination. Every test checks that
curl used UDP ASSOCIATE, that each association carried exactly one
destination and no DNS, and that the request completed over HTTP/3.

Real proxies are tested when SOCKS5_UDP_PROXIES holds a comma separated list
of proxy URLs (socks5h://user:pass@host:port).
"""

from __future__ import annotations

import os
import time
from urllib.parse import urlsplit

import pytest

from curl_cffi import CurlOpt, requests


pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

MODES = {
    "plain": (),
    "single-target": ("--single-target",),
    "batched": ("--batch", "4"),
    "unspecified-relay": ("--bind-addr", "0.0.0.0"),
    "zero-reply-source": ("--reply-src", "zero"),
    "name-reply-source": ("--reply-src", "name"),
    "auth-required": ("--require-auth", "--single-target"),
}


def get(url, proxy, http_version, port, **kwargs):
    return requests.get(
        url,
        impersonate="chrome",
        http_version=http_version,
        proxy=proxy,
        verify=False,
        timeout=15,
        curl_options={
            CurlOpt.RESOLVE: [f"localhost:{port}:127.0.0.1"],
            CurlOpt.FORBID_REUSE: 1,
        },
        **kwargs,
    )


def assert_single_destination(assocs):
    assert assocs, "no UDP ASSOCIATE"
    for a in assocs:
        assert len(a["dst"]) == 1, a
        assert a["violations"] == 0, a
        assert a["dns"] == 0, a


@pytest.mark.parametrize("mode", list(MODES))
@pytest.mark.parametrize("http_version", ["v3only", "v3"])
@pytest.mark.parametrize("scheme", ["socks5h", "socks5"])
def test_http3_over_udp_associate(h3_server, socks_proxy, scheme, http_version, mode):
    proxy = socks_proxy(*MODES[mode])
    # A bulk transfer, so that a batching relay batches short header packets.
    url = h3_server.url + "?size=65536"
    started = time.monotonic()
    r = get(url, proxy.url(scheme), http_version, h3_server.port)
    elapsed = time.monotonic() - started
    assert r.status_code == 200
    assert r.http_version == 30
    assert len(r.json()["pad"]) == 65536
    assocs = proxy.settle(1)
    assert_single_destination(assocs)
    if mode == "batched":
        # Unsplit batches lose their datagrams and stall on retransmissions.
        assert assocs[0]["batched"] > 0
        assert elapsed < 1.0
    expected = "localhost" if scheme == "socks5h" else "127.0.0.1"
    assert assocs[0]["dst"] == [f"{expected}:{h3_server.port}"]
    if http_version == "v3only":
        assert not [r for r in proxy.records() if r.get("cmd") == "CONNECT"]


def test_one_association_per_connection(h3_server, socks_proxy):
    proxy = socks_proxy("--single-target")
    with requests.Session(
        curl_options={
            CurlOpt.RESOLVE: [f"localhost:{h3_server.port}:127.0.0.1"],
            CurlOpt.FORBID_REUSE: 1,
        }
    ) as s:
        for _ in range(3):
            r = s.get(
                h3_server.url,
                impersonate="chrome",
                http_version="v3only",
                proxy=proxy.url(),
                verify=False,
                timeout=15,
            )
            assert r.http_version == 30
    assocs = proxy.settle(3)
    assert len(assocs) == 3
    assert_single_destination(assocs)


def test_two_origins_two_associations(h3_server, socks_proxy):
    proxy = socks_proxy("--single-target")
    for host in ("localhost", "127.0.0.1"):
        r = get(
            f"https://{host}:{h3_server.port}/",
            proxy.url(),
            "v3only",
            h3_server.port,
        )
        assert r.http_version == 30
    assocs = proxy.settle(2)
    assert sorted(a["dst"][0] for a in assocs) == sorted(
        [f"localhost:{h3_server.port}", f"127.0.0.1:{h3_server.port}"]
    )
    assert_single_destination(assocs)


@pytest.mark.parametrize("server", ["h3_server", "h3_server_rejecting"])
def test_resumption_and_0rtt_through_proxy(request, socks_proxy, server):
    srv = request.getfixturevalue(server)
    proxy = socks_proxy("--single-target")
    with requests.Session(
        curl_options={
            CurlOpt.RESOLVE: [f"localhost:{srv.port}:127.0.0.1"],
            CurlOpt.FORBID_REUSE: 1,
        }
    ) as s:
        for _ in range(2):
            r = s.get(
                srv.url,
                impersonate="chrome",
                http_version="v3only",
                proxy=proxy.url(),
                verify=False,
                timeout=15,
            )
            assert r.status_code == 200
    fresh, resumed = srv.records()[-2], r.json()
    assert not fresh["resumed"]
    if server == "h3_server":
        assert resumed["resumed"] and resumed["early_data"]
    else:
        # The server forgot the ticket: the 0-RTT request was sent again.
        assert not resumed["resumed"] and not resumed["early_data"]
    assert_single_destination(proxy.settle(2))


REAL_PROXIES = [p for p in os.environ.get("SOCKS5_UDP_PROXIES", "").split(",") if p]
BROWSERLEAKS = "https://quic.browserleaks.com/?minify=1"
IMPERSONATE_H3 = "https://fp.impersonate.pro/api/http3"


@pytest.mark.skipif(not REAL_PROXIES, reason="SOCKS5_UDP_PROXIES not set")
@pytest.mark.parametrize(
    "proxy", REAL_PROXIES, ids=lambda p: f"{urlsplit(p).hostname}:{urlsplit(p).port}"
)
@pytest.mark.parametrize("http_version", ["v3only", "v3"])
@pytest.mark.parametrize("scheme", ["socks5h", "socks5"])
def test_real_proxy(proxy, scheme, http_version):
    """Three QUIC connections, two origins: each needs its own association."""
    proxy = scheme + "://" + proxy.split("://", 1)[-1]
    options = {CurlOpt.FORBID_REUSE: 1}
    if http_version == "v3":
        # "v3" races a TCP connection after 100 ms without QUIC data, which is
        # always the case behind a remote proxy; a single lost UDP packet then
        # lets TCP win. A longer race keeps the test about the UDP path.
        options[CurlOpt.HAPPY_EYEBALLS_TIMEOUT_MS] = 5000
    with requests.Session(curl_options=options) as s:
        responses = [
            s.get(
                url,
                impersonate="chrome",
                http_version=http_version,
                proxy=proxy,
                timeout=30,
            )
            for url in (BROWSERLEAKS, BROWSERLEAKS, IMPERSONATE_H3)
        ]
    assert [r.status_code for r in responses] == [200, 200, 200]
    assert [r.http_version for r in responses] == [30, 30, 30]
    fresh, resumed = responses[0].json(), responses[1].json()
    assert fresh["ja4"] == "q13d0312h3_55b375c5d22e_178839b6cec1"
    assert resumed["ja4"] == "q13d0314h3_55b375c5d22e_79cc91d6b50c"
    assert resumed["quic"]["0-rtt"]
    for data in (fresh, resumed):
        assert data["h3_hash"] == "ba909fc3dc419ea5c5b26c6323ac1879"
