"""Live fingerprint comparison with real Chrome captures.

Takes the snapshot of tests/quic_bench/capture_curl_cffi.py (quic.browserleaks.com
twice for a resumed connection, fp.impersonate.pro, tls.peet.ws) and runs the
structural comparator of tests/quic_bench/fingerprint_diff.py against the Chrome
captures in tests/groundtruth. Needs internet access with UDP egress, or a
SOCKS5 proxy with UDP ASSOCIATE in FINGERPRINT_PROXY. Set RUN_LIVE_TESTS=1 to
run.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_LIVE_TESTS"), reason="set RUN_LIVE_TESTS=1"
)


def references(snapshot: dict) -> list[str]:
    """Like Chrome, curl uses real ECH when DNS has HTTPS records for the site
    (direct connections) and GREASE ECH behind a proxy."""
    first = snapshot["browserleaks_first"].get("data") or {}
    if ((first.get("tls") or {}).get("ech") or {}).get("ech_success"):
        return ["chrome154_dns_ech.json"]
    return ["chrome155.json", "chrome152.json"]


def comparator_failures(snapshot: dict, tcp: bool) -> dict[str, list[str]]:
    from fingerprint_diff import diff

    failures = {}
    for reference in references(snapshot):
        ref = json.loads((TESTS / "groundtruth" / reference).read_text())
        failed = diff(ref, snapshot).failed
        failures[reference] = [n for n in failed if n.startswith("tcp.") == tcp]
    return failures


@pytest.fixture(scope="module")
def snapshot() -> dict:
    sys.path.insert(0, str(TESTS / "quic_bench"))
    from capture_curl_cffi import capture

    snap = capture("live", proxy=os.environ.get("FINGERPRINT_PROXY"))
    if all("error" in snap[key] for key in ("peet", "browserleaks_tls")):
        pytest.skip(f"no internet access: {snap['browserleaks_tls']['error']}")
    for key in ("browserleaks_first", "browserleaks_resumed"):
        assert snap[key].get("http_version") == 30, (key, snap[key])
    return snap


def test_quic_matches_chrome(snapshot):
    failures = comparator_failures(snapshot, tcp=False)
    assert failures == dict.fromkeys(failures, [])


def test_tcp_matches_chrome(snapshot):
    if not snapshot["peet"].get("data"):
        pytest.skip(f"tls.peet.ws unavailable: {snapshot['peet']}")
    failures = comparator_failures(snapshot, tcp=True)
    assert failures == dict.fromkeys(failures, [])


def test_google_http3_certificate_verifies():
    """Google leaves the intermediate out over QUIC for the trust anchor IDs
    Chrome sends, so the client has to hold it."""
    from curl_cffi import CurlECode, CurlError, requests

    errors = []
    for _ in range(3):
        try:
            r = requests.get(
                "https://www.google.com/",
                impersonate="chrome",
                http_version="v3only",
                proxy=os.environ.get("FINGERPRINT_PROXY"),
                timeout=15,
            )
        except CurlError as e:
            assert e.code != CurlECode.PEER_FAILED_VERIFICATION, e
            errors.append(repr(e))
            continue
        assert (r.status_code, r.http_version) == (200, 30)
        return
    pytest.skip(f"no HTTP/3 handshake with www.google.com: {errors}")
