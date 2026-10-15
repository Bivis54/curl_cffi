"""0-RTT requests follow the HTTP/3 control streams in a later packet.

Chrome sends SETTINGS and GREASE on the control stream with its first flight
and the request afterwards. Servers that read the control stream and the
request concurrently (quic.browserleaks.com) otherwise sometimes see the
request before the control frames that arrived in the same packet.
"""

from __future__ import annotations

from curl_cffi import CurlOpt, requests

# A long name makes the ClientHello fill the second Initial datagram, so the
# control streams cannot ride along in it.
LONG_HOST = ".".join(["a" * 63, "b" * 63, "c" * 63, "test"])


def test_early_data_request_follows_control_streams(h3_server):
    port = h3_server.port
    options = {
        CurlOpt.RESOLVE: [f"{LONG_HOST}:{port}:127.0.0.1"],
        CurlOpt.FORBID_REUSE: 1,
    }
    with requests.Session(curl_options=options) as s:
        for _ in range(2):
            r = s.get(
                f"https://{LONG_HOST}:{port}/",
                impersonate="chrome",
                http_version="v3only",
                verify=False,
                timeout=10,
            )
    resumed = r.json()
    assert resumed["resumed"] and resumed["early_data"]
    assert resumed["control_datagram"] < resumed["headers_datagram"], resumed
