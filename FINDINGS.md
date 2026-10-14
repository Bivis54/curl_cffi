# FINDINGS: QUIC through SOCKS5, indistinguishable from Chrome

This branch rebases the fork onto upstream curl_cffi **0.16.4b1**
(curl-impersonate **2.2.3**, curl **8.22**, BoringSSL, ngtcp2 1.20, nghttp3
1.15) and re-applies the fork's changes from scratch. One wheel now:

1. sends HTTP/3 through authenticated SOCKS5 proxies with UDP ASSOCIATE for
   `http_version="v3"` and `"v3only"`, with `socks5://` and `socks5h://`,
   including relays that only serve one destination per association (soax),
   relays that batch datagrams, and relays with odd BND.ADDR or reply headers;
2. produces a QUIC/HTTP/3 fingerprint that a structural comparator cannot tell
   apart from Chrome 152/155 on quic.browserleaks.com and fp.impersonate.pro,
   first connection and 0-RTT resumption included;
3. keeps the fork's WebSocket changes (`WebSocket._inflate`, own PONG in
   `recv_fragment`, `CurlWsFlag.DEFLATE`) and the Chrome TCP fingerprint, now
   with GREASE in `signature_algorithms` (peetprint matches);
4. has no CLOSE_WAIT build-up (#837) and keeps WebSockets on TCP.

Install (Linux x86_64, glibc >= 2.17, CPython >= 3.10):

```
pip install https://github.com/Bivis54/curl_cffi/releases/download/chrome152-3/curl_cffi-0.16.4b1-cp310-abi3-manylinux2014_x86_64.manylinux_2_17_x86_64.whl
```

The wheel reports `curl-impersonate/2.2.3-bivis.2` in
`curl_cffi.__curl_version__`.

## 1. Build path

- curl_cffi links one static `libcurl-impersonate.a`. Upstream's
  `scripts/build.py` downloads it prebuilt from lexiforest/curl-impersonate
  releases unless `IMPERSONATE_BUILD_DIR` points at a local build.
- The old fork downloaded `2.1.0-ws4` from Bivis54/curl-impersonate. Pushing
  to that repository is denied for this work (HTTP 403), so the native patches
  now live in this repository:
  - `native/curl-impersonate.env` pins upstream curl-impersonate `v2.2.3` and
    zig 0.15.2.
  - `native/patches/<dependency>/*.patch` are appended to the matching
    `patches/<dependency>.patch` of that release (curl, ngtcp2, nghttp3).
  - `scripts/build_libcurl_impersonate.sh OUT` clones the release, applies the
    patches and builds for `x86_64-linux-gnu.2.17` with zig (manylinux2014),
    then merges everything into `OUT/libdir/libcurl-impersonate.a`.
  - The `Makefile` applies `native/patches/curl/*.patch` when it preprocesses
    the curl headers for the cffi bindings.
- `.github/workflows/fork-wheel.yaml` builds the library (about 5 minutes,
  cached on `native/**`), builds the cp310-abi3 manylinux2014 x86_64 wheel with
  cibuildwheel (which also runs the unit suite), verifies the wheel on Ubuntu
  24.04 (section 7) and publishes a pre-release for `chrome152-*` tags.
- Only Linux x86_64 is built. Upstream's multi-platform jobs in
  `build-and-test.yaml` link upstream's prebuilt library, which lacks these
  patches, so they now only run in lexiforest/curl_cffi; lint and sdist still
  run here. For the same reason `scripts/build.py` without
  `IMPERSONATE_BUILD_DIR` builds against a library without the fork's
  patches; build with `scripts/build_libcurl_impersonate.sh out` and
  `IMPERSONATE_BUILD_DIR=out/libdir`.

## 2. The old fork's changes and where they went

| Change in chrome152-2 / its curl-impersonate | Status on 0.16.4b1 |
| --- | --- |
| (a) `WebSocket._inflate`, `CurlWsFlag.DEFLATE` (RSV1 reported to Python) | Re-applied: `native/patches/curl/0001`, `curl_cffi/requests/websockets.py` |
| (b) Own PONG in `recv_fragment` | Re-applied and extended (below) |
| (c) chrome152 target with trust anchor IDs (`trust-anchors.patch`) | 2.2.3 already has the `CURLOPT_TLS_TRUST_ANCHORS` machinery; only the chrome152 entry is carried (`0005`) |
| (c) `chrome152` in `impersonate.py` | Re-applied; `chrome` now resolves to `chrome152` |
| (d) `build.py` pointing at `2.1.0-ws4`, `bin/curl_chrome152`, `win/build.bat` | Replaced by the in-repo native build; the CLI wrapper is not needed by curl_cffi |

The brief says upstream 0.16.3 ships a chrome152 target; it does not. The
newest native target in curl-impersonate 2.2.3 is `chrome150`, so the fork
keeps its own chrome152 entry.

Own PONG: since curl 8.21 the automatic PONG is queued in `ws->pending` and
only flushed by the next send, so a connection that only receives pings never
answers them and the server closes it at its ping timeout. The fork sets
`CURLWS_NOAUTOPONG` on every WebSocket handle and replies itself in `recv`,
`recv_fragment`, `run_forever` and the async reader (RFC 6455 5.5.3: the PONG
echoes the PING payload).

## 3. HTTP/3 through SOCKS5 UDP ASSOCIATE

curl 8.22 already contains the fixes for #842/#843 (UDP ASSOCIATE decided at
connect time) and #743 (`v3` with a proxy). Real relays needed more:

| Problem found | Effect before | Fix |
| --- | --- | --- |
| Relay sends several complete SOCKS datagrams (each with its own header) in one UDP datagram; seen on 24.144.88.46 | upstream reads the first QUIC packet, drops the rest; HTTP/3 stalls or times out on most sites | `0002`: split batches, one datagram per read |
| BND.ADDR `0.0.0.0`, private, CGNAT or loopback from a public proxy | datagrams sent to an unusable address | `0002`: fall back to the proxy's address |
| Reply headers with a zero or domain source address | upstream took the QUIC peer from each reply header; with `socks5://` a zeroed source no longer matched the path and ngtcp2 dropped the packets | `0002`: the QUIC peer never changes after setup |
| Local HTTPS-RR (DNS) lookups for the origin while using a proxy | DNS leak, and ECH configs Chrome behind a proxy never has (changes the resumed JA4) | `0003`: no HTTPS-RR query when a proxy resolves the origin |
| `socks5://` sends the IPv6 address of dual-stack names (curl 8.22 prefers IPv6, the proxy cannot fall back) | www.facebook.com through an IPv4-only relay: error 7 over QUIC, 97 over TCP | `0007`: prefer IPv4 unless `CURLOPT_IPRESOLVE` asks for IPv6 |

### Single-destination relays (soax) and why routers work

soax support says one association reliably serves only one destination. The
owner's probe sends DNS queries through an association, then reuses it, and
the second run fails with `dns rcode 2`. curl's design avoids every part of
that, verified with the local proxy's `--single-target` mode, which drops and
counts datagrams to a second destination:

- One UDP association per QUIC connection, opened by the connection and
  closed with it. A new connection, including a resumption, opens a new
  association (`test_one_association_per_connection`: 3 connections, 3
  associations).
- One destination per association, always written the same way: the host
  name for `socks5h://`, the resolved IP for `socks5://`. Two origins get two
  associations (`test_two_origins_two_associations`).
- Nothing but QUIC packets to that destination: no DNS or probes through the
  relay (every association logs `dns: 0`, `violations: 0`).
- The UDP ASSOCIATE request carries `0.0.0.0:0`, which relays accept when the
  client is behind NAT.

Routers that "just work" with soax (tun2socks, sing-box, Clash and similar)
do the same thing: one association per UDP flow (source and destination),
DNS resolved separately, never mixing destinations, so they never hit the
restriction. Real soax and proxyshard credentials have not been provided
yet; `test_real_proxy` runs against any list in `SOCKS5_UDP_PROXIES`.

### `v3` races TCP behind a proxy

With `http_version="v3"` curl starts a TCP attempt when the QUIC attempt has
seen no data after 100 ms (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS / 2`), and
always after 200 ms. Behind a remote proxy the SOCKS handshake alone takes
longer, so the proxy normally sees a TCP CONNECT next to the UDP ASSOCIATE
(verified by chaining the logging proxy in front of 206.189.95.199). QUIC
normally wins; in 30 sessions through 206.189.95.199 one first request was
won by TCP after a lost UDP packet. This is curl's design, close to Chrome,
which also races TCP on connections where QUIC is not yet known to work.
Use `v3only` for UDP only, or a larger `HAPPY_EYEBALLS_TIMEOUT_MS`.

## 4. QUIC fingerprint parity

Reference: Chrome for Testing 152.0.7977.82 and Chrome 155.0.8059.39 captured
in CI (`.github/workflows/quic-bench.yaml`, `tests/groundtruth/`); Chrome
152, 154 and 155 produce the same QUIC fingerprint when ECH is GREASE.

| Field | Chrome | upstream 0.16.4b1 | chrome152-2 | this branch |
| --- | --- | --- | --- | --- |
| JA4, first | `q13d0312h3_55b375c5d22e_178839b6cec1` | `q13d0311h3_…_653d80c3fe9d` | same as Chrome | same as Chrome |
| JA4, resumed | `q13d0314h3_55b375c5d22e_79cc91d6b50c` | `q13d0311h3_…` (no resumption) | `q13d0313h3_…_b0954bf1abdf` | same as Chrome |
| `h3_hash` | `ba909fc3dc419ea5c5b26c6323ac1879` | `e1d11ee6…` | `e1d11ee6…` | same as Chrome |
| Extension order | permuted, PSK last | permuted | sorted | permuted per connection, PSK last |
| Initial packets | 2 x 1250 B, PN 1, 2 | 2 x 1200 B, PN 1, 2 | 2 x 1200 B, PN 0, 1 | 2 x 1250 B, PN 1, 2 |
| HTTP/3 frames | SETTINGS, GREASE, PRIORITY_UPDATE, HEADERS | SETTINGS, HEADERS | SETTINGS, HEADERS | as Chrome |
| `initial_rtt` TP | resumed only | none | none | resumed only |
| 0-RTT, early_data, token | yes | no | no | yes |
| TCP JA4 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `t13d1516h2_…_806a8c22fdea` | same as Chrome | same as Chrome |
| TCP peetprint | `fc97c1cdfb1409c9a9326c1b726d1dee` | `67c3e911…` | `1528e8ef…` | same as Chrome |

Levers (`native/patches/`):

- **Extension permutation**: BoringSSL's permutation on the QUIC handshake
  (`http3_ssl_permute_extensions`) with Chrome's HTTP/3 extension set; PSK
  stays last and the order changes with every connection.
- **Initial size 1250**: `CURLOPT_QUIC_MAX_UDP_PAYLOAD_SIZE` sets ngtcp2's
  `max_tx_udp_payload_size`, without payload shaping or PMTUD.
- **First packet number 1**: 2.2.3's `quic_initial_packet_number`.
- **ClientHello split**: Chrome's resumed ClientHello fits in two Initials;
  ngtcp2's Initial "crumbling" needed three in 4 of 5 attempts. The ngtcp2
  patch packs CRYPTO data densely, splits the SNI inside a packet and fills
  gaps with PING frames only, so the rest can be padding or coalesced 0-RTT.
- **HTTP/3 GREASE frame**: new `nghttp3_conn_submit_grease_frame()` (nghttp3
  patch), sent on the control stream after SETTINGS, type `0x1f * N + 0x21`
  with `N % 4` bytes like Chromium.
- **PRIORITY_UPDATE**: sent for the request stream unless the priority is the
  default `u=3`, giving Chrome's `984832` (`0xF0700`) frame.
- **`initial_rtt`** (TP 0x3127): the `12583:CACHED` keyword sends the smoothed
  RTT remembered from the previous connection to the host, and nothing on a
  first connection, as Chrome does.
- **0-RTT, early_data, address token**: BoringSSL early data for QUIC on
  resumption (GET/HEAD only), 0-RTT transport parameters, `NEW_TOKEN` tokens
  kept per peer in the session cache and replayed. A server rejecting 0-RTT
  makes curl re-send the request after the handshake (tested).
- **0-RTT packet layout** (`0008`): with early data curl wrote nothing until
  the request was added, so whenever the ClientHello filled the second Initial
  datagram, SETTINGS, GREASE, PRIORITY_UPDATE and HEADERS shared one 0-RTT
  packet. quic.browserleaks.com reads the streams concurrently and reported
  only SETTINGS and HEADERS for 2 of 20 resumed connections (`h3_hash`
  mismatch). Chrome sends the control stream in its first flight and the
  request in a later packet (seen in a decrypted local capture); curl now does
  the same, and 40 of 40 resumed connections were correct afterwards.
- **Transport parameter details**: GREASE TP with 0-15 random bytes and a
  random GREASE position in `version_information`, both like Chromium.
- **TCP**: `CURLOPT_TLS_GREASE_SIGALGS` (BoringSSL
  `SSL_CTX_set_grease_sigalgs_enabled`, Chromium `kTlsGreaseSigalgs`), only
  over TCP like Chrome.
- **Trust anchor IDs** (`0006`): chrome152 advertises Chrome's 28 trust
  anchor IDs, 15 of which belong to intermediates (Google WR1-4, WE1-4, AE1;
  Let's Encrypt E7-9, R12-14) that Chrome's root store treats as trust
  anchors. Google then sends only the leaf over QUIC, and verification against
  a roots-only CA bundle failed with curl error 60. Transfers advertising
  these IDs now load the matching certificates
  (`scripts/gen_trust_anchor_certs.py` regenerates them from Chromium).

Structural comparator (`tests/quic_bench/fingerprint_diff.py`) against
`tests/groundtruth/chrome155.json` (the same with `chrome152.json`): **0
failed checks** for this branch, **23** for chrome152-2, **25** for upstream
0.16.4b1. Like Chrome, curl uses real ECH when DNS has HTTPS records for the
site, which is the case on direct connections; behind a proxy neither has
them and both use GREASE ECH. CI therefore compares a direct capture with
`chrome154_dns_ech.json` and a capture through a local SOCKS5 proxy with the
Chrome 155 and 152 captures; both show 0 failed checks.

### Chrome details found while measuring

- `initial_rtt` only appears when Chrome has an RTT for the host, so never on
  a first connection.
- Chrome replays the server's address token only sometimes: 4 of 11 resumed
  captures, and the same Chrome for Testing 152 build did it in two runs and
  not in a third. quiche's `QuicClientSessionCache::OnNewTokenReceived` drops a
  token that arrives before the session entry exists, and
  `TlsClientHandshaker::InsertSession` only creates the entry after the
  server's HTTP/3 SETTINGS, so it is a race. The fork always keeps the token
  (the case the brief asks for); the references used have it.
- With DNS HTTPS records Chrome uses real ECH and the resumed JA4 becomes
  `q13d0313h3_…_27b11b7e031e` (`chrome154_dns_ech.json`). Behind a proxy
  Chrome has no HTTPS records and uses GREASE ECH, which is what the fork
  does and why `0003` stops local HTTPS-RR lookups behind proxies.
- Chrome's first load of fp.impersonate.pro is HTTP/2; the capture retries
  until HTTP/3.

## 5. Preserved behaviour and regressions

| Check | Before | After |
| --- | --- | --- |
| Markers: `WebSocket._inflate`, PONG in `recv_fragment`, `CurlWsFlag.DEFLATE == 128` | missing on upstream | present |
| `tests/unittest/test_websockets_fork.py` (inflate with context takeover and fragments; PONG from 4 readers) | upstream 0.16.4b1: 8 of 8 fail | 8 pass |
| Idle wss, server pings every 20 s with a 10 s timeout, 70 s | upstream 0.16.4b1: `recv`, `run_forever` and async reader all dropped at 30 s | all alive at 70 s |
| CLOSE_WAIT through a SOCKS proxy, TLS peer without close_notify, 6 x 100 requests (#837) | 0.16.0: 22, 32, 41, 53, 65, 77 (0.16.4b1: all 0) | 0, 0, 0, 0, 0, 0 |
| WebSocket with `http_version` v3/v3only through SOCKS5 | TCP (curl bootstraps WebSockets over HTTP/1.1 only) | only CONNECT, no UDP ASSOCIATE |
| Local SOCKS5 relay matrix (`tests/integration/test_socks5_udp.py`, 34 cases) | chrome152-2: 0 pass; upstream 0.16.4b1: 25 pass | 34 pass |

## 6. Known issues

- **Google and YouTube over QUIC through the maintainer's test relays** often
  end in handshake timeouts for every client: upstream 0.16.4b1 failed 12 of
  12 attempts through 206.189.95.199, this branch 14 of 16. In the failing
  attempts the relay returns a single datagram from Google. Other QUIC sites work
  through the same relays, and Google works from CI with direct UDP
  (`test_google_http3_certificate_verifies`).
- **QPACK differs from Chrome, visible to the server only** (decrypted local
  captures). Chrome opens its QPACK encoder stream with the first request,
  inserts most headers into the dynamic table (about 400 bytes of encoder
  instructions, a 20-byte HEADERS frame) and uses remembered server SETTINGS
  for 0-RTT. nghttp3 opens the control, encoder and decoder streams together,
  sends a 190-byte HEADERS frame on new connections and only literal headers
  (430 bytes) in 0-RTT. quic.browserleaks.com and fp.impersonate.pro do not
  report this; matching it needs a different encoder strategy in nghttp3.
- `Curl.getinfo(CurlInfo.CERTINFO)` crashes: curl_cffi treats the
  `struct curl_certinfo *` result as a `curl_slist` and frees curl's memory.
  This is upstream curl_cffi code, unchanged here.
- Only Linux x86_64 wheels are built (section 1).
- Real soax and proxyshard runs are pending credentials.

## 7. Test bench

- `tests/integration/test_socks5_udp.py`: HTTP/3 through the local proxy in
  every scheme x version x relay mode (plain, single target, batching,
  unspecified BND.ADDR, zero and domain reply sources, mandatory auth), one
  association per connection and origin, 0-RTT and 0-RTT rejection through
  the proxy, IPv4 preference, and real proxies from `SOCKS5_UDP_PROXIES`.
- `tests/integration/test_websocket_idle.py` (`RUN_SLOW_TESTS=1`),
  `test_close_wait.py`, `test_websocket_transport.py`,
  `test_http3_early_data.py` (0-RTT request after the control streams),
  `tests/unittest/test_websockets_fork.py`.
- `tests/integration/test_quic_fingerprint.py` (`RUN_LIVE_TESTS=1`, optional
  `FINGERPRINT_PROXY`): live capture diffed against the Chrome references,
  and Google over HTTP/3 with certificate verification.
- `tests/quic_bench/`: `capture_chrome.py` (Playwright, Chrome for Testing),
  `capture_curl_cffi.py`, `fingerprint_diff.py`, `h3_server.py` (aioquic) and
  `socks5_udp.py` (CONNECT and UDP ASSOCIATE with the relay modes above,
  chaining to an upstream proxy, JSON log per association).

With an installed wheel, run them from a copy of `tests/` (and `assets/`)
outside the source tree, as `fork-wheel.yaml` does, so that the source
package does not shadow the wheel:

```
python tests/quic_bench/capture_curl_cffi.py --out snap --proxy socks5h://user:pass@host:port
python tests/quic_bench/fingerprint_diff.py tests/groundtruth/chrome155.json snap/curl_cffi.json
SOCKS5_UDP_PROXIES=socks5h://user:pass@host:port RUN_SLOW_TESTS=1 python -m pytest tests/integration
```

Issues: #842, #843 (SOCKS5 UDP regression), #743 (`v3` with a proxy), #837
(CLOSE_WAIT).
