#!/usr/bin/env python3
"""Verbose diagnostics for HTTP/3 through SOCKS5 UDP ASSOCIATE.

Companion of test_real_proxies.py, which must be in the same directory: same
environment variables (PROXYSHARD_SOCKS5_URL, SOAX_SOCKS5_URL), never prints
them, and scrubs the proxy URL, credentials, host and addresses from
everything it prints or writes. Each probe is one request (two for resume)
with curl's verbose output and its SOCKS, HTTP/3 (QUIC), UDP, TCP, TLS and
connection setup traces. The informative lines are printed with the time
since the probe started, followed by datagram and packet counts and a
PASS/FAIL line against the probe's criteria; the full traces go to
--trace-dir.

Probes per provider:
  tcp       HTTPS over TCP through the proxy (SOCKS5 CONNECT)
  h3        Cloudflare's trace endpoint over HTTP/3 through socks5h://
  h3-local  the same through socks5:// (destination resolved locally)
  resume    quic.browserleaks.com twice; the second connection resumes with 0-RTT
  google    www.google.com over HTTP/3 through socks5h://
--direct adds h3, resume and google without a proxy (needs UDP egress).

Exit status: 0 when every probe passed, 1 when one failed, 2 when no provider
is configured, 3 when the script itself failed.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from io import BytesIO
from pathlib import Path

import curl_cffi
import curl_cffi._wrapper
from curl_cffi import Curl, CurlInfo, CurlOpt
from test_real_proxies import (
    CHROME_JA4,
    PROVIDERS,
    TARGETS,
    Redactor,
    chrome_ja4,
    direct_ip,
    load_providers,
)

TRACE_CONFIG = "socks,http/3,udp,tcp,ssl,happy-eyeballs,https-connect,setup,dns"
CURLINFO_TEXT, CURLINFO_HEADER_IN, CURLINFO_HEADER_OUT = 0, 1, 2
HTTP_VERSION_3ONLY = 31
HTTP3 = 30
MAX_SHOWN_LINES = 200
# Per-packet and bookkeeping lines; they stay in the trace files.
NOISE = re.compile(
    r"QUIC over SOCKS UDP (send|recv):|\[(UDP|TCP)\] (send|recv)\(|progress_ingress"
    r"|egress, collect and send|egress, send collected|recvd \d+ packets with"
    r"|cf_recv\(buflen=|cf_send\(|adjust.pollset|rx window|\[DNS\] (get|cache"
    r"|cached|added|\[A)|hostip_resolv|check for next|want to do more"
    r"|connect -> 0, done=0|Curl_conn_connect\(block=0\) -> 0, done=0"
    r"|HTTPS-RR not available|checked connect attempts|\[HTTP/3\] \[\d+\] \[[^]]+: "
    r"|query ALPN|removing connected setup filter|\] destroy$|\] added$"
    r"|connected filter chain below|Curl_conn_connect\(block=0\) -> 0, done=1"
    r"|\[HTTP/3\] \[\d+\] header: |ms > (?!GET |POST |HEAD )"
)


@dataclass
class Probe:
    provider: str
    name: str
    criteria: str
    result: str = "FAIL"
    observed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Tracer:
    """Collects curl's verbose output of one probe."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.started = time.monotonic()

    def __call__(self, kind: int, data: bytes) -> None:
        if kind not in (CURLINFO_TEXT, CURLINFO_HEADER_IN, CURLINFO_HEADER_OUT):
            return
        mark = {CURLINFO_HEADER_IN: "< ", CURLINFO_HEADER_OUT: "> "}.get(kind, "")
        ms = (time.monotonic() - self.started) * 1000
        for line in data.decode(errors="replace").splitlines():
            if line.strip():
                self.lines.append(f"{ms:7.0f}ms {mark}{line}")

    def text(self) -> str:
        return "\n".join(self.lines)


def enable_curl_traces() -> bool:
    """Turns on curl's per-filter traces, which curl_cffi has no binding for."""
    try:
        lib = ctypes.CDLL(curl_cffi._wrapper.__file__)
        lib.curl_global_trace.argtypes = [ctypes.c_char_p]
        lib.curl_global_trace.restype = ctypes.c_int
        return lib.curl_global_trace(TRACE_CONFIG.encode()) == 0
    except (OSError, AttributeError):
        return False


def stats(trace: str) -> str:
    sent = [int(n) for n in re.findall(r"\[UDP\] send\(len=\d+\) -> 0, (\d+)", trace)]
    recv = [int(n) for n in re.findall(r"\[UDP\] recv\(len=\d+\) -> 0, (\d+)", trace)]
    packets = sum(map(int, re.findall(r"recvd (\d+) packets with", trace)))
    parts = [
        f"UDP datagrams sent {len(sent)} ({sum(sent)} B), "
        f"received {len(recv)} ({sum(recv)} B), QUIC packets received {packets}"
    ]
    if "batches datagrams" in trace:
        parts.append("relay batches datagrams (split)")
    handshake = re.search(r"handshake complete after (\d+)ms", trace)
    if handshake:
        parts.append(f"QUIC handshake {handshake.group(1)} ms")
    return "; ".join(parts)


class Diagnosis:
    def __init__(
        self, args: argparse.Namespace, redact: Redactor, traced: bool
    ) -> None:
        self.args = args
        self.redact = redact
        self.traced = traced
        self.direct_ip: str | None = None
        self.probes: list[Probe] = []
        Path(args.trace_dir).mkdir(parents=True, exist_ok=True)

    def perform(
        self, curl: Curl, tracer: Tracer, url: str, proxy: str | None, h3: bool
    ) -> tuple[int, int, str, str | None]:
        body = BytesIO()
        curl.setopt(CurlOpt.URL, url)
        # perform() drops the callback contexts afterwards while libcurl keeps
        # pointers to them: set the callbacks again before every perform().
        curl.setopt(CurlOpt.WRITEDATA, body)
        curl.setopt(CurlOpt.DEBUGFUNCTION, tracer)
        # An empty proxy also disables libcurl's proxy environment variables.
        curl.setopt(CurlOpt.PROXY, proxy or "")
        if h3:
            curl.setopt(CurlOpt.HTTP_VERSION, HTTP_VERSION_3ONLY)
        tracer.lines.append(f"{'':7}   ---- GET {url}")
        try:
            curl.perform()
        except Exception as e:  # noqa: BLE001
            return 0, 0, "", str(e)
        return (
            int(curl.getinfo(CurlInfo.RESPONSE_CODE)),
            int(curl.getinfo(CurlInfo.HTTP_VERSION)),
            body.getvalue().decode(errors="replace"),
            None,
        )

    def new_curl(self) -> Curl:
        curl = Curl()
        curl.impersonate("chrome152")
        curl.setopt(CurlOpt.ACCEPT_ENCODING, "gzip, deflate, br, zstd")
        curl.setopt(CurlOpt.TIMEOUT, int(self.args.timeout))
        curl.setopt(CurlOpt.FORBID_REUSE, 1)
        curl.setopt(CurlOpt.VERBOSE, 1)
        return curl

    @staticmethod
    def finish(curl: Curl) -> None:
        # curl_cffi before chrome152-4 frees the debug callback context before
        # curl_easy_cleanup(), which still logs; no verbose output, no logging.
        curl.setopt(CurlOpt.VERBOSE, 0)
        curl.close()

    def report(self, probe: Probe, tracer: Tracer) -> None:
        trace = self.redact(tracer.text())
        probe.errors = [self.redact(e) for e in probe.errors]
        probe.observed = [self.redact(o) for o in probe.observed]
        if not probe.errors:
            probe.result = "PASS"
        path = Path(self.args.trace_dir) / f"{probe.provider}-{probe.name}.log"
        path.write_text(trace + "\n")
        shown = [line for line in trace.splitlines() if not NOISE.search(line)]
        if len(shown) > MAX_SHOWN_LINES:
            half = MAX_SHOWN_LINES // 2
            skipped = len(shown) - 2 * half
            shown = [
                *shown[:half],
                f"   ... {skipped} lines, see {path}",
                *shown[-half:],
            ]
        print(f"\n=== {probe.provider} / {probe.name}")
        print(f"criteria: {probe.criteria}")
        print(f"--- trace (informative lines; full trace in {path})")
        print("\n".join(shown))
        print(f"--- {stats(trace)}")
        for item in probe.observed:
            print(f"observed: {item}")
        for error in probe.errors:
            print(f"error: {error}")
        print(f"RESULT {probe.provider}/{probe.name}: {probe.result}")
        self.probes.append(probe)

    def check_h3(self, probe: Probe, status: int, version: int) -> None:
        probe.observed.append(f"HTTP status {status}, CURLINFO_HTTP_VERSION {version}")
        if version != HTTP3:
            probe.errors.append(f"not HTTP/3 (CURLINFO_HTTP_VERSION {version})")

    def cloudflare(self, probe: Probe, body: str, expect: str = "http/3") -> None:
        fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        ip = fields.get("ip", "?")
        shown = ip if self.args.show_ips else "hidden"
        probe.observed.append(
            f"Cloudflare: http={fields.get('http', '?')} loc={fields.get('loc', '?')} "
            f"ip={shown}"
        )
        if fields.get("http") != expect:
            probe.errors.append(f"Cloudflare received {fields.get('http', '?')}")
        if probe.provider != "direct" and self.direct_ip and ip == self.direct_ip:
            probe.errors.append("exit address is this machine's: proxy bypassed")

    def probe_tcp(self, provider: str, url: str) -> None:
        probe = Probe(
            provider,
            "tcp",
            "HTTPS over TCP through the proxy returns 200: the proxy is reachable "
            "and accepts the credentials (isolates UDP problems)",
        )
        tracer = Tracer()
        curl = self.new_curl()
        status, version, body, error = self.perform(
            curl, tracer, TARGETS["cloudflare"], url, h3=False
        )
        self.finish(curl)
        if error:
            probe.errors.append(error)
        else:
            probe.observed.append(
                f"HTTP status {status}, CURLINFO_HTTP_VERSION {version}"
            )
            if status != 200:
                probe.errors.append(f"HTTP status {status}")
            self.cloudflare(probe, body, expect="http/2")
        self.report(probe, tracer)

    def probe_h3(self, provider: str, url: str | None, name: str) -> None:
        via = "without a proxy" if url is None else f"through {url.split(':')[0]}://"
        criteria = (
            f"Cloudflare's trace endpoint over HTTP/3 {via}: CURLINFO_HTTP_VERSION 30 "
            "and Cloudflare reports http=http/3"
        )
        if url is not None:
            criteria += (
                ", the trace shows 'SOCKS5 UDP relay is' (UDP ASSOCIATE granted) and "
                "the exit address differs from this machine's"
            )
        probe = Probe(provider, name, criteria)
        tracer = Tracer()
        curl = self.new_curl()
        status, version, body, error = self.perform(
            curl, tracer, TARGETS["cloudflare"], url, h3=True
        )
        self.finish(curl)
        if error:
            probe.errors.append(error)
        else:
            self.check_h3(probe, status, version)
            self.cloudflare(probe, body)
        if url is not None and "SOCKS5 UDP relay is" not in tracer.text():
            probe.errors.append("no 'SOCKS5 UDP relay is' in the trace")
        self.report(probe, tracer)

    def probe_resume(self, provider: str, url: str | None) -> None:
        probe = Probe(
            provider,
            "resume",
            "two connections to quic.browserleaks.com over HTTP/3; the first has "
            f"JA4 {CHROME_JA4['fresh']}, the second resumes with 0-RTT: JA4 "
            f"{CHROME_JA4['resumed']} ({CHROME_JA4['resumed-ech']} when ECH configs "
            "came from DNS), quic.0-rtt true and 'server did accept N "
            "bytes of early data' in the trace",
        )
        tracer = Tracer()
        curl = self.new_curl()
        for kind in ("fresh", "resumed"):
            status, version, body, error = self.perform(
                curl, tracer, TARGETS["browserleaks"], url, h3=True
            )
            if error:
                probe.errors.append(f"{kind}: {error}")
                continue
            self.check_h3(probe, status, version)
            try:
                data = json.loads(body)
            except ValueError:
                probe.errors.append(f"{kind}: no JSON from quic.browserleaks.com")
                continue
            ja4, zero_rtt = data.get("ja4"), (data.get("quic") or {}).get("0-rtt")
            probe.observed.append(
                f"{kind}: JA4 {ja4}, h3_hash {data.get('h3_hash')}, 0-rtt {zero_rtt}"
            )
            expected = chrome_ja4(kind, data)
            if ja4 != expected:
                probe.errors.append(f"{kind}: JA4 {ja4}, Chrome {expected}")
            if kind == "resumed" and not zero_rtt:
                probe.errors.append("resumed: no 0-RTT")
        self.finish(curl)
        early = re.findall(
            r"server did( not)? accept (\d+) bytes of early data", tracer.text()
        )
        probe.observed.append(
            "early data: "
            + (
                ", ".join(f"{'rejected' if n else 'accepted'} {b} B" for n, b in early)
                or "none"
            )
        )
        if self.traced and not probe.errors and not any(not n for n, _ in early):
            probe.errors.append("resumed: early data not accepted by the server")
        self.report(probe, tracer)

    def probe_google(self, provider: str, url: str | None) -> None:
        probe = Probe(
            provider,
            "google",
            "www.google.com/generate_204 over HTTP/3: status 204, "
            "CURLINFO_HTTP_VERSION 30",
        )
        tracer = Tracer()
        curl = self.new_curl()
        status, version, _, error = self.perform(
            curl, tracer, TARGETS["google"], url, h3=True
        )
        self.finish(curl)
        if error:
            probe.errors.append(error)
        else:
            self.check_h3(probe, status, version)
            if status != 204:
                probe.errors.append(f"HTTP status {status}")
        self.report(probe, tracer)

    def run(self, provider: str, url: str | None) -> None:
        print(f"\n######## {provider} ########")
        if url is not None:
            self.probe_tcp(provider, url)
            self.probe_h3(provider, url, "h3")
            local = "socks5://" + url.split("://", 1)[1]
            self.probe_h3(provider, local, "h3-local")
        else:
            self.probe_h3(provider, None, "h3")
        self.probe_resume(provider, url)
        self.probe_google(provider, url)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--providers",
        default=",".join(PROVIDERS),
        help="comma separated subset of: " + ", ".join(PROVIDERS),
    )
    parser.add_argument("--direct", action="store_true", help="also probe directly")
    parser.add_argument("--trace-dir", default="traces", help="full traces go here")
    parser.add_argument("--timeout", type=float, default=20.0, help="per request")
    parser.add_argument("--json", metavar="FILE", help="also write results as JSON")
    parser.add_argument("--show-ips", action="store_true", help="print exit addresses")
    parser.add_argument(
        "--no-exit-ip-check",
        action="store_true",
        help="do not compare the exit address with this machine's (local proxies)",
    )
    args = parser.parse_args()
    names = [n.strip() for n in args.providers.split(",") if n.strip()]
    unknown = [n for n in names if n not in PROVIDERS]
    if unknown:
        parser.error(f"unknown provider(s): {', '.join(unknown)}")

    print(f"curl_cffi {curl_cffi.__version__}: {curl_cffi.__curl_version__}")
    traced = enable_curl_traces()
    print(f"curl traces ({TRACE_CONFIG}): {'on' if traced else 'NOT available'}")
    urls, problems = load_providers(names)
    for problem in problems:
        print(problem)
    if not urls and not args.direct:
        print("no provider configured")
        return 2
    diagnosis = Diagnosis(args, Redactor(list(urls.values())), traced)
    if not args.no_exit_ip_check:
        diagnosis.direct_ip = direct_ip(args.timeout)
    print(
        "this machine's address (direct, over TCP): "
        + ("found" if diagnosis.direct_ip else "not used, bypass check skipped")
    )
    if args.direct:
        diagnosis.run("direct", None)
    for name, url in urls.items():
        diagnosis.run(name, url)

    print("\n######## summary ########")
    for p in diagnosis.probes:
        print(
            f"{p.result}  {p.provider}/{p.name}"
            + (f": {p.errors[0]}" if p.errors else "")
        )
    if args.json:
        with open(args.json, "w") as f:
            json.dump([asdict(p) for p in diagnosis.probes], f, indent=2)
    return 1 if any(p.result == "FAIL" for p in diagnosis.probes) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        configured = [os.environ.get(var, "").strip() for var in PROVIDERS.values()]
        redact = Redactor([url for url in configured if url])
        print(redact(traceback.format_exc()), file=sys.stderr)
        sys.exit(3)
