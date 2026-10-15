#!/usr/bin/env python3
"""HTTP/3 through real SOCKS5 proxies with UDP ASSOCIATE.

Reads the proxy URLs from PROXYSHARD_SOCKS5_URL and SOAX_SOCKS5_URL
(socks5h://user:pass@host:port) and never prints them: error messages are
scrubbed of the URL, the credentials and the proxy host. Needs only an
installed curl_cffi wheel of this fork. For every configured provider:

- matrix: socks5h:// and socks5:// with http_version v3only and v3 against
  Cloudflare's trace endpoint, which reports the protocol it received
  (http=http/3) and the exit address;
- sequential: rounds over different hosts, every request on a new QUIC
  connection and so a new UDP association; later requests to a host resume
  the TLS session with 0-RTT;
- concurrent: all hosts at once, several requests each;
- fingerprint: JA4 and HTTP/3 fingerprint of a fresh and a resumed connection
  on quic.browserleaks.com, compared with Chrome 152.

A request passes when it completed over HTTP/3; the Cloudflare checks also
need Cloudflare to have seen HTTP/3 from an address other than this
machine's. --direct adds the same requests without a proxy as a baseline.
Exit status: 0 when nothing failed, 1 when a check failed, 2 when no
provider is configured, 3 when the script itself failed.

usage: test_real_proxies.py [--providers NAME,...] [--rounds N]
                            [--concurrency N] [--timeout SECONDS]
                            [--json FILE] [--show-ips] [--no-exit-ip-check]
                            [--direct]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import sys
import time
import traceback
from dataclasses import asdict, dataclass, field
from urllib.parse import unquote, urlsplit

import curl_cffi
from curl_cffi import CurlOpt, requests
from curl_cffi.requests import AsyncSession

PROVIDERS = {"proxyshard": "PROXYSHARD_SOCKS5_URL", "soax": "SOAX_SOCKS5_URL"}
DIRECT = "direct"  # --direct: the same requests without a proxy
TARGETS = {
    "cloudflare": "https://cloudflare-quic.com/cdn-cgi/trace",
    "google": "https://www.google.com/generate_204",
    "browserleaks": "https://quic.browserleaks.com/?minify=1",
    "impersonate.pro": "https://fp.impersonate.pro/api/http3",
}
CHROME_JA4 = {
    "fresh": "q13d0312h3_55b375c5d22e_178839b6cec1",
    "resumed": "q13d0314h3_55b375c5d22e_79cc91d6b50c",
}
CHROME_H3_HASH = "ba909fc3dc419ea5c5b26c6323ac1879"
HTTP3 = 30  # CURLINFO_HTTP_VERSION of HTTP/3
PROTOCOLS = {1: "h1.0", 2: "h1.1", 3: "h2", HTTP3: "h3"}


@dataclass
class Check:
    provider: str
    test: str
    target: str
    result: str = "FAIL"  # PASS, WARN or FAIL
    protocol: str = "-"
    status: str = "-"
    seconds: float = 0.0
    details: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Redactor:
    """Replaces the proxy URLs, their credentials and hosts in text."""

    def __init__(self, urls: list[str]) -> None:
        secrets = set()
        for url in urls:
            secrets.add(url)
            parts = urlsplit(url)
            for value in (parts.netloc, parts.username, parts.password):
                if value:
                    secrets.update((value, unquote(value)))
            if parts.hostname:
                secrets.add(parts.hostname)
        self.secrets = sorted((s for s in secrets if len(s) >= 3), key=len)[::-1]

    def __call__(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "<hidden>")
        return text


class Runner:
    def __init__(self, args: argparse.Namespace, redact: Redactor) -> None:
        self.args = args
        self.redact = redact
        self.direct_ip: str | None = None
        self.checks: list[Check] = []

    def record(self, check: Check) -> None:
        check.errors = [self.redact(e) for e in check.errors]
        check.details = [self.redact(d) for d in check.details]
        if check.errors:
            check.result = "FAIL"
        self.checks.append(check)
        print({"PASS": ".", "WARN": "W"}.get(check.result, "F"), end="", flush=True)

    def evaluate(self, check: Check, response) -> dict:
        """Check the protocol and status; returns the parsed JSON, if any."""
        check.protocol = PROTOCOLS.get(
            response.http_version, str(response.http_version)
        )
        check.status = str(response.status_code)
        check.result = "PASS"
        if response.http_version != HTTP3:
            check.errors.append(f"completed over {check.protocol}, not HTTP/3")
        if response.status_code >= 400:
            check.errors.append(f"HTTP status {response.status_code}")
        if check.target == "cloudflare":
            fields = dict(
                line.split("=", 1) for line in response.text.splitlines() if "=" in line
            )
            seen = fields.get("http", "?")
            if seen != "http/3":
                check.errors.append(f"Cloudflare received {seen}")
            ip = fields.get("ip", "?")
            if check.provider != DIRECT and self.direct_ip and ip == self.direct_ip:
                check.errors.append("exit address is this machine's: proxy bypassed")
            exit_at = fields.get("loc", "?") + (f" {ip}" if self.args.show_ips else "")
            check.details.append(f"Cloudflare saw {seen} from {exit_at}")
        data = {}
        if check.target == "browserleaks":
            try:
                data = response.json()
            except ValueError:
                check.errors.append("no JSON from quic.browserleaks.com")
            check.details.append(f"JA4 {str(data.get('ja4'))[:10]}")
            if (data.get("quic") or {}).get("0-rtt"):
                check.details.append("0-RTT")
        return data

    def request(self, session, check: Check, url: str | None, **kwargs):
        """GET the target of `check`; records failures, returns the response."""
        started = time.monotonic()
        try:
            return session.get(
                TARGETS[check.target],
                impersonate="chrome",
                proxy=url,
                timeout=self.args.timeout,
                **kwargs,
            )
        except Exception as e:  # noqa: BLE001
            check.errors.append(str(e))
            return None
        finally:
            check.seconds = time.monotonic() - started

    def matrix(self, provider: str, url: str | None) -> None:
        if url is None:
            return
        rest = url.split("://", 1)[1]
        for scheme in ("socks5h", "socks5"):
            for version in ("v3only", "v3"):
                options = {CurlOpt.FORBID_REUSE: 1}
                if version == "v3":
                    # v3 races TCP after 100 ms without QUIC data, which is
                    # always the case behind a remote proxy; a lost UDP packet
                    # would let TCP win. A longer race tests the UDP path.
                    options[CurlOpt.HAPPY_EYEBALLS_TIMEOUT_MS] = 5000
                check = Check(provider, f"matrix {scheme} {version}", "cloudflare")
                with requests.Session(trust_env=False, curl_options=options) as s:
                    r = self.request(
                        s, check, f"{scheme}://{rest}", http_version=version
                    )
                if r is not None:
                    self.evaluate(check, r)
                self.record(check)

    def sequential(self, provider: str, url: str | None) -> None:
        options = {CurlOpt.FORBID_REUSE: 1}
        with requests.Session(trust_env=False, curl_options=options) as s:
            for n in range(1, self.args.rounds + 1):
                for target in TARGETS:
                    check = Check(provider, f"sequential {n}", target)
                    r = self.request(s, check, url, http_version="v3only")
                    if r is not None:
                        self.evaluate(check, r)
                    self.record(check)

    def concurrent(self, provider: str, url: str | None) -> None:
        async def one(session: AsyncSession, target: str, n: int) -> None:
            check = Check(provider, f"concurrent {n}", target)
            started = time.monotonic()
            try:
                r = await session.get(
                    TARGETS[target],
                    impersonate="chrome",
                    http_version="v3only",
                    proxy=url,
                    timeout=self.args.timeout,
                )
            except Exception as e:  # noqa: BLE001
                check.errors.append(str(e))
            else:
                self.evaluate(check, r)
            check.seconds = time.monotonic() - started
            self.record(check)

        async def run() -> None:
            async with AsyncSession(
                trust_env=False,
                max_clients=64,
                curl_options={CurlOpt.FORBID_REUSE: 1},
            ) as session:
                await asyncio.gather(
                    *(
                        one(session, target, n)
                        for n in range(1, self.args.concurrency + 1)
                        for target in TARGETS
                    )
                )

        asyncio.run(run())

    def fingerprint(self, provider: str, url: str | None) -> None:
        options = {CurlOpt.FORBID_REUSE: 1}
        with requests.Session(trust_env=False, curl_options=options) as s:
            for kind in ("fresh", "resumed"):
                check = Check(provider, f"fingerprint {kind}", "browserleaks")
                r = self.request(s, check, url, http_version="v3only")
                if r is None:
                    self.record(check)
                    continue
                data = self.evaluate(check, r)
                check.details.clear()
                ja4 = data.get("ja4")
                if ja4 == CHROME_JA4[kind]:
                    check.details.append("JA4 = Chrome")
                else:
                    check.errors.append(f"JA4 {ja4}, Chrome {CHROME_JA4[kind]}")
                if data.get("h3_hash") == CHROME_H3_HASH:
                    check.details.append("HTTP/3 hash = Chrome")
                elif not check.errors:
                    # browserleaks reads the HTTP/3 streams concurrently and
                    # now and then reports a request before the control frames.
                    check.result = "WARN"
                    check.details.append(
                        f"HTTP/3 {data.get('h3_text')} (re-run; see FINDINGS)"
                    )
                if kind == "resumed" and not (data.get("quic") or {}).get("0-rtt"):
                    check.errors.append("no 0-RTT on resumption")
                self.record(check)

    def provider(self, name: str, url: str | None) -> None:
        print(f"{name}: ", end="", flush=True)
        for step in (self.matrix, self.sequential, self.concurrent, self.fingerprint):
            step(name, url)
            print(" ", end="", flush=True)
        print()


def load_providers(names: list[str]) -> tuple[dict[str, str], list[str]]:
    urls, problems = {}, []
    for name in names:
        var = PROVIDERS[name]
        url = os.environ.get(var, "").strip()
        if not url:
            problems.append(f"{name}: {var} is not set, skipped")
            continue
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            problems.append(f"{name}: {var} is not a valid URL, skipped")
            continue
        if parts.scheme not in ("socks5h", "socks5") or not parts.hostname or not port:
            problems.append(
                f"{name}: {var} must look like socks5h://user:pass@host:port, skipped"
            )
            continue
        urls[name] = url
    return urls, problems


def direct_ip(timeout: float) -> str | None:
    try:
        with requests.Session(trust_env=False) as s:
            text = s.get(
                TARGETS["cloudflare"], impersonate="chrome", timeout=timeout
            ).text
    except Exception:  # noqa: BLE001
        return None
    for line in text.splitlines():
        if line.startswith("ip="):
            return line[3:]
    return None


def print_table(checks: list[Check]) -> None:
    header = (
        "provider",
        "test",
        "target",
        "result",
        "proto",
        "status",
        "time",
        "details",
    )
    rows = [
        (
            c.provider,
            c.test,
            c.target,
            c.result,
            c.protocol,
            c.status,
            f"{c.seconds:.1f}s",
            "; ".join(c.details + (["see errors below"] if c.errors else [])),
        )
        for c in checks
    ]
    # The last column (details) is not padded.
    widths = [max(len(r[i]) for r in [header, *rows]) for i in range(len(header) - 1)]
    for row in [header, tuple("-" * w for w in widths) + ("-" * 7,), *rows]:
        cells = [
            cell.ljust(width) for cell, width in zip(row[:-1], widths, strict=True)
        ]
        print("  ".join([*cells, row[-1]]).rstrip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--providers",
        default=",".join(PROVIDERS),
        help="comma separated subset of: " + ", ".join(PROVIDERS),
    )
    parser.add_argument("--rounds", type=int, default=3, help="sequential rounds")
    parser.add_argument(
        "--concurrency", type=int, default=2, help="concurrent requests per host"
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="per request")
    parser.add_argument("--json", metavar="FILE", help="also write results as JSON")
    parser.add_argument(
        "--show-ips", action="store_true", help="print exit addresses (hidden)"
    )
    parser.add_argument(
        "--no-exit-ip-check",
        action="store_true",
        help="do not compare the exit address with this machine's (for local proxies)",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="also run the requests without a proxy, as a baseline (needs UDP egress)",
    )
    args = parser.parse_args()
    names = [n.strip() for n in args.providers.split(",") if n.strip()]
    unknown = [n for n in names if n not in PROVIDERS]
    if unknown:
        parser.error(f"unknown provider(s): {', '.join(unknown)}")

    tokens = curl_cffi.__curl_version__.split()
    impersonate = next((t for t in tokens if t.startswith("curl-impersonate/")), "?")
    print(
        f"curl_cffi {curl_cffi.__version__}, {tokens[0]}, {impersonate}, "
        f"Python {platform.python_version()}, {platform.system()} {platform.machine()}"
    )
    if "-bivis" not in impersonate:
        print("warning: not this fork's build; SOCKS5 UDP fixes may be missing")

    urls, problems = load_providers(names)
    for problem in problems:
        print(problem)
    if not urls and not args.direct:
        print("no provider configured")
        return 2
    runner = Runner(args, Redactor(list(urls.values())))
    runs: dict[str, str | None] = {DIRECT: None} if args.direct else {}
    runs.update(urls)
    if not args.no_exit_ip_check:
        runner.direct_ip = direct_ip(args.timeout)
        if runner.direct_ip:
            ip = runner.direct_ip if args.show_ips else "hidden"
            print(f"this machine's address: {ip} (a proxied exit must differ)")
        else:
            print("this machine's address is unknown: proxy bypass check skipped")
    print("progress: . pass, W warning, F failure")
    try:
        for name, url in runs.items():
            runner.provider(name, url)
    except KeyboardInterrupt:
        print("\ninterrupted, partial results:")

    print()
    print_table(runner.checks)
    print()
    for name in runs:
        own = [c for c in runner.checks if c.provider == name]
        counts = {r: sum(c.result == r for c in own) for r in ("PASS", "WARN", "FAIL")}
        print(
            f"{name}: {counts['PASS']}/{len(own)} passed, "
            f"{counts['WARN']} warnings, {counts['FAIL']} failed"
        )
        per_target = []
        for target in TARGETS:
            rows = [c for c in own if c.target == target]
            if rows:
                ok = sum(c.result != "FAIL" for c in rows)
                per_target.append(f"{target} {ok}/{len(rows)}")
        print("    by host: " + ", ".join(per_target))
    failed = [c for c in runner.checks if c.errors]
    if failed:
        print("\nerrors:")
        for n, c in enumerate(failed, 1):
            print(
                f"{n:3}. {c.provider} / {c.test} / {c.target}: {' | '.join(c.errors)}"
            )
    if args.json:
        with open(args.json, "w") as f:
            json.dump({"checks": [asdict(c) for c in runner.checks]}, f, indent=2)
    return 1 if any(c.result == "FAIL" for c in runner.checks) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        configured = [os.environ.get(var, "").strip() for var in PROVIDERS.values()]
        redact = Redactor([url for url in configured if url])
        print(redact(traceback.format_exc()), file=sys.stderr)
        sys.exit(3)
