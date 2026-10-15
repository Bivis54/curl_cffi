"""Capture the same snapshots as ``capture_chrome.py`` with curl_cffi.

QUIC endpoints are fetched twice with ``CURLOPT_FORBID_REUSE`` on one session:
the second request needs a new connection and resumes the TLS session of the
first one (PSK, early data and the server's address token when supported).

usage: capture_curl_cffi.py --out DIR [--label NAME] [--impersonate chrome]
                            [--proxy socks5h://user:pass@host:port | --proxy-env VAR]

--proxy-env reads the proxy URL from an environment variable, which keeps it
out of the process list. Errors in the snapshot never contain the proxy URL,
credentials or host, and the client address the services saw is replaced by
<hidden> unless --show-ips is given.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

import curl_cffi
from curl_cffi import CurlOpt, requests

BROWSERLEAKS = "https://quic.browserleaks.com/?minify=1"
IMPERSONATE_H3 = "https://fp.impersonate.pro/api/http3"
PEET = "https://tls.peet.ws/api/all"
BROWSERLEAKS_TLS = "https://tls.browserleaks.com/json"


def fetch(session, url: str, http_version: str | None, **kwargs):
    started = time.monotonic()
    try:
        r = session.get(url, http_version=http_version, timeout=30, **kwargs)
    except Exception as e:  # noqa: BLE001
        return {"error": repr(e)[:300], "elapsed": time.monotonic() - started}
    entry: dict[str, object] = {
        "status": r.status_code,
        "http_version": r.http_version,
        "elapsed": time.monotonic() - started,
    }
    try:
        entry["data"] = r.json()
    except ValueError:
        entry["text"] = r.text[:300]
    return entry


def fetch_pair(url: str, http_version: str, **kwargs) -> tuple[dict, dict]:
    with requests.Session(curl_options={CurlOpt.FORBID_REUSE: 1}) as s:
        first = fetch(s, url, http_version, **kwargs)
        resumed = fetch(s, url, http_version, **kwargs)
    return first, resumed


def scrub(text: str, proxy: str | None) -> str:
    if not proxy:
        return text
    parts = urlsplit(proxy)
    secrets = {proxy, parts.netloc, parts.hostname, parts.username, parts.password}
    secrets |= {unquote(s) for s in secrets if s}
    for secret in sorted((s for s in secrets if s and len(s) >= 3), key=len)[::-1]:
        text = text.replace(secret, "<hidden>")
    return text


ADDRESS_KEYS = {"ip", "src_ip", "client_ip", "remote_addr", "x_forwarded_for"}


def hide_addresses(value: object) -> object:
    """The client (exit) address as the services saw it."""
    if isinstance(value, dict):
        return {
            k: "<hidden>" if k in ADDRESS_KEYS else hide_addresses(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [hide_addresses(v) for v in value]
    return value


def capture(
    label: str = "curl_cffi",
    impersonate: str = "chrome",
    proxy: str | None = None,
    http_version: str = "v3only",
) -> dict[str, object]:
    kwargs = {"impersonate": impersonate}
    if proxy:
        kwargs["proxy"] = proxy
    result: dict[str, object] = {
        "label": label,
        "curl_cffi": curl_cffi.__version__,
        "libcurl": curl_cffi.__curl_version__,
    }
    with requests.Session() as s:
        result["peet"] = fetch(s, PEET, None, **kwargs)
        result["browserleaks_tls"] = fetch(s, BROWSERLEAKS_TLS, None, **kwargs)
    result["browserleaks_first"], result["browserleaks_resumed"] = fetch_pair(
        BROWSERLEAKS, http_version, **kwargs
    )
    result["impersonate_h3"], result["impersonate_h3_resumed"] = fetch_pair(
        IMPERSONATE_H3, http_version, **kwargs
    )
    for entry in result.values():
        if isinstance(entry, dict) and "error" in entry:
            entry["error"] = scrub(str(entry["error"]), proxy)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", default="curl_cffi")
    parser.add_argument("--impersonate", default="chrome")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--proxy-env", metavar="VAR", default=None)
    parser.add_argument("--http-version", default="v3only")
    parser.add_argument("--show-ips", action="store_true", help="keep exit addresses")
    args = parser.parse_args()
    proxy = os.environ.get(args.proxy_env, "").strip() if args.proxy_env else None
    if args.proxy_env and not proxy:
        parser.error(f"{args.proxy_env} is not set")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    result = capture(
        args.label, args.impersonate, proxy or args.proxy, args.http_version
    )

    if not args.show_ips:
        result = hide_addresses(result)
    path = out / f"{args.label}.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(f"wrote {path}")
    for key, entry in result.items():
        if not isinstance(entry, dict):
            continue
        if "error" in entry:
            print(f"{key}: error {entry['error']}")
            continue
        data = entry.get("data") or {}
        print(
            f"{key}: status {entry.get('status')}, http_version "
            f"{entry.get('http_version')}, ja4 {data.get('ja4', '-')}, "
            f"h3_hash {data.get('h3_hash', '-')}"
        )


if __name__ == "__main__":
    main()
