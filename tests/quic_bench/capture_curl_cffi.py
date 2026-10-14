"""Capture the same snapshots as ``capture_chrome.py`` with curl_cffi.

QUIC endpoints are fetched twice with ``CURLOPT_FORBID_REUSE`` on one session:
the second request needs a new connection and resumes the TLS session of the
first one (PSK, early data and the server's address token when supported).

usage: capture_curl_cffi.py --out DIR [--label NAME] [--impersonate chrome]
                            [--proxy socks5h://user:pass@host:port]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", default="curl_cffi")
    parser.add_argument("--impersonate", default="chrome")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--http-version", default="v3only")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    kwargs = {"impersonate": args.impersonate}
    if args.proxy:
        kwargs["proxy"] = args.proxy
    result: dict[str, object] = {
        "label": args.label,
        "curl_cffi": curl_cffi.__version__,
        "libcurl": curl_cffi.__curl_version__,
    }
    with requests.Session() as s:
        result["peet"] = fetch(s, PEET, None, **kwargs)
        result["browserleaks_tls"] = fetch(s, BROWSERLEAKS_TLS, None, **kwargs)
    result["browserleaks_first"], result["browserleaks_resumed"] = fetch_pair(
        BROWSERLEAKS, args.http_version, **kwargs
    )
    result["impersonate_h3"], result["impersonate_h3_resumed"] = fetch_pair(
        IMPERSONATE_H3, args.http_version, **kwargs
    )

    path = out / f"{args.label}.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(f"wrote {path}")
    for key in ("browserleaks_first", "browserleaks_resumed"):
        entry = result[key]
        data = entry.get("data") or {}
        print(key, entry.get("http_version"), data.get("ja4"), data.get("h3_hash"))


if __name__ == "__main__":
    main()
