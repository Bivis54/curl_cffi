"""Capture QUIC/TLS fingerprint snapshots from a real Chrome build.

The snapshots are the ground truth that ``fingerprint_diff.py`` compares
curl_cffi against. Chrome learns HTTP/3 from Alt-Svc on the first (TCP) load,
so the page is loaded until a QUIC snapshot comes back; that is the first QUIC
connection. Chrome then closes the idle connection after its 30 s idle timeout
and the next load resumes the session (PSK, early data, address token).

usage: capture_chrome.py --chrome /path/to/chrome --out DIR [--label NAME]
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

BROWSERLEAKS = "https://quic.browserleaks.com/?minify=1"
IMPERSONATE_H3 = "https://fp.impersonate.pro/api/http3"
PEET = "https://tls.peet.ws/api/all"
BROWSERLEAKS_TLS = "https://tls.browserleaks.com/json"


def load_json(page, url: str, protocols: dict[str, str]) -> tuple[dict | None, str]:
    try:
        page.goto(url, wait_until="load", timeout=45_000)
        text = page.inner_text("body")
    except Exception as e:  # noqa: BLE001
        print(f"{url}: {e!r}"[:300])
        return None, "error"
    protocol = protocols.get(url, "")
    try:
        return json.loads(text), protocol
    except json.JSONDecodeError:
        return None, protocol


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", default="chrome")
    parser.add_argument("--idle", type=float, default=45.0)
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    result: dict[str, object] = {"label": args.label}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=args.chrome,
            headless=True,
            args=["--no-first-run", "--no-default-browser-check"],
        )
        result["browser_version"] = browser.version
        context = browser.new_context()
        page = context.new_page()
        protocols: dict[str, str] = {}
        cdp = context.new_cdp_session(page)
        cdp.send("Network.enable")
        cdp.on(
            "Network.responseReceived",
            lambda e: protocols.__setitem__(
                e["response"]["url"], e["response"].get("protocol", "")
            ),
        )

        tcp, proto = load_json(page, PEET, protocols)
        result["peet"] = {"protocol": proto, "data": tcp}
        tcp, proto = load_json(page, BROWSERLEAKS_TLS, protocols)
        result["browserleaks_tls"] = {"protocol": proto, "data": tcp}

        first = None
        attempts = []
        for _ in range(8):
            data, proto = load_json(page, BROWSERLEAKS, protocols)
            attempts.append(proto)
            if data and proto == "h3":
                first = data
                break
            time.sleep(1)
        result["browserleaks_attempts"] = attempts
        result["browserleaks_first"] = first

        h3, proto = load_json(page, IMPERSONATE_H3, protocols)
        result["impersonate_h3"] = {"protocol": proto, "data": h3}

        # Let both QUIC connections hit the idle timeout so the next load
        # resumes instead of reusing the open connection.
        page.goto("about:blank")
        time.sleep(args.idle)
        resumed, proto = load_json(page, BROWSERLEAKS, protocols)
        result["browserleaks_resumed"] = resumed
        result["browserleaks_resumed_protocol"] = proto

        time.sleep(args.idle)
        h3_resumed, proto = load_json(page, IMPERSONATE_H3, protocols)
        result["impersonate_h3_resumed"] = {"protocol": proto, "data": h3_resumed}

        browser.close()

    path = out / f"{args.label}.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True))
    print(f"wrote {path}")
    first_data = result["browserleaks_first"] or {}
    resumed_data = result["browserleaks_resumed"] or {}
    print("version:", result["browser_version"])
    print("attempts:", attempts)
    print("first ja4:", first_data.get("ja4"), "h3_hash:", first_data.get("h3_hash"))
    print("resumed ja4:", resumed_data.get("ja4"), "proto:", proto)


if __name__ == "__main__":
    main()
