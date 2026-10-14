"""Structural diff of QUIC/TLS fingerprint snapshots (see capture_*.py).

Compares a candidate snapshot with a reference one, typically a real Chrome
capture, field by field. Random values (GREASE code points, ECH payloads,
connection IDs, RTT estimates) are compared by presence and shape; sets,
counts and ordering behaviour must match exactly. Prints every check and
exits with status 1 if any required check fails.

usage: fingerprint_diff.py REFERENCE CANDIDATE [--optional CHECK ...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Transport parameters whose values are fixed by the browser build.
FIXED_TP = {1, 3, 4, 5, 6, 7, 8, 9, 32}
TP_INITIAL_RTT = 12583
EXT_PSK = 41
EXT_EARLY_DATA = 42
GREASE_ECH_PAYLOADS = {144, 176, 208, 240}


def is_grease_u16(v: int) -> bool:
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def is_grease_tp(v: int) -> bool:
    return v >= 27 and (v - 27) % 31 == 0


def norm_ext(v: int) -> int | str:
    return "GREASE" if is_grease_u16(v) else v


def norm_tp(v: int) -> int | str:
    return "GREASE" if v not in FIXED_TP and is_grease_tp(v) else v


def entry_data(snapshot: dict, key: str) -> dict:
    entry = snapshot.get(key) or {}
    if isinstance(entry, dict) and "data" in entry:
        return entry.get("data") or {}
    return entry


class Report:
    def __init__(self, optional: set[str]) -> None:
        self.optional = optional
        self.failed: list[str] = []

    def check(self, name: str, ok: bool, ref: object, cand: object) -> None:
        status = "PASS" if ok else ("WARN" if name in self.optional else "FAIL")
        if not ok and name not in self.optional:
            self.failed.append(name)
        print(f"{status}  {name}")
        if not ok:
            print(f"        reference: {ref}")
            print(f"        candidate: {cand}")


def ext_ids(snap: dict) -> list[int]:
    return [e["id"] for e in (snap.get("tls") or {}).get("extensions") or []]


def transport_params(snap: dict) -> list[dict]:
    for e in (snap.get("tls") or {}).get("extensions") or []:
        if e["id"] == 57:
            return (e.get("data") or {}).get("transport_parameters") or []
    return []


def ech_info(snap: dict) -> dict:
    for e in (snap.get("tls") or {}).get("extensions") or []:
        if e["id"] == 65037:
            return e.get("data") or {}
    return {}


def compare_quic(r: Report, label: str, ref: dict, cand: dict) -> None:
    p = f"{label}."
    rj, cj = ref.get("ja4"), cand.get("ja4")
    r.check(p + "ja4", rj == cj, rj, cj)
    r.check(
        p + "h3_hash",
        ref.get("h3_hash") == cand.get("h3_hash"),
        ref.get("h3_hash"),
        cand.get("h3_hash"),
    )
    r.check(
        p + "h3_text",
        ref.get("h3_text") == cand.get("h3_text"),
        ref.get("h3_text"),
        cand.get("h3_text"),
    )

    rq, cq = ref.get("quic") or {}, cand.get("quic") or {}
    for key in ("dcid_length", "scid_length", "0-rtt"):
        r.check(p + f"quic.{key}", rq.get(key) == cq.get(key), rq.get(key), cq.get(key))

    ri, ci = rq.get("initial_packets") or [], cq.get("initial_packets") or []
    r.check(p + "initial.count", len(ri) == len(ci), len(ri), len(ci))
    rl = [x.get("packet_length") for x in ri]
    cl = [x.get("packet_length") for x in ci]
    r.check(p + "initial.packet_length", rl == cl, rl, cl)
    rpn = ri[0].get("packet_number") if ri else None
    cpn = ci[0].get("packet_number") if ci else None
    r.check(p + "initial.first_packet_number", rpn == cpn, rpn, cpn)
    rt = [x.get("has_token") for x in ri]
    ct = [x.get("has_token") for x in ci]
    r.check(p + "initial.has_token", rt == ct, rt, ct)
    # CRYPTO split up with PING frames; PADDING only where the ClientHello
    # leaves room, which varies with the random ECH GREASE length and token.
    cf = sorted({f for x in ci for f in x.get("frames") or []})
    r.check(p + "initial.frame_types", {1, 6} <= set(cf) <= {0, 1, 6}, [0, 1, 6], cf)

    re_, ce = ext_ids(ref), ext_ids(cand)
    rs = sorted(map(str, map(norm_ext, re_)))
    cs = sorted(map(str, map(norm_ext, ce)))
    r.check(p + "tls.extension_set", rs == cs, rs, cs)
    body = [e for e in ce if e != EXT_PSK]
    r.check(
        p + "tls.extension_order_not_sorted",
        body != sorted(body),
        "permuted",
        ce,
    )
    if EXT_PSK in re_ or EXT_PSK in ce:
        r.check(
            p + "tls.psk_last",
            bool(ce) and ce[-1] == EXT_PSK and EXT_PSK in re_,
            re_,
            ce,
        )

    rech, cech = ech_info(ref), ech_info(cand)
    r_ok = (ref.get("tls") or {}).get("ech", {}).get("ech_success")
    c_ok = (cand.get("tls") or {}).get("ech", {}).get("ech_success")
    r.check(p + "tls.ech_success", r_ok == c_ok, r_ok, c_ok)
    if not c_ok:
        r.check(
            p + "tls.ech_grease_payload",
            cech.get("payload_length") in GREASE_ECH_PAYLOADS
            and rech.get("payload_length") in GREASE_ECH_PAYLOADS,
            rech.get("payload_length"),
            cech.get("payload_length"),
        )

    rtp, ctp = transport_params(ref), transport_params(cand)
    rids = sorted(map(str, (norm_tp(t["id"]) for t in rtp)))
    cids = sorted(map(str, (norm_tp(t["id"]) for t in ctp)))
    r.check(p + "tp.id_set", rids == cids, rids, cids)
    rv = {t["id"]: t.get("value") for t in rtp if t["id"] in FIXED_TP}
    cv = {t["id"]: t.get("value") for t in ctp if t["id"] in FIXED_TP}
    r.check(p + "tp.fixed_values", rv == cv, rv, cv)
    rrtt = [t.get("value") for t in rtp if t["id"] == TP_INITIAL_RTT]
    crtt = [t.get("value") for t in ctp if t["id"] == TP_INITIAL_RTT]
    r.check(
        p + "tp.initial_rtt",
        bool(rrtt) == bool(crtt)
        and all(isinstance(v, int) and 1000 <= v <= 5_000_000 for v in crtt),
        rrtt,
        crtt,
    )
    r.check(
        p + "tp.order_not_sorted",
        [t["id"] for t in ctp] != sorted(t["id"] for t in ctp),
        "permuted",
        [t["id"] for t in ctp],
    )

    rfr = [f.get("name") for f in ref.get("http3") or []]
    cfr = [f.get("name") for f in cand.get("http3") or []]
    r.check(p + "http3.frames", rfr == cfr, rfr, cfr)
    rpu = [
        f.get("raw") for f in ref.get("http3") or [] if f["name"] == "PRIORITY_UPDATE"
    ]
    cpu = [
        f.get("raw") for f in cand.get("http3") or [] if f["name"] == "PRIORITY_UPDATE"
    ]
    r.check(p + "http3.priority_update", rpu == cpu, rpu, cpu)


def compare_impersonate_pro(r: Report, label: str, ref: dict, cand: dict) -> None:
    """fp.impersonate.pro/api/http3, the curl_cffi maintainer's own check."""
    p = f"{label}."
    rq, cq = ref.get("quic") or {}, cand.get("quic") or {}
    r.check(p + "quic", rq == cq, rq, cq)
    rt, ct = ref.get("tls") or {}, cand.get("tls") or {}
    rj = (rt.get("ja3n") or {}).get("text")
    cj = (ct.get("ja3n") or {}).get("text")
    r.check(p + "ja3n", rj == cj, rj, cj)
    rs = sorted(map(str, (norm_ext(e["id"]) for e in rt.get("extensions") or [])))
    cs = sorted(map(str, (norm_ext(e["id"]) for e in ct.get("extensions") or [])))
    r.check(p + "tls.extension_set", rs == cs, rs, cs)
    rh, ch = ref.get("http3") or {}, cand.get("http3") or {}
    rp, cp = rh.get("perk_text_normalized"), ch.get("perk_text_normalized")
    r.check(p + "perk_text_normalized", rp == cp, rp, cp)
    ro, co = rh.get("header_order"), ch.get("header_order")
    r.check(p + "http3.header_order", ro == co, ro, co)


def compare_tcp(r: Report, ref: dict, cand: dict) -> None:
    rt, ct = ref.get("tls") or {}, cand.get("tls") or {}
    r.check("tcp.ja4", rt.get("ja4") == ct.get("ja4"), rt.get("ja4"), ct.get("ja4"))
    ra = (ref.get("http2") or {}).get("akamai_fingerprint_hash")
    ca = (cand.get("http2") or {}).get("akamai_fingerprint_hash")
    r.check("tcp.akamai_hash", ra == ca, ra, ca)
    r.check(
        "tcp.peetprint",
        rt.get("peetprint_hash") == ct.get("peetprint_hash"),
        rt.get("peetprint_hash"),
        ct.get("peetprint_hash"),
    )


def diff(ref: dict, cand: dict, optional: set[str] | None = None) -> Report:
    r = Report(optional or set())
    print(f"reference: {ref.get('label')} {ref.get('browser_version', '')}")
    print(f"candidate: {cand.get('label')} {cand.get('libcurl', '')}")
    for key in ("browserleaks_first", "browserleaks_resumed"):
        rd, cd = entry_data(ref, key), entry_data(cand, key)
        if not rd or not cd:
            r.check(key, False, bool(rd), bool(cd))
            continue
        compare_quic(r, key, rd, cd)
    for key in ("impersonate_h3", "impersonate_h3_resumed"):
        rd, cd = entry_data(ref, key), entry_data(cand, key)
        if rd.get("quic") and cd.get("quic"):
            compare_impersonate_pro(r, key, rd, cd)
        else:
            print(f"SKIP  {key} (no HTTP/3 snapshot)")
    first, resumed = (
        entry_data(cand, "browserleaks_first"),
        entry_data(cand, "browserleaks_resumed"),
    )
    if first and resumed:
        shared = [norm_ext(e) for e in ext_ids(first)]
        again = [
            norm_ext(e) for e in ext_ids(resumed) if e not in (EXT_PSK, EXT_EARLY_DATA)
        ]
        r.check(
            "tls.order_differs_between_connections",
            shared != again,
            "different",
            [shared, again],
        )
    rp, cp = entry_data(ref, "peet"), entry_data(cand, "peet")
    if rp and cp:
        compare_tcp(r, rp, cp)
    else:
        print("SKIP  tcp (no tls.peet.ws snapshot)")
    print(f"\n{len(r.failed)} failed check(s)" + (f": {r.failed}" if r.failed else ""))
    return r


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("reference")
    parser.add_argument("candidate")
    parser.add_argument(
        "--optional",
        action="append",
        default=[],
        help="check name to report as a warning instead of a failure",
    )
    args = parser.parse_args(argv)
    ref = json.loads(Path(args.reference).read_text())
    cand = json.loads(Path(args.candidate).read_text())
    return 1 if diff(ref, cand, set(args.optional)).failed else 0


if __name__ == "__main__":
    sys.exit(main())
