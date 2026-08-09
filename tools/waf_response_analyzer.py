#!/usr/bin/env python3
"""waf_response_analyzer.py — detect WAF vendor from HTTP response + suggest bypass.

Usage:
    python3 tools/waf_response_analyzer.py --url https://target.com
    python3 tools/waf_response_analyzer.py --file response.txt

Detection via: headers, cookies, body signatures, status code patterns.
Outputs vendor + bypass strategy from a knowledge table.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf-chl", "cloudflare"],
     "Find origin IP (crt.sh/SecurityTrails/Shodan) → bypass via origin. Else use payload encoding (waf_encoder.py)."),
    ("AWS WAF", ["x-amzn-requestid", "awswaf", "x-amz-cf-id", "awselb"],
     "SQL: /**/ comment split. Oversized body (>8KB) bypasses inspection. Header mutation."),
    ("Imperva", ["x-iinfo", "incap_ses_", "visid_incap", "imperva"],
     "Unicode overlong %c0%2e, parameter pollution, chunked TE split."),
    ("F5 BIG-IP ASM", ["TS[0-9a-f]{6}", "x-wa-info", "bigip", "f5"],
     "Double-slash //admin, strip TS cookie, malformed content-length."),
    ("Akamai", ["akamai", "ak_bmsc", "bm_sz", "akavpau"],
     "Case randomization, comment injection, HTTP/1.0 downgrade."),
    ("Sucuri", ["sucuri", "x-sucuri-id", "sucuri_cloudproxy"],
     "Origin find, then standard encodings."),
    ("ModSecurity", ["mod_security", "modsecurity", "sec-fetch", "406"],
     "Comment stuffing /**/, newline splitting, case mix, parameter pollution."),
    ("Fastly", ["x-fastly", "fastly", "fastly-io"],
     "Vary header abuse, origin bypass via X-Forwarded-Host."),
    ("Wordfence", ["wordfence", "wfwaf"],
     "Query param pollution, multipart confusion, JSON body encoding."),
    ("Barracuda", ["barracuda", "x-barracuda"],
     "Null bytes, double encoding, oversized payloads."),
    ("Citrix", ["citrix", "ns_af", "x-citrix"],
     "Path confusion /, //, ;, URL encoding rounds."),
    ("Radware", ["radware", "x-pp-", "altsvc"],
     "Chunked requests, case variations, TLS fingerprint rotation."),
    ("Unknown", [], "Run wafw00f for full fingerprint, then use waf_encoder.py variants."),
]


def analyze(headers: str, body: str = "") -> list[tuple[str, str, str]]:
    hay = (headers + "\n" + body).lower()
    hits: list[tuple[str, str, str]] = []
    for vendor, sigs, advice in SIGNATURES:
        matched = [s for s in sigs if s.lower() in hay]
        if matched:
            hits.append((vendor, ",".join(matched), advice))
    return hits


def fetch(url: str) -> tuple[str, str]:
    try:
        res = subprocess.run(
            ["curl", "-s", "-D", "-", "-o", "/tmp/waf_body.txt", "-m", "15", url],
            capture_output=True, text=True, timeout=20)
        body = ""
        try:
            body = open("/tmp/waf_body.txt").read(20000)
        except OSError:
            pass
        return res.stdout, body
    except Exception as e:  # noqa: BLE001
        return "", str(e)


def main() -> int:
    ap = argparse.ArgumentParser(description="WAF vendor detection")
    ap.add_argument("--url", help="target URL")
    ap.add_argument("--file", help="file with raw HTTP response")
    args = ap.parse_args()

    if args.file:
        try:
            data = open(args.file).read(100000)
        except OSError as e:
            print(f"[-] {e}", file=sys.stderr)
            return 2
        headers, _, body = data.partition("\r\n\r\n")
        if not body:
            headers, _, body = data.partition("\n\n")
    elif args.url:
        headers, body = fetch(args.url)
    else:
        ap.print_help()
        return 2

    hits = analyze(headers, body)
    if not hits:
        print("[*] No known WAF signature detected. Run wafw00f for deeper fingerprinting.")
        return 0
    for vendor, sigs, advice in hits:
        print(f"[+] WAF: {vendor}")
        print(f"    signature: {sigs}")
        print(f"    bypass: {advice}")
    return 0


if __name__ == "__main__":
    sys.exit(main())