#!/usr/bin/env python3
"""token_scanner.py — scan files/repos/JS for leaked secrets.

Usage:
    python3 tools/token_scanner.py --path /path/to/repo
    python3 tools/token_scanner.py --path ./js/bundle.js
    python3 tools/token_scanner.py --path . --ext js,json,env,py,sh,go --entropy 4.5

Detects (by regex + entropy):
  AWS keys, Google API keys, GitHub tokens, Slack tokens, Stripe keys,
  JWT, private keys (RSA/EC/OPENSSH), Azure, GCP, Twilio, SendGrid,
  Mailgun, npm token, PyPI token, generic high-entropy hex/base64 secrets,
  connection strings (mongodb://, postgres://, mysql://, redis://).
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

RULES: list[tuple[str, str]] = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret", r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{36,255}"),
    ("GitHub Fine-grained", r"github_pat_[0-9A-Za-z_]{22,}"),
    ("GitLab PAT", r"glpat-[0-9A-Za-z\-_]{20,}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"),
    ("Stripe Secret", r"sk_live_[0-9A-Za-z]{24,}"),
    ("Stripe Publishable", r"pk_live_[0-9A-Za-z]{24,}"),
    ("Square Token", r"sq0atp-[0-9A-Za-z\-_]{22,}"),
    ("PayPal Braintree", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Twilio", r"SK[0-9a-fA-F]{32}"),
    ("SendGrid", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Mailgun", r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp", r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("Heroku", r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("npm Token", r"npm_[0-9A-Za-z]{36}"),
    ("PyPI Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"),
    ("Azure Storage", r"AccountKey=[0-9a-zA-Z+/]{86}==?"),
    ("Azure AppInsights", r"InstrumentationKey=[0-9a-f\-]{36}"),
    ("GCP Service Acct", r"\"type\":\s*\"service_account\""),
    ("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("JWT", r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----"),
    ("OpenSSH Private", r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("PGP Private", r"-----BEGIN PGP PRIVATE KEY-----"),
    ("Mongo URI", r"mongodb(\+srv)?://[^\s'\"]+"),
    ("Postgres URI", r"postgres(ql)?://[^\s'\"]+"),
    ("MySQL URI", r"mysql://[^\s'\"]+"),
    ("Redis URI", r"redis://[^\s'\"]+"),
    ("S3 Bucket URL", r"s3://[a-z0-9.\-]{3,63}/[^\s'\"]*"),
    ("Generic Secret", r"(?i)(secret|token|password|passwd|api[_-]?key|client[_-]?secret|private[_-]?key)\s*[=:]\s*['\"][^'\"]{12,}['\"]"),
]

EXTS = {".js", ".json", ".env", ".py", ".sh", ".go", ".rb", ".php", ".yml", ".yaml",
        ".toml", ".ini", ".conf", ".xml", ".ts", ".jsx", ".tsx", ".vue", ".properties"}


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    p, lns = Counter(data), float(len(data))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())


def scan_file(path: Path, entropy_threshold: float) -> list[dict]:
    findings: list[dict] = []
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return findings

    for name, pattern in RULES:
        for m in re.finditer(pattern, text):
            match = m.group(0)
            findings.append({"rule": name, "match": match[:80], "line": text[:m.start()].count("\n") + 1})

    # high-entropy scan on token-like values (avoid noise: only quoted strings >= 20 chars)
    if entropy_threshold > 0:
        for m in re.finditer(r"['\"]([A-Za-z0-9_\-+/=]{20,})['\"]", text):
            val = m.group(1)
            ent = shannon_entropy(val)
            if ent >= entropy_threshold and not any(
                name in val.lower() for name in ("example", "your_", "sample", "changeme")
            ):
                findings.append({"rule": f"high-entropy ({ent:.2f})", "match": val[:80],
                                 "line": text[:m.start()].count("\n") + 1})
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Secret scanner")
    ap.add_argument("--path", required=True, help="file or directory to scan")
    ap.add_argument("--ext", default="", help="comma-separated extensions (default: common)")
    ap.add_argument("--entropy", type=float, default=4.5, help="entropy threshold (0=off)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.path)
    if not root.exists():
        print(f"[-] no such path: {root}", file=sys.stderr)
        return 2

    exts = {f".{e.strip().lstrip('.')}" for e in args.ext.split(",") if e.strip()} or EXTS
    files = [root] if root.is_file() else [
        p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts
        and not any(part.startswith(".") for part in p.parts)
        and "node_modules" not in p.parts and ".git" not in p.parts
    ]

    total: list[dict] = []
    for f in files:
        total.extend({"file": str(f), **r} for r in scan_file(f, args.entropy))

    if args.json:
        import json
        print(json.dumps(total, indent=2))
    else:
        print(f"[*] scanned {len(files)} files → {len(total)} potential secrets")
        for r in total[:80]:
            print(f"  {r['file']}:{r['line']}  [{r['rule']}] {r['match']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())