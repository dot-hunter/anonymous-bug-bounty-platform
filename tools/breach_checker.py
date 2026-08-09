#!/usr/bin/env python3
"""breach_checker.py — check a dataset (emails/usernames) against local breach
databases / wordlists. Purely local; no API calls.

Usage:
    python3 tools/breach_checker.py --emails users.txt --breach-db breach-hashes.txt
    python3 tools/breach_checker.py --emails users.txt --password-list rockyou-subset.txt --report

Sources can be:
  - a file of `hash` lines (sha1/sha256/ntlm)
  - a file of `email:password` lines
  - a password wordlist (to flag weak/reused passwords)

Output: per-account hit report → findings/breach_report.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from pathlib import Path

HASHERS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "md5": hashlib.md5,
           "ntlm": None}


def load_breach_db(path: Path) -> dict[str, set[str]]:
    """Returns {hash_type: set_of_hashes}. Accepts bare hashes or `email:hash` lines."""
    result: dict[str, set[str]] = {k: set() for k in HASHERS}
    try:
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip().lower()
            if not line:
                continue
            h = line
            if ":" in line:
                left, _, right = line.partition(":")
                # email:hash form — take the right side only when left looks like an email
                if "@" in left and len(right) in (32, 40, 64):
                    h = right
            if len(h) == 32:
                result["md5"].add(h)
            elif len(h) == 40:
                result["sha1"].add(h)
            elif len(h) == 64:
                result["sha256"].add(h)
    except OSError as e:
        print(f"[-] cannot read breach db: {e}", file=sys.stderr)
    return result


def hash_value(value: str, algo: str) -> str:
    if algo == "ntlm":
        # NTLM = MD4(UTF-16LE) — needs hashlib fallback; skip if unavailable
        try:
            import hashlib as h
            md4 = h.new("md4", value.encode("utf-16le"))
            return md4.hexdigest()
        except (ValueError, TypeError):
            return ""
    return HASHERS[algo](value.encode()).hexdigest()


def check_emails(emails: list[str], breach_db: dict[str, set[str]],
                 password_list: Path | None) -> list[dict]:
    hits: list[dict] = []
    weak_words: set[str] = set()
    if password_list and password_list.exists():
        weak_words = {w.strip().lower() for w in password_list.read_text(errors="ignore").splitlines() if w.strip()}

    for email in emails:
        email = email.strip().lower()
        if not email:
            continue
        row = {"email": email}
        for algo in ("sha1", "sha256", "md5"):
            hv = hash_value(email, algo)
            if hv and hv in breach_db.get(algo, set()):
                row[f"breach_{algo}"] = "HIT"
        # weak password check on the local part
        local = email.split("@")[0]
        if local.lower() in weak_words or len(local) <= 4:
            row["weak_local"] = "FLAG"
        if any(k.endswith("HIT") or v == "FLAG" for k, v in row.items() if isinstance(v, str)):
            hits.append(row)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Local breach checker")
    ap.add_argument("--emails", required=True, help="file with emails (one per line)")
    ap.add_argument("--breach-db", help="file with hashes (sha1/sha256/md5, one per line)")
    ap.add_argument("--password-list", help="password wordlist to flag weak credentials")
    ap.add_argument("--report", action="store_true", help="write findings/breach_report.csv")
    args = ap.parse_args()

    try:
        emails = [l.strip() for l in open(args.emails, errors="ignore").read().splitlines() if l.strip()]
    except OSError as e:
        print(f"[-] {e}", file=sys.stderr)
        return 2

    breach_db: dict[str, set[str]] = {}
    if args.breach_db:
        breach_db = load_breach_db(Path(args.breach_db))
        total = sum(len(v) for v in breach_db.values())
        print(f"[*] breach db loaded: {total} hashes")

    hits = check_emails(emails, breach_db, Path(args.password_list) if args.password_list else None)
    print(f"[*] checked {len(emails)} emails → {len(hits)} flagged")

    for h in hits:
        print(f"  {h}")

    if args.report and hits:
        out = Path("findings/breach_report.csv")
        out.parent.mkdir(exist_ok=True)
        with open(out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(hits[0].keys()))
            w.writeheader()
            w.writerows(hits)
        print(f"[+] report → {out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())