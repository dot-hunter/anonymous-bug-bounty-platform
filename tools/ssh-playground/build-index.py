#!/usr/bin/env python3
"""
build-index.py — build the key->username index used by playground.py.

The playground greets a connecting client by GitHub username. SSH clients
offer every public key in ~/.ssh and the agent; the playground just records
the offered *public* keys (never accepting any of them), then looks each
fingerprint up in this index.

This builder pulls the canonical, public mapping:
    github.com/<username>.keys  (no auth, no rate limit)

Usage:
  python3 build-index.py --users-file users.txt --out index.jsonl
  python3 build-index.py --org <org> --out index.jsonl          # all public members
  python3 build-index.py --search <term>                        # GitHub user search (API, limited)

Index format (JSONL): {"user": "octocat", "fp": "SHA256:base64..."} per line.
"""
import argparse
import base64
import hashlib
import json
import re
import sys
import time
import urllib.request
import urllib.error

KEY_RE = re.compile(r"^(ssh-(rsa|ed25519|dss)\s+[A-Za-z0-9+/=]+|ecdsa-sha2-[^\s]+\s+[A-Za-z0-9+/=]+|sk-(ssh-ed25519|ecdsa-sha2-)[^\s]*\s+[A-Za-z0-9+/=]+)\s*(.*)$")


def sha256_fingerprint(b64key: str) -> str | None:
    """Return 'SHA256:...' same as `ssh-keygen -lf`. Uses only the base64 body."""
    parts = b64key.split()
    if len(parts) < 2:
        return None
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception:
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def fetch_user_keys(user: str) -> list[str]:
    url = f"https://github.com/{user}.keys"
    req = urllib.request.Request(url, headers={"User-Agent": "ssh-playground/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "replace")
    except Exception:
        return []
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)", line):
            keys.append(line)
    return keys


def fetch_org_members(org: str, token: str = "") -> list[str]:
    members = []
    page = 1
    while True:
        url = f"https://api.github.com/orgs/{urllib.parse.quote(org)}/public_members?per_page=100&page={page}"
        req = urllib.request.Request(url, headers={"User-Agent": "ssh-playground/1.0"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
        except Exception:
            break
        if not isinstance(data, list) or not data:
            break
        members.extend(m["login"] for m in data if isinstance(m, dict))
        if len(data) < 100:
            break
        page += 1
    return members


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--users-file", help="one GitHub username per line")
    ap.add_argument("--org", help="org whose public members to index")
    ap.add_argument("--token", default="", help="GitHub token for org member list (optional)")
    ap.add_argument("--out", default="index.jsonl")
    args = ap.parse_args()

    users = []
    if args.users_file:
        with open(args.users_file) as f:
            users = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if args.org:
        print(f"[*] fetching public members of {args.org} ...")
        org_users = fetch_org_members(args.org, args.token)
        print(f"    {len(org_users)} members")
        users.extend(org_users)
    if not users:
        ap.error("provide --users-file and/or --org")

    n_keys = 0
    with open(args.out, "w") as out:
        for i, user in enumerate(users):
            keys = fetch_user_keys(user)
            for k in keys:
                fp = line_fingerprint(k)
                if fp:
                    out.write(json.dumps({"user": user, "fp": fp, "key": k}) + "\n")
                    n_keys += 1
            if (i + 1) % 10 == 0:
                print(f"    [{i+1}/{len(users)}] {n_keys} keys")
            time.sleep(0.05)  # be polite to github.com

    print(f"[+] done: {len(users)} users, {n_keys} keys -> {args.out}")


def line_fingerprint(line: str) -> str | None:
    m = KEY_RE.match(line)
    if not m:
        return None
    return sha256_fp(m.group(1))


def sha256_fp(b64key: str) -> str | None:
    parts = b64key.split()
    if len(parts) < 2:
        parts = (parts + [""] * 2)[:2]
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception:
        return None
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


if __name__ == "__main__":
    main()