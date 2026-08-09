#!/usr/bin/env python3
"""scope_checker.py — deterministic scope safety gate.

Every outbound request in the pipeline MUST pass through this checker first.
Exits 0 (allowed) or 1 (blocked). Prints a machine-readable verdict line.

Scope file: ~/.config/vulnera-mcp/scope.yaml (also loaded from /home/bb/.config/vulnera-mcp/scope.yaml)
Supports: exact hosts, wildcards (*.example.com), full URLs, CIDRs, and
port-specific entries. All matching is case-insensitive.

Usage:
    python3 tools/scope_checker.py --check https://api.example.com/users
    python3 tools/scope_checker.py --check example.com --json
    python3 tools/scope_checker.py --list                     # show current scope
    python3 tools/scope_checker.py --add https://new.example.com --in_scope
    python3 tools/scope_checker.py --remove example.com

Exit codes:
    0 = IN SCOPE (allowed)
    1 = OUT OF SCOPE / BLOCKED (denied)
    2 = scope file missing / misconfigured (fail-closed!)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

SCOPE_PATHS = [
    Path.home() / ".config/vulnera-mcp/scope.yaml",
    Path("/home/bb/.config/vulnera-mcp/scope.yaml"),
    Path.cwd() / "config" / "scope.yaml",
    Path.cwd() / "scope.yaml",
]


def load_scope() -> dict:
    """Load scope.yaml from the first existing path. YAML subset parser (no deps)."""
    for p in SCOPE_PATHS:
        if p.exists():
            return parse_yaml_subset(p.read_text(errors="ignore"))
    return {}


def parse_yaml_subset(text: str) -> dict:
    """Minimal YAML list parser for scope.yaml structure:
       in_scope: [entries...] / out_of_scope: [entries...]
    Handles both inline lists and dash-lists. Fails safe (returns {}) on weird input."""
    result: dict = {"in_scope": [], "out_of_scope": []}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("in_scope"):
            current = "in_scope"
            if "[" in line:
                result["in_scope"] = extract_inline_list(line)
                current = None
            continue
        if line.startswith("out_of_scope"):
            current = "out_of_scope"
            if "[" in line:
                result["out_of_scope"] = extract_inline_list(line)
                current = None
            continue
        if current and line.startswith("-"):
            entry = line[1:].strip().strip('"').strip("'")
            # strip trailing inline comments (e.g. `- "*.example.com"  # note`)
            if " #" in entry:
                entry = entry.split(" #", 1)[0].strip().strip('"').strip("'")
            if entry:
                result[current].append(entry)
    return result


def extract_inline_list(line: str) -> list[str]:
    m = re.search(r"\[(.*)\]", line)
    if not m:
        return []
    return [x.strip().strip('"').strip("'") for x in m.group(1).split(",") if x.strip()]


def host_from_target(target: str) -> str:
    """Extract hostname from a URL or bare host, lowercased, no port."""
    if "://" in target:
        target = urlparse(target).netloc or target
    target = target.split("@")[-1]  # strip userinfo
    host = target.split(":")[0].strip("/").lower()
    return host


def match_entry(host: str, entry: str) -> bool:
    entry = entry.strip().lower()
    if not entry:
        return False

    # Full URL entry
    if "://" in entry:
        e_host = host_from_target(entry)
        return host == e_host

    # Wildcard *.example.com — matches example.com and all subdomains
    if entry.startswith("*."):
        base = entry[2:]
        return host == base or host.endswith("." + base)

    # Bare wildcard .example.com style
    if entry.startswith("."):
        base = entry[1:]
        return host == base or host.endswith("." + base)

    # CIDR block
    if "/" in entry:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False

    # Exact host or subdomain-of
    return host == entry or host.endswith("." + entry)


def verdict(target: str, scope: dict) -> tuple[bool, str]:
    """Return (allowed, reason).

    Precedence (safe by design):
      1. EXPLICIT in_scope match  → ALLOW   (specific host beats wildcard exclusions)
      2. out_of_scope match       → BLOCK
      3. not listed               → BLOCK (fail-closed default)
    """
    host = host_from_target(target)
    in_list = scope.get("in_scope", []) or []
    out_list = scope.get("out_of_scope", []) or []

    # 1. explicit in-scope entries win (they are the authoritative allowlist)
    for entry in in_list:
        if match_entry(host, entry):
            return True, f"in_scope match: {entry}"

    # 2. out-of-scope / wildcard exclusions block
    for entry in out_list:
        if match_entry(host, entry):
            return False, f"out_of_scope match: {entry}"

    # 3. default: NOT listed = NOT allowed (fail-closed)
    return False, "not listed in in_scope (fail-closed default)"


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic scope safety gate")
    ap.add_argument("--check", help="URL or host to check")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--list", action="store_true", help="list current scope")
    ap.add_argument("--add", help="add entry (use --in_scope/--out_of_scope)")
    ap.add_argument("--remove", help="remove entry")
    ap.add_argument("--in_scope", action="store_true")
    ap.add_argument("--out_of_scope", action="store_true")
    args = ap.parse_args()

    scope = load_scope()
    if not scope or not scope.get("in_scope"):
        print(json.dumps({"allowed": False, "reason": "scope file missing/empty — FAIL CLOSED"}))
        return 2

    if args.list:
        for k in ("in_scope", "out_of_scope"):
            print(f"{k}:")
            for e in scope.get(k, []):
                print(f"  - {e}")
        return 0

    if args.add:
        entry = args.add
        section = "in_scope" if args.in_scope else "out_of_scope"
        p = next((x for x in SCOPE_PATHS if x.exists()), None)
        if not p:
            print("ERROR: no scope file to modify", file=sys.stderr)
            return 2
        with open(p, "a") as f:
            f.write(f"  - \"{entry}\"\n")
        print(f"added {entry} to {section}")
        return 0

    if args.remove:
        p = next((x for x in SCOPE_PATHS if x.exists()), None)
        if not p:
            return 2
        lines = [l for l in p.read_text().splitlines(keepends=True) if args.remove not in l]
        p.write_text("".join(lines))
        print(f"removed {args.remove}")
        return 0

    if not args.check:
        ap.print_help()
        return 2

    allowed, reason = verdict(args.check, scope)
    if args.json:
        print(json.dumps({"target": args.check, "allowed": allowed, "reason": reason}))
    else:
        print(("ALLOWED" if allowed else "BLOCKED") + f"  [{reason}]")
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())