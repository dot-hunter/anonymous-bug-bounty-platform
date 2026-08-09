#!/usr/bin/env python3
"""dashboard.py — real-time phase dashboard for recon/hunt runs.

Usage:
    python3 tools/dashboard.py --tail --kind scan --target target.com
    python3 tools/dashboard.py --tail --kind recon --target target.com
    python3 tools/dashboard.py --show --kind scan --target target.com   # snapshot
    python3 tools/dashboard.py --watch --dir findings/target.com        # any dir
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

FINDINGS = Path("findings")
RECON = Path("recon")


def phase_for(kind: str, target: str) -> list[str]:
    if kind == "recon":
        return ["subdomain enumeration", "DNS resolution", "HTTP probing",
                "URL harvesting", "param extraction", "tech fingerprint"]
    return ["scope check", "recon load", "XSS pipeline", "SQLi verifier",
            "SSTI canary", "race check", "RCE probe", "MFA/SAML check", "summary"]


def render(target: str, kind: str) -> None:
    # infer progress from output artifacts
    recon_dir = RECON / target
    find_dir = FINDINGS / target
    progress: list[tuple[str, bool]] = []
    if kind == "recon":
        checks = [("subs.txt", "subdomain enumeration"), ("resolved.txt", "DNS resolution"),
                  ("live.txt", "HTTP probing"), ("urls.txt", "URL harvesting"),
                  ("params.txt", "param extraction"), ("tech.txt", "tech fingerprint")]
        for fname, label in checks:
            progress.append((label, (recon_dir / fname).exists()))
    else:
        # scan: infer from summary artifacts + stderr log
        if (find_dir / "summary.txt").exists():
            progress = [(l, True) for l in phase_for("scan", target)]
        else:
            stderr = find_dir / "scan_stderr.txt"
            done = 0
            if stderr.exists():
                done = sum(1 for _ in stderr.read_text(errors="ignore").splitlines())
            phases = phase_for("scan", target)
            progress = [(p, i < done) for i, p in enumerate(phases)]

    print(f"┌─ DASHBOARD: {target} [{kind}] " + "─" * max(0, 40 - len(target) - len(kind)))
    n = len(progress)
    done_n = sum(1 for _, d in progress if d)
    pct = int(done_n / n * 100) if n else 0
    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
    print(f"│ {bar} {pct:3d}%")
    for label, done in progress:
        mark = "✓" if done else "…"
        print(f"│  {mark} {label}")
    print("└" + "─" * 48)


def watch_dir(path: Path) -> None:
    seen: set[str] = set()
    try:
        while True:
            files = sorted(str(p) for p in path.rglob("*") if p.is_file())
            new = [f for f in files if f not in seen]
            for f in new:
                print(f"[new] {f}")
                try:
                    tail = Path(f).read_text(errors="ignore")[-300:]
                    print(tail)
                except OSError:
                    pass
            seen.update(files)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[.] dashboard stopped")


def main() -> int:
    ap = argparse.ArgumentParser(description="Hunt/recon progress dashboard")
    ap.add_argument("--tail", action="store_true", help="live tail mode")
    ap.add_argument("--watch", metavar="DIR", help="watch arbitrary dir")
    ap.add_argument("--show", action="store_true", help="snapshot render")
    ap.add_argument("--kind", choices=["scan", "recon"], default="scan")
    ap.add_argument("--target", required=True)
    args = ap.parse_args()

    if args.watch:
        watch_dir(Path(args.watch))
        return 0

    if args.tail:
        try:
            while True:
                render(args.target, args.kind)
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n[.] dashboard stopped")
        return 0

    render(args.target, args.kind)
    return 0


if __name__ == "__main__":
    sys.exit(main())