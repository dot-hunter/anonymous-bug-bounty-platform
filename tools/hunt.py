#!/usr/bin/env python3
"""hunt.py — active vulnerability hunt orchestrator (ghoulish script entrypoint).

Wraps vuln_scanner.sh and MCP tooling into a single production command:
    python3 tools/hunt.py --target target.com            # full (recon + scan)
    python3 tools/hunt.py --target target.com --scan-only  # scan existing recon
    python3 tools/hunt.py --target target.com --quick      # quick subset
    python3 tools/hunt.py --target target.com --no-banner  # CI-friendly
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
RECON_DIR = REPO_ROOT / "recon"
FINDINGS_DIR = REPO_ROOT / "findings"

BANNER = r"""
██████  ██████  ██   ██ ██   ██ ███   █ ███████
██   ██ ██   ██ ██   ██ ██   ██ ████  █   ███
██████  ██████  ███████ ██   ██ ██ ██ █   ███
██████  ██████  ███████ ██   ██ ██  ███   ███
██   ██ ██   ██ ██   ██ ██   ██ ██   ██   ███
██████  ██████  ██   ██ ███████ ██   ██   ███

+ Recon. Hunt. Validate. Report. +
"""


def log(msg: str, kind: str = "info") -> None:
    marker = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]"}.get(kind, "[*]")
    print(f"{marker} {msg}", flush=True)


def ensure_recon(target: str, quick: bool) -> Path:
    """Run quick recon if recon/<target>/ doesn't already exist."""
    recon_dir = RECON_DIR / target
    if recon_dir.exists() and any(recon_dir.iterdir()):
        log(f"Recon dir exists: {recon_dir}", "ok")
        return recon_dir

    log(f"No recon dir for {target} — gathering baseline", "warn")
    recon_dir.mkdir(parents=True, exist_ok=True)

    # Passive + light active recon (scope-safe: only the provided target host).
    live = subprocess.run(
        ["bash", str(TOOLS_DIR / "vuln_scanner.sh"), "--recon-only", target],
        capture_output=True, text=True, timeout=300,
    )
    with open(recon_dir / "live_hosts.txt", "w") as f:
        f.write(live_hosts(target))
    with open(recon_dir / "scan_log.txt", "w") as f:
        f.write(live.stdout)
    return recon_dir


def live_hosts(target: str) -> str:
    """Return candidate host lines for a raw target (subdomain pass optional)."""
    return target


def run_scanner(target: str, quick: bool) -> dict:
    recon_dir = ensure_recon(target, quick)
    scanner = TOOLS_DIR / "vuln_scanner.sh"
    if not scanner.exists():
        log(f"Missing {scanner} — cannot scan", "err")
        sys.exit(2)

    findings_dir = FINDINGS_DIR / target
    findings_dir.mkdir(parents=True, exist_ok=True)

    cmd = ["bash", str(scanner), str(recon_dir)]
    if quick:
        cmd.append("--quick")
    log(f"Running vuln_scanner.sh against {recon_dir}/ ...")
    t0 = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0

    summary = {
        "target": target,
        "ts": datetime.now(timezone.utc).isoformat(),
        "mode": "quick" if quick else "full",
        "exit_code": result.returncode,
        "elapsed_s": round(elapsed, 1),
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
    }
    out_file = findings_dir / "scan_output.txt"
    out_file.write_text(result.stdout or "")
    if result.stderr:
        (findings_dir / "scan_stderr.txt").write_text(result.stderr)

    # Parse scanner summary if present (XSS/SQLi/SSTI/Race counters)
    parsed = parse_summary(result.stdout)
    summary = {**summary, **parsed}
    (findings_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (findings_dir / "summary.txt").write_text(
        f"TARGET: {target}\nTS: {summary['ts']}\nMODE: {summary['mode']}\n"
        f"EXIT: {result.returncode} ({round(elapsed,1)}s)\n"
        + "\n".join(f"{k}: {v}" for k, v in parsed.items())
    )
    log(f"Results -> {findings_dir}/summary.txt", "ok")
    return summary


def parse_summary(stdout: str) -> dict:
    out = {}
    for line in stdout.splitlines():
        low = line.lower()
        for key in ("xss pipeline", "sqli", "ssti", "race", "rce", "mfa/saml"):
            if key in low:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    out[key.strip().replace(" ", "_")] = parts[1].strip()
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="bhunt active hunt orchestrator")
    ap.add_argument("--target", required=True, help="target host or file")
    ap.add_argument("--scan-only", action="store_true", help="skip recon step")
    ap.add_argument("--quick", action="store_true", help="fewer checks")
    ap.add_argument("--no-banner", action="store_true")
    args = ap.parse_args()

    if not args.no_banner:
        print(BANNER)

    # Lightweight sanity: refuse scanning without a target string
    if not args.target:
        log("--target required", "err")
        sys.exit(1)

    summary = run_scanner(args.target, args.quick)
    log(f"BUNT COMPLETE — {summary['target']}: exit={summary['exit_code']} "
        f"({summary.get('xss_pipeline', 'xss:N/A')}), see findings/{summary['target']}/summary.txt", "ok")


if __name__ == "__main__":
    main()