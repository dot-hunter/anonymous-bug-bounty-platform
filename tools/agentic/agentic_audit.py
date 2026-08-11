#!/usr/bin/env python3
"""
agentic_audit.py — orchestrator for the Agentic PoC Validation Layer.

HUNT (semgrep + gitleaks)
  -> TRIAGE (noise_filter.py)
  -> AUDIT (poc_validator.py bounded retry in sandbox)
  -> REPORT (findings/audit/<ts>/: report.md, findings.json, vex.json,
             evidence/<id>/...)
  -> RETEST (--retest <report.json>: FIXED / STILL_PRESENT / CANNOT_VERIFY)

Reporting gate: only CONFIRMED findings reach the headline table; everything
else is preserved with its reasons (STATIC_ONLY appendix, VEX for non-proofs).

Usage:
  python agentic_audit.py --target-dir <repo> [--sandbox auto|docker|jail]
                          [--report-dir <out>] [--no-sandbox] [--json]
  python agentic_audit.py --retest <prior-report.json> --target-dir <repo> --report-dir <out>
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from noise_filter import triage  # noqa: E402
from poc_validator import validate_finding, corpus_payloads  # noqa: E402
from sandbox_runner import detect_backend  # noqa: E402

DEFAULT_RULESETS = ["p/owasp-top-ten", "p/security-audit"]
LOCAL_RULES_DIR = Path(__file__).resolve().parent / "rules"
CUSTOM_RULES_DIR = LOCAL_RULES_DIR


def run_semgrep(target_dir: str, extra_args: str | None = None) -> list[dict]:
    """Deterministic static pass over the target. Returns raw findings list.

    Local deterministic rules run first (offline, always work). Registry packs
    are best-effort extras: each runs in isolation and failures are non-fatal
    (so a flaky pack can never zero out local findings).
    """
    findings: list[dict] = []
    pack_errors: list[str] = []

    def _scan(cfg: str) -> list[dict]:
        cmd = ["semgrep", "--json", "--quiet", "--config", cfg]
        if extra_args:
            cmd += extra_args.split()
        # explicit file targets: semgrep 1.172 resolves directory targets to
        # zero files in some setups — enumerate deterministically instead
        targets = _list_candidate_files(target_dir)
        if not targets:
            return []
        cmd += targets[:500]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                               cwd=target_dir)
            data = json.loads(p.stdout or "{}")
            errs = [e.get("message", "")[:160] for e in data.get("errors", []) if isinstance(e, dict)]
            pack_errors.extend(errs)
            return _findings_from_semgrep(data)
        except Exception as e:
            pack_errors.append(f"{cfg}: {e}")
            return []

    local_rules = sorted(LOCAL_RULES_DIR.glob("*.yml")) if LOCAL_RULES_DIR.exists() else []
    for r in local_rules:
        findings += _scan(str(r))
    for pack in DEFAULT_RULESETS:
        findings += _scan(pack)

    if not findings and pack_errors:
        findings.append({"check_id": "semgrep-note", "severity": "INFO", "path": "",
                         "line": 0, "code": "registry packs unavailable: " + "; ".join(pack_errors[:2])})
    return findings


def _findings_from_semgrep(data: dict) -> list[dict]:
    out = []
    for r in data.get("results", []):
        path = r.get("path", "")
        extra = r.get("extra", {})
        out.append({
            "path": path,
            "line": (r.get("start") or {}).get("line", 0),
            "check_id": (r.get("check_id") or "").split(".")[-1],
            "vuln_class": _class_from_check(r.get("check_id") or "", extra.get("metadata", {})),
            "severity": extra.get("severity", "medium"),
            # snippet is filled from the SOURCE FILE in audit() — semgrep's
            # extra.lines is not reliable on every build (observed literal
            # "requires login" instead of code)
            "code": "",
        })
    return out


def _class_from_check(check_id: str, metadata: dict) -> str:
    cwe = str(metadata.get("cwe") or "")
    cid = check_id.lower()
    if "command" in cid or ("injection" in cid and "shell" in cid):
        return "command_injection"
    if "path" in cid or "traversal" in cid:
        return "path_traversal"
    if "xss" in cid or "cross-site" in cwe.lower():
        return "xss"
    if "sql" in cid or "sqli" in cwe.lower():
        return "sqli"
    if "template" in cid or "ssti" in cwe.lower():
        return "ssti"
    return cid.split(".")[-1].replace("-", "_") or "unknown"


def _extract_snippet(lines: str, line: int) -> str:
    return (lines or "").strip()[:400]


def _fill_snippets(raw: list[dict], repo_lines: dict[str, list[str]]) -> None:
    """Fill each finding's `code` from the scanned source (deterministic)."""
    for f in raw:
        rel = f.get("path") or ""
        if not rel:
            continue
        src = repo_lines.get(rel) or []
        ln = int(f.get("line") or 0)
        if not (1 <= ln <= len(src)):
            continue
        f["code"] = (src[ln - 1] or "")[:400]


def run_gitleaks(target_dir: str) -> list[dict]:
    try:
        p = subprocess.run(["gitleaks", "detect", "--no-banner", "--source", target_dir, "--report-format", "json"],
                           capture_output=True, text=True, timeout=120)
        data = json.loads(p.stdout or "[]")
        return [{"path": d.get("File", ""), "line": d.get("StartLine", 0),
                 "check_id": f"gitleaks:{d.get('RuleID','secret')}",
                 "vuln_class": "secret_leak",
                 "severity": "critical",
                 "code": (d.get("Secret", "") or "")[:40] + "..."}
                for d in data if isinstance(d, dict)]
    except Exception:
        return []


_TARGET_EXTS = {".py", ".js", ".ts", ".go", ".rb", ".php", ".java", ".c", ".cpp", ".h",
                ".sh", ".sql", ".html"}
_SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "dist", "build", "vendor", "__pycache__"}


def _list_candidate_files(target_dir: str) -> list[str]:
    files = []
    for p in Path(target_dir).rglob("*"):
        if not p.is_file() or p.suffix.lower() not in _TARGET_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        files.append(str(p.resolve()))
    return files


def _repo_lines(target_dir: str) -> dict[str, list[str]]:
    lines: dict[str, list[str]] = {}
    root = Path(target_dir)
    for p in Path(target_dir).rglob("*"):
        if p.is_file() and p.suffix in (".py", ".js", ".ts", ".go", ".rb", ".php", ".c", ".cpp", ".java", ".sh"):
            try:
                lines[str(p.relative_to(root))] = p.read_text(errors="replace").splitlines()
            except Exception:
                pass
    return lines


def audit(target_dir: str, sandbox: str | None = None, no_sandbox: bool = False,
          extra_args: str | None = None) -> dict:
    """Run the full HUNT -> TRIAGE -> AUDIT -> REPORT pipeline."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = Path("findings/audit") / ts
    evidence_dir = report_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    repo_lines = _repo_lines(target_dir)

    # HUNT
    raw = run_semgrep(target_dir, extra_args)
    secrets = run_gitleaks(target_dir)
    raw += secrets
    # relativize paths (absolute paths would trip the /tests/ ignore heuristic)
    root = Path(target_dir).resolve()
    for f in raw:
        p = f.get("path") or ""
        if p:
            try:
                f["path"] = str(Path(p).resolve().relative_to(root))
            except ValueError:
                pass
    # deterministic snippets straight from the scanned files
    _fill_snippets(raw, repo_lines)

    # TRIAGE
    t = triage(raw, repo_lines)

    # AUDIT
    validated: list[dict] = []
    sandbox_info = detect_backend(sandbox)
    for f in t["poc_candidates"]:
        if no_sandbox:
            v = {**f, "validation": {"verdict": "NOT_TESTED_NO_SANDBOX",
                                     "sandbox": sandbox_info}}
        else:
            v = validate_finding(f, target_dir, sandbox)
            # persist evidence
            vid = f"{Path(f['path']).stem}_{f['line']}_{f['vuln_class']}".replace("/", "_")
            (evidence_dir / vid).mkdir(parents=True, exist_ok=True)
            ev = v.get("validation", {}).get("evidence") or {}
            (evidence_dir / vid / "verdict.json").write_text(
                json.dumps(v.get("validation", {}), indent=2))
            if ev.get("payload"):
                (evidence_dir / vid / "poc_input.txt").write_text(ev["payload"])
            if ev.get("stdout_tail"):
                (evidence_dir / vid / "out.txt").write_text(ev["stdout_tail"])
        validated.append(v)

    confirmed = [v for v in validated if v.get("validation", {}).get("verdict") == "CONFIRMED"]
    blocked = [v for v in validated if v.get("validation", {}).get("verdict") == "BLOCKED"]
    vex = [{"path": v.get("path"), "line": v.get("line"), "vuln_class": v.get("vuln_class"),
            "verdict": v.get("validation", {}).get("verdict"),
            "reasons": v.get("reasons", [])}
           for v in validated if v.get("validation", {}).get("verdict") not in ("CONFIRMED",)]

    result = {
        "ts": ts,
        "target_dir": str(Path(target_dir).resolve()),
        "sandbox": sandbox_info,
        "counts": {
            "raw": len(raw),
            **t["counts"],
            "validated": len(validated),
            "confirmed": len(confirmed),
            "blocked": len(blocked),
        },
        "confirmed": confirmed,
        "validated": validated,
        "static_only": t["static_only"],
        "ignored": t["ignored"],
        "human_review": t["human_review"],
        "vex": vex,
        "report_dir": str(report_dir),
    }

    _write_report(result, report_dir)
    return result


def _write_report(result: dict, report_dir: Path) -> None:
    (report_dir / "findings.json").write_text(json.dumps(result, indent=2, default=str))
    (report_dir / "vex.json").write_text(json.dumps(result["vex"], indent=2))
    md = [f"# Agentic PoC Validation Report — {result['ts']}",
          "",
          f"**Target:** `{result['target_dir']}`",
          f"**Sandbox:** `{result['sandbox']['backend']}` ({result['sandbox'].get('why')})",
          f"**Raw findings:** {result['counts']['raw']} | "
          f"**POC candidates:** {result['counts']['POC_CANDIDATE']} | "
          f"**CONFIRMED:** {result['counts']['confirmed']} | "
          f"**BLOCKED:** {result['counts']['blocked']} | "
          f"**VEX:** {len(result.get('vex', []))}",
          ""]
    if result["confirmed"]:
        md += ["## CONFIRMED (exploited in sandbox)", ""]
        for c in result["confirmed"]:
            ev = c.get("validation", {}).get("evidence") or {}
            md += [f"- **{c['vuln_class']}** `{c['path']}:{c['line']}` "
                   f"payload={ev.get('payload','')!r} → {ev.get('stdout_tail','')[-120:]!r}"]
    else:
        md += ["## CONFIRMED: none", ""]
    md += ["## VEX / non-proofs", ""]
    for v in result.get("vex", []):
        md += [f"- {v['verdict']}: {v['vuln_class']} {v['path']}:{v['line']} ({', '.join(v.get('reasons', []))})"]
    (report_dir / "report.md").write_text("\n".join(md))


def retest(prior_report: Path, target_dir: str, sandbox: str | None = None) -> dict:
    """Re-validate prior CONFIRMED/LIKELY findings against changed code.

    Findings are re-anchored by FUNCTION NAME (line numbers shift between
    versions). FIXED = current code no longer produces exploit signal.
    """
    prior = json.loads(prior_report.read_text())
    seen: set[tuple] = set()
    prior_confirmed = []
    for v in prior.get("confirmed", []) + [v for v in prior.get("validated", [])
                                           if v.get("validation", {}).get("verdict")
                                           in ("CONFIRMED", "LIKELY_INCONCLUSIVE")]:
        key = (v.get("path"), v.get("line"), v.get("vuln_class"))
        if key in seen:
            continue
        seen.add(key)
        prior_confirmed.append(v)

    results = []
    for v in prior_confirmed:
        cur = validate_finding(v, target_dir, sandbox,
                               function_hint=v.get("function"))
        verdict = cur.get("validation", {}).get("verdict")
        # FIXED: exploit signal gone (BLOCKED = defended); STILL_PRESENT: the
        # exact exploit still fires; anything ambiguous = CANNOT_VERIFY.
        if verdict == "CONFIRMED":
            state = "STILL_PRESENT"
        elif verdict == "BLOCKED":
            state = "FIXED"
        else:
            state = "CANNOT_VERIFY"
        results.append({"path": v.get("path"), "line": v.get("line"),
                        "function": v.get("function"),
                        "vuln_class": v.get("vuln_class"),
                        "prior": v.get("validation", {}).get("verdict"),
                        "now": verdict, "state": state})
    return {"target_dir": str(Path(target_dir).resolve()), "results": results,
            "counts": {s: sum(1 for r in results if r["state"] == s)
                       for s in ("FIXED", "STILL_PRESENT", "CANNOT_VERIFY")}}


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--retest" in args:
        prior = Path(args[args.index("--retest") + 1])
        target = args[args.index("--target-dir") + 1] if "--target-dir" in args else "."
        sandbox = args[args.index("--sandbox") + 1] if "--sandbox" in args else None
        print(json.dumps(retest(prior, target, sandbox), indent=2))
        sys.exit(0)
    if "--self-test" in args:
        from poc_validator import self_test
        sys.exit(self_test())
    target = args[args.index("--target-dir") + 1] if "--target-dir" in args else "."
    sandbox = args[args.index("--sandbox") + 1] if "--sandbox" in args else None
    no_sb = "--no-sandbox" in args
    res = audit(target, sandbox=sandbox, no_sandbox=no_sb)
    if "--json" in args:
        print(json.dumps(res, indent=2, default=str))
    else:
        print(f"raw={res['counts']['raw']} candidates={res['counts']['POC_CANDIDATE']} "
              f"CONFIRMED={res['counts']['confirmed']} BLOCKED={res['counts']['blocked']} "
              f"report={res['report_dir']}")