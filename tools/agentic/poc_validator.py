#!/usr/bin/env python3
"""
poc_validator.py — bounded-retry sandbox PoC loop with verdict classification.

For each POC_CANDIDATE finding this attempts (<= MAX_ATTEMPTS) to prove
exploitability INSIDE the sandbox, evaluating a differential signal
(payload run vs benign run) plus class-specific markers:

  Verdicts:
    CONFIRMED      exploit signal observed (differential + class marker)
    BLOCKED        no signal; sanitizer present or code defended
    UNREACHABLE    harness could not import/call the sink (missing deps, bad path)
    NEEDS_CONTEXT  finding is executable in principle but requires runtime
                   config/credentials to verify (reported, flagged)
    INCONCLUSIVE   differential ambiguous (behavior differs but no class marker)

Attempt ladder:
  0: payload from RAG corpus (payloads by vuln_class)
  1: encoder variants of attempt-0 payload
  2: alternate payload shape / second corpus hit

Evidence for every attempt is persisted by the caller via the returned dict.

Usage:
  python poc_validator.py --finding '<finding-json>' --target-dir <repo> [--sandbox auto]
  python poc_validator.py --self-test
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_runner import run_in_sandbox, detect_backend  # noqa: E402
from noise_filter import CLASS_FAMILIES as FAMILIES  # noqa: E402


def _family(vuln_class: str) -> str:
    """Map a checker's vuln_class to its exploit family (shared markers/payloads)."""
    return FAMILIES.get(vuln_class, vuln_class)

MAX_ATTEMPTS = 3
BENIGN_INPUTS = {
    "command_exec": "hello world",
    "file_read": "hello.txt",
    "sqli": "1",
    "xss": "plaintext",
    "ssti": "hello {{1+1}}",
    "default": "test",
}
# Class-specific success markers observed in output, keyed by exploit FAMILY
# (marker + optional expanded-token). For echo-back-prone families (cmd exec,
# xss, ssti) the marker must appear in EXPANDED form: the raw payload must NOT
# appear verbatim in output (echo '…' would print it), while real execution
# shows the marker without the payload wrapper.
CLASS_MARKERS = {
    "command_exec": (r"PWN_MARKER", "PWN_MARKER"),
    "file_read": (r"PAYLOAD_MARKER|SECRET_MARKER|flag\{|root:x:0|BEGIN PRIVATE KEY", None),
    "xss": (r"<script>|PWN_MARKER|alert\(1\)", "PWN_MARKER"),
    "sqli": (r"sqlite3\.|mysql|psycopg|SyntaxError|syntax error|operator does not exist", None),
    "default": (r"PAYLOAD_MARKER", "PAYLOAD_MARKER"),
}


def corpus_payloads(vuln_class: str, query: str, max_payloads: int = 3) -> list[str]:
    """Pull payload candidates from the RAG corpus CLI (best-effort)."""
    rag = Path(__file__).resolve().parents[1] / "rag-builder" / "search_payloads.py"
    try:
        p = subprocess.run(
            [sys.executable, str(rag), "--class", vuln_class, "--query", query, "--top", str(max_payloads)],
            capture_output=True, text=True, timeout=30,
        )
        hits = []
        for line in (p.stdout or "").splitlines():
            line = line.strip()
            if line and not line.startswith("[") and not line.startswith("file:"):
                line = line.split("[", 1)[0]
                if line:
                    hits.append(line[:300])
        return hits or class_default_payloads(vuln_class)
    except Exception:
        return class_default_payloads(vuln_class)


def class_default_payloads(family: str) -> list[str]:
    base = {
        # $(echo PWN_MARKER) — expands to PWN_MARKER only if the shell executes
        # it; if quoted/echoed literally, output contains "$(echo PWN_MARKER".
        "command_exec": ["$(echo PWN_MARKER)", "; echo PWN_MARKER", "| id"],
        # multi-depth ladder: the sink prefixes a base dir ("notes/"), and the
        # audit runs with cwd=target_dir — 8 "../" reaches "/" from a 3-level
        # fixture dir; 12 covers deeper nesting; 6 is a shallow fallback.
        "file_read": ["../../../../../../../../etc/passwd",
                      "../../../../../../../../../../etc/passwd",
                      "../../../../../../etc/passwd"],
        "sqli": ["1' OR '1'='1", "1 OR 1=1 --"],
        "xss": ["<script>PWN_MARKER</script>", '"><img src=x onerror=alert(1)>'],
        "ssti": ["{{7*7}}", "${7*7}"],
        "default": ["PAYLOAD_MARKER"],
    }
    return base.get(family, base["default"])


def build_harness(finding: dict, target_dir: str, payload: str,
                  function_hint: str | None = None) -> tuple[Path, str] | tuple[None, str]:
    """Build an executable harness for the finding's sink.

    function_hint: retest mode — anchor by FUNCTION NAME (line numbers shift
    between versions); falls back to line-based anchoring when absent.
    """
    fpath = finding.get("path") or finding.get("file") or ""
    line = int(finding.get("line") or 0)
    language = str(fpath).split(".")[-1].lower()
    src_path = Path(target_dir) / fpath
    if not src_path.exists():
        return None, f"source file not found: {fpath}"

    if language == "py":
        text = src_path.read_text(errors="replace")
        funcs = list(re.finditer(
            r"(?:^|\n)[ \t]*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->[^:]*)?:",
            text))
        target = None
        if function_hint:
            for m in funcs:
                if m.group(1) == function_hint:
                    target = m
                    break
            if not target:
                return None, f"function not found in current code: {function_hint}"
        else:
            for m in funcs:
                start = text[: m.start()].count("\n") + 1
                # end of function = until next TOP-LEVEL def/class (cap 400 body lines)
                rest = text[m.end():]
                nxt = re.search(r"\n(?:async\s+def|def|class)\s+\w+", rest)
                if nxt:
                    end_line = start + rest[: nxt.start()].count("\n")
                else:
                    end_line = start + min(rest.count("\n"), 400)
                if start <= line <= end_line:
                    target = m
                    break
            if not target:
                return None, "sink not inside a function definition"
        fname = target.group(1)
        params = []
        for p in target.group(2).split(","):
            p = p.strip()
            if not p:
                continue
            p = p.split("=")[0].strip()      # drop defaults
            params.append(p.split(":")[0].strip())  # drop type annotations
        if not params:
            return None, "sink function takes no parameters"
        module = src_path.stem
        abs_src = str(src_path.resolve())
        harness = f"""# agentic POC harness (generated)
import sys, json, importlib.util
sys.path.insert(0, {json.dumps(str(Path(target_dir).resolve()))})
try:
    spec = importlib.util.spec_from_file_location({json.dumps(module)}, {json.dumps(abs_src)})
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
except Exception as e:
    print("HARNESS_IMPORT_ERR:", type(e).__name__, str(e)[:200])
    sys.exit(42)
fn = getattr(mod, {json.dumps(fname)})
n_params = len({json.dumps(params)})
try:
    if n_params == 1:
        out = fn({json.dumps(payload)})
    else:
        out = fn({json.dumps(payload)}, *["" ] * (n_params - 1))
    print(json.dumps({{"ret": str(out)[:500]}}))
except Exception as e:
    print("HARNESS_CALL_ERR:", type(e).__name__, str(e)[:200])
    sys.exit(43)
"""
        tmp = Path(tempfile.mkdtemp(prefix="validx-")) / f"poc_{fname}.py"
        tmp.write_text(harness)
        return tmp, f"python harness calling {fname}(input)"

    if language in ("js", "mjs", "cjs"):
        funcs = list(re.finditer(r"(?:^|\n)\s*(?:function|const\s+\w+\s*=\s*function|export\s+function)\s+(\w+)\s*\(([^)]*)\)\s*[:{]", text))
        # pragmatic v1: skip complex JS harness, mark NEEDS_CONTEXT
        return None, "JS harness requires app runtime (v1: python/exec-only)"

    return None, f"no harness strategy for .{language} (v1 supports python; node/others: NEEDS_CONTEXT)"


def evaluate(finding: dict, payload: str, benign: str, target_dir: str,
             backend: str | None, function_hint: str | None = None) -> dict:
    """Run benign + payload in sandbox and produce an attempt verdict."""
    family = _family(finding.get("vuln_class") or "default")
    harness, desc = build_harness(finding, target_dir, payload, function_hint=function_hint)
    if not harness:
        return {"stage": "harness", "outcome": "NEEDS_CONTEXT", "detail": desc}

    harness_b, _ = build_harness(finding, target_dir, benign, function_hint=function_hint)
    if not harness_b:
        harness_b = harness

    mfn = re.search(r"calling (\w+)\(", desc)
    res_function = mfn.group(1) if mfn else None

    r_benign = run_in_sandbox([sys.executable, "-E", "-I", str(harness_b)], timeout=20, backend=backend, workdir=target_dir)
    r_payload = run_in_sandbox([sys.executable, "-E", "-I", str(harness)], timeout=20, backend=backend, workdir=target_dir)

    markers, expanded_token = CLASS_MARKERS.get(family, CLASS_MARKERS["default"])
    out = (r_payload.get("stdout") or "") + "\n" + (r_payload.get("stderr") or "")
    bout = (r_benign.get("stdout") or "") + "\n" + (r_benign.get("stderr") or "")

    if r_payload.get("exit") == 42 or "HARNESS_IMPORT_ERR" in out:
        return {"stage": "harness", "outcome": "UNREACHABLE", "detail": out.strip()[:200],
                "benign_exit": r_benign.get("exit")}
    if r_payload.get("exit") == 43 or "HARNESS_CALL_ERR" in out:
        return {"stage": "harness", "outcome": "NEEDS_CONTEXT", "detail": out.strip()[:200],
                "benign_exit": r_benign.get("exit")}

    marker_hit = bool(re.search(markers, out))
    if marker_hit and expanded_token:
        # expanded-only: if the RAW payload wrapper appears in output, the sink
        # echoed it literally (safe) — the token must appear WITHOUT the wrapper.
        # Blocks: "$(echo TOKEN" (unexpanded command substitution) and
        # "echo TOKEN" as text (the safe sink echoed the payload verbatim).
        if ("$(echo " + expanded_token) in out:
            marker_hit = False
        if ("echo " + expanded_token) in out:
            marker_hit = False
    differential = (out != bout) and not (r_payload.get("timed_out") and r_benign.get("timed_out"))

    # marker-bearing payload echoed back VERBATIM (payload string fully present
    # in output) => the sink treated input as DATA, not code (list-form
    # subprocess, quoted echo, escaped output) — defended, not exploitable.
    echoed_literal = bool(expanded_token and payload and expanded_token in payload
                          and payload in out and not marker_hit)
    if echoed_literal:
        return {
            "stage": "attempt", "outcome": "BLOCKED", "payload": payload,
            "detail": "sink echoed the marker-bearing payload verbatim (input treated as data)",
            "stdout_tail": (out or "")[-300:], "benign_tail": (bout or "")[-300:],
            "backend": r_payload.get("backend"), "marker_hit": False,
            "differential": differential, "benign_exit": r_benign.get("exit"),
            "function": res_function,
        }

    if marker_hit and differential:
        outcome = "CONFIRMED"
    elif marker_hit:
        outcome = "CONFIRMED"  # marker alone is a strong signal even if benign differs similarly
    elif differential and finding.get("sanitizer_hint"):
        outcome = "BLOCKED"  # behavior differs but sanitizer present and no marker -> defended
    elif differential:
        outcome = "INCONCLUSIVE"
    elif finding.get("sanitizer_hint"):
        outcome = "BLOCKED"
    else:
        outcome = "UNREACHABLE" if r_payload.get("exit") in (None, -1) else "INCONCLUSIVE"

    return {
        "stage": "attempt",
        "outcome": outcome,
        "payload": payload,
        "detail": f"exit={r_payload.get('exit')} benign_exit={r_benign.get('exit')}",
        "stdout_tail": (out or "")[-300:],
        "benign_tail": (bout or "")[-300:],
        "backend": r_payload.get("backend"),
        "marker_hit": marker_hit,
        "differential": differential,
        "benign_exit": r_benign.get("exit"),
        "function": res_function,
    }


def validate_finding(finding: dict, target_dir: str, sandbox: str | None = None,
                     max_attempts: int = MAX_ATTEMPTS,
                     function_hint: str | None = None) -> dict:
    """Bounded retry loop for one finding. Returns the final validated finding."""
    vclass = finding.get("vuln_class") or "default"
    family = _family(vclass)
    benign = BENIGN_INPUTS.get(family, BENIGN_INPUTS["default"])

    payloads = []
    # attempt 0: corpus top hit (learned payloads)
    first = corpus_payloads(vclass, vclass.replace("_", " "), 6)
    payloads.extend(first[:1])
    # attempts 1-2: family defaults (depth ladder etc.) — placed AFTER corpus
    # so deterministic payloads are never starved on attempt budget
    payloads.extend(class_default_payloads(family))

    attempts: list[dict] = []
    final = {"REVIEW": "INCONCLUSIVE"}
    fname = None
    for i, payload in enumerate(payloads[:max_attempts]):
        try:
            res = evaluate(finding, payload, benign, target_dir, sandbox,
                           function_hint=function_hint)
        except Exception as e:
            res = {"stage": "attempt", "outcome": "INCONCLUSIVE", "detail": f"validator error: {e}"}
        fname = res.get("function") or fname
        attempts.append(res)
        if res.get("outcome") in ("CONFIRMED", "BLOCKED", "UNREACHABLE"):
            if res["outcome"] == "CONFIRMED":
                final = {"REVIEW": "CONFIRMED", "evidence": res}
                break
            final = {"REVIEW": res["outcome"], "evidence": res}
            break
        # INCONCLUSIVE/NEEDS_CONTEXT -> next attempt
        final = {"REVIEW": res.get("outcome", "INCONCLUSIVE"),
                 "evidence": res if res.get("outcome") == "NEEDS_CONTEXT" else None}
    # exhaustion: if never CONFIRMED but INCONCLUSIVE remained, keep LIKELY-flag
    if final["REVIEW"] == "INCONCLUSIVE":
        final["REVIEW"] = "LIKELY_INCONCLUSIVE"
    # containment heuristic: benign input worked but EVERY payload was refused
    # with FileNotFoundError — the sink confines input (defended), not unverifiable
    if final["REVIEW"] in ("NEEDS_CONTEXT", "LIKELY_INCONCLUSIVE"):
        if attempts and all(a.get("stage") == "harness"
                            and "FileNotFoundError" in (a.get("detail") or "")
                            for a in attempts) \
                and any(a.get("benign_exit") == 0 for a in attempts):
            final = {"REVIEW": "BLOCKED",
                     "evidence": {"stage": "harness", "outcome": "BLOCKED",
                                  "detail": "all payloads refused (FileNotFoundError) while benign "
                                            "succeeded — path containment"}}
    return {
        **finding,
        "function": fname,
        "validation": {
            "verdict": final["REVIEW"],
            "evidence": final.get("evidence"),
            "attempts": attempts,
            "sandbox": detect_backend(sandbox),
        },
    }


def self_test() -> int:
    """Standalone smoke test: probe the sandbox backend and a tiny eval."""
    info = detect_backend()
    print("backend:", json.dumps(info))
    r = run_in_sandbox([sys.executable, "-c", "print('SANDBOX_OK')"], timeout=15)
    print(f"run: exit={r['exit']} stdout={r['stdout'].strip()!r} backend={r['backend']}")
    return 0 if r["exit"] == 0 else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    if "--finding" in sys.argv:
        i = sys.argv.index("--finding")
        finding = json.loads(sys.argv[i + 1])
        target_dir = sys.argv[sys.argv.index("--target-dir") + 1] if "--target-dir" in sys.argv else "."
        sandbox = sys.argv[sys.argv.index("--sandbox") + 1] if "--sandbox" in sys.argv else None
        print(json.dumps(validate_finding(finding, target_dir, sandbox), indent=2))
        sys.exit(0)
    print(__doc__)