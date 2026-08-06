#!/usr/bin/env python3
"""
Security-Research MCP Server — 2026 Elite Vulnerability Research Stack.

Tools provided to the OpenCode agent:
  - run_semgrep            : Run semgrep with custom + bundled rulesets, return structured JSON
  - run_codeql             : Create a CodeQL DB and run a taint-tracking query (graceful no-op if codeql absent)
  - race_condition_test    : Fire N parallel requests to exploit TOCTOU / single-use-token windows
  - check_dependency_confusion : Check npm manifest packages against the public registry
  - save_weird_log         : Append an anomaly to the session "weird inventory"
  - read_weird_inventory   : Return the current weird inventory for this session
  - variant_analysis       : Given a confirmed vuln class + root cause, emit a Semgrep rule + GitHub search query
  - get_session_protocol   : Return the pre/during/post-session protocol for the agent
  - generate_poc_scaffold  : Emit a Dockerfile + poc.py + report_draft.md for a confirmed finding
  - list_custom_rules      : List the bundled custom Semgrep rules
  - load_custom_rule       : Return a specific bundled custom rule YAML by id
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("security-research")

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "rules"
QUERIES_DIR = HERE / "queries"
POC_TEMPLATES_DIR = HERE / "poc-templates"
DATA_DIR = Path.home() / ".config" / "opencode"
SESSION_LOGS_DIR = DATA_DIR / "session-logs"
WEIRD_INVENTORY_DIR = DATA_DIR / "weird-inventory"
SESSION_LOGS_DIR.mkdir(parents=True, exist_ok=True)
WEIRD_INVENTORY_DIR.mkdir(parents=True, exist_ok=True)

SEMGRP = shutil.which("semgrep") or shutil.which("semgrep-core")
CODEQL = shutil.which("codeql")


def _which(name: str):
    return shutil.which(name)


def _run(cmd, timeout=120, cwd=None):
    """Run a command, returning (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)


# --------------------------------------------------------------------------- #
# Semgrep runner
# --------------------------------------------------------------------------- #

def _run_semgrep_impl(target_path, custom_rule_yaml=None, rulesets=None, extra_args=None):
    """Run semgrep and return parsed JSON results."""
    if not SEMGRP:
        return {
            "error": "semgrep not installed",
            "hint": "Install with: pip install semgrep  OR  brew install semgrep",
            "target": target_path,
        }

    cmd = [SEMGRP, "--json"]
    tmp_rule_path = None

    if custom_rule_yaml:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, prefix="semgrep_rule_")
        tmp.write(custom_rule_yaml)
        tmp.close()
        tmp_rule_path = tmp.name
        cmd += ["--config", tmp_rule_path]

    for rs in rulesets or []:
        # Auto-resolve bare rule names (e.g. "custom-security-2026") from RULES_DIR
        rule_path = RULES_DIR / f"{rs}.yml"
        if not rule_path.exists():
            rule_path = RULES_DIR / f"{rs}.yaml"
        if rule_path.exists():
            cmd += ["--config", str(rule_path)]
        elif rs.startswith("p/") or rs.startswith("http"):
            cmd += ["--config", rs]
        else:
            # Try as a direct path
            cmd += ["--config", rs]

    if not custom_rule_yaml and not rulesets:
        cmd += ["--config", "p/owasp-top-10", "--config", "p/r2c-security-audit"]

    if extra_args:
        cmd += extra_args

    cmd.append(target_path)

    rc, stdout, stderr = _run(cmd, timeout=300)
    result = {"target": target_path, "returncode": rc, "command": " ".join(cmd)}

    if tmp_rule_path:
        try:
            os.unlink(tmp_rule_path)
        except OSError:
            pass

    if rc == 0:
        try:
            parsed = json.loads(stdout)
            findings = parsed.get("results", [])
            result["total_findings"] = len(findings)
            result["errors"] = parsed.get("errors", [])
            result["findings"] = [
                {
                    "check_id": f.get("check_id"),
                    "path": f.get("path"),
                    "start": f.get("start"),
                    "end": f.get("end"),
                    "extra_message": f.get("extra", {}).get("message"),
                    "extra_severity": f.get("extra", {}).get("severity"),
                    "extra_metadata": f.get("extra", {}).get("metadata"),
                }
                for f in findings
            ]
        except json.JSONDecodeError:
            result["raw_output"] = stdout[:8000]
            result["error"] = "Failed to parse semgrep JSON output"
    else:
        result["error"] = stderr[:4000] or "semgrep failed"
        result["raw_output"] = stdout[:4000]

    return result


# --------------------------------------------------------------------------- #
# CodeQL runner
# --------------------------------------------------------------------------- #

def _run_codeql_impl(repo_path, language, query_file=None, query_content=None):
    """Create a CodeQL DB and run a query. Gracefully degrades if codeql absent."""
    if not CODEQL:
        return {
            "error": "codeql CLI not installed",
            "hint": "Download from https://github.com/github/codeql-cli-binaries and add to PATH",
            "repo_path": repo_path,
            "language": language,
        }

    db_path = tempfile.mkdtemp(prefix="codeql_db_")
    results_path = tempfile.mktemp(prefix="codeql_results_", suffix=".bqrs")

    rc, _, stderr = _run(
        [CODEQL, "database", "create", db_path, "--language", language, "--source-root", repo_path, "--overwrite"],
        timeout=300,
    )
    if rc != 0:
        return {"error": "codeql database creation failed", "details": stderr[:4000]}

    qpath = query_file
    tmp_q = None
    if query_content and not qpath:
        tmp_q = tempfile.mktemp(suffix=".ql")
        Path(tmp_q).write_text(query_content)
        qpath = tmp_q

    if not qpath:
        return {"error": "No query provided (query_file or query_content required)"}

    rc, _, stderr = _run(
        [CODEQL, "query", "run", "--database", db_path, qpath, "--output", results_path],
        timeout=300,
    )
    if tmp_q:
        try:
            os.unlink(tmp_q)
        except OSError:
            pass

    if rc != 0:
        return {"error": "codeql query run failed", "details": stderr[:4000]}

    rc, stdout, stderr = _run([CODEQL, "bqrs", "decode", results_path, "--format=csv"], timeout=60)
    if rc != 0:
        return {"error": "codeql decode failed", "details": stderr[:4000]}

    return {"repo_path": repo_path, "language": language, "results_csv": stdout[:16000], "query_file": qpath}


# --------------------------------------------------------------------------- #
# Race condition tester
# --------------------------------------------------------------------------- #

async def _race_attack(url, method, payload, headers, parallel_count, timeout=15.0):
    """Fire N parallel requests and report how many succeeded (expected: 1)."""
    body = None
    if payload is not None:
        body = json.dumps(payload).encode() if isinstance(payload, dict) else str(payload).encode()

    base_headers = headers or {}
    base_headers.setdefault("Content-Type", "application/json")
    sem = asyncio.Semaphore(parallel_count)

    async def fire(idx):
        async with sem:
            req_headers = {**base_headers, "X-Race-Id": str(idx)}
            loop = asyncio.get_event_loop()

            def _do():
                req = urllib.request.Request(url, data=body, method=method.upper(), headers=req_headers)
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        return {"id": idx, "status": resp.status, "ok": 200 <= resp.status < 300}
                except urllib.error.HTTPError as e:
                    return {"id": idx, "status": e.code, "ok": 200 <= e.code < 300}
                except Exception as e:
                    return {"id": idx, "error": str(e)[:200], "ok": False}

            return await loop.run_in_executor(None, _do)

    tasks = [fire(i) for i in range(parallel_count)]
    results = await asyncio.gather(*tasks)
    successes = sum(1 for r in results if r.get("ok"))
    return {
        "url": url,
        "method": method,
        "parallel_requests": parallel_count,
        "successful": successes,
        "expected": 1,
        "race_condition_detected": successes > 1,
        "all_results": results,
    }


def _race_condition_test_sync(url, method="POST", payload=None, headers=None, parallel_count=50):
    """Sync wrapper around the async race attack."""
    try:
        return asyncio.run(_race_attack(url, method, payload, headers, parallel_count))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_race_attack(url, method, payload, headers, parallel_count))
        finally:
            loop.close()


# --------------------------------------------------------------------------- #
# Dependency confusion checker
# --------------------------------------------------------------------------- #

def _check_dependency_confusion_impl(manifest_path):
    """Check an npm package.json for packages missing from the public registry."""
    p = Path(manifest_path)
    if not p.exists():
        return {"error": f"manifest not found: {manifest_path}"}

    try:
        manifest = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        return {"error": f"invalid JSON: {e}"}

    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps.update(manifest.get(key, {}))

    results = []
    for pkg in deps:
        try:
            url = f"https://registry.npmjs.org/{pkg}"
            req = urllib.request.Request(url, headers={"User-Agent": "security-research-mcp/2026"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                results.append({"package": pkg, "exists_on_public_registry": resp.status == 200, "status": resp.status})
        except urllib.error.HTTPError as e:
            results.append({"package": pkg, "exists_on_public_registry": False, "status": e.code})
        except Exception as e:
            results.append({"package": pkg, "exists_on_public_registry": False, "status": "network_error", "error": str(e)[:100]})

    missing = [r for r in results if not r["exists_on_public_registry"]]
    return {
        "manifest": manifest_path,
        "total_checked": len(results),
        "missing_from_public_registry": missing,
        "dependency_confusion_candidates": len(missing),
        "risk": "HIGH" if missing else "LOW",
        "all_results": results,
    }


# --------------------------------------------------------------------------- #
# Weird inventory + session logging
# --------------------------------------------------------------------------- #

def _weird_inventory_path(session_id):
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)
    return WEIRD_INVENTORY_DIR / f"{safe}.jsonl"


def _save_weird_log_impl(session_id, kind, endpoint, description, tested=None, deferred=None):
    """Append an anomaly to the session weird inventory."""
    valid_kinds = {"WEIRD", "TESTED", "DEFERRED", "GADGET"}
    kind = kind.upper()
    if kind not in valid_kinds:
        return {"error": f"invalid kind '{kind}', must be one of {valid_kinds}"}

    entry = {
        "kind": kind,
        "date": time.strftime("%Y-%m-%d"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "endpoint": endpoint,
        "description": description,
    }
    if tested:
        entry["tested"] = tested
    if deferred:
        entry["deferred"] = deferred

    path = _weird_inventory_path(session_id)
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")

    return {"saved": True, "session_id": session_id, "entry": entry, "path": str(path)}


def _read_weird_inventory_impl(session_id):
    path = _weird_inventory_path(session_id)
    if not path.exists():
        return {"session_id": session_id, "entries": [], "count": 0}
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    by_kind = {}
    for e in entries:
        by_kind.setdefault(e["kind"], []).append(e)
    return {"session_id": session_id, "count": len(entries), "entries": entries, "by_kind": by_kind}


# --------------------------------------------------------------------------- #
# Variant analysis
# --------------------------------------------------------------------------- #

VARIANT_RULE_TEMPLATES = {
    "prototype-pollution": '''rules:
  - id: variant-prototype-pollution
    patterns:
      - pattern: |
          function $MERGE($TARGET, $SOURCE) {
            ...
            $TARGET[$KEY] = $SOURCE[$KEY]
            ...
          }
      - pattern-not: |
          if ($KEY === "__proto__" || $KEY === "constructor" || $KEY === "prototype") ...
    message: "Deep merge without __proto__/constructor key filtering — prototype pollution variant"
    severity: ERROR
    languages: [javascript, typescript]
''',
    "ssrf": '''rules:
  - id: variant-ssrf-unvalidated-url
    patterns:
      - pattern: requests.get($URL, ...)
      - pattern-not: |
          if not $URL.startswith(("https://", "http://")): ...
    message: "HTTP fetch with potentially user-controlled URL — SSRF variant"
    severity: WARNING
    languages: [python]
''',
    "sqli": '''rules:
  - id: variant-sqli-raw-query
    patterns:
      - pattern: $DB.execute($QUERY + $USER_INPUT)
      - pattern-not: $DB.execute($QUERY, $PARAMS)
    message: "String concatenation into SQL query — SQL injection variant"
    severity: ERROR
    languages: [python]
''',
    "deserialization": '''rules:
  - id: variant-unsafe-deserialization
    patterns:
      - pattern: pickle.loads($INPUT)
      - pattern-not: pickle.loads($TRUSTED)
    message: "pickle.loads with potentially untrusted input — deserialization RCE variant"
    severity: ERROR
    languages: [python]
''',
    "race-condition": '''rules:
  - id: variant-toctou-async
    patterns:
      - pattern: |
          async def $FUNC(...):
            ...
            if await $CHECK(...):
              ...
              await $ACT(...)
    message: "Async check-then-act — TOCTOU race condition variant"
    severity: WARNING
    languages: [python]
''',
    "prompt-injection": '''rules:
  - id: variant-mcp-prompt-injection
    patterns:
      - pattern: $CONTEXT = ... + $TOOL_RESULT.content + ...
      - pattern-not: sanitize($TOOL_RESULT.content)
    message: "Tool response concatenated into agent context without sanitization — prompt injection variant"
    severity: ERROR
    languages: [javascript, typescript, python]
''',
}

VARIANT_GITHUB_QUERIES = {
    "prototype-pollution": 'language:javascript "deepMerge" "function" path:src',
    "ssrf": 'language:python "requests.get(url)" path:webhook',
    "sqli": 'language:python ".execute(query +" path:api',
    "deserialization": 'language:python "pickle.loads(" path:worker',
    "race-condition": 'language:python "async def" "await" "if" path:api',
    "prompt-injection": 'language:typescript "callTool" "content" "context" path:agent',
}


def _variant_analysis_impl(vuln_class, root_cause_description, confirmed_location=None):
    """Generate a Semgrep rule + GitHub search query for variant hunting."""
    vc = vuln_class.lower().strip()
    if vc not in VARIANT_RULE_TEMPLATES:
        return {
            "error": f"unknown vuln_class '{vuln_class}'",
            "supported_classes": list(VARIANT_RULE_TEMPLATES.keys()),
        }
    return {
        "vuln_class": vc,
        "root_cause": root_cause_description,
        "confirmed_location": confirmed_location,
        "custom_semgrep_rule": VARIANT_RULE_TEMPLATES[vc],
        "github_search_query": VARIANT_GITHUB_QUERIES[vc],
        "workflow": [
            "1. Save custom_semgrep_rule to a .yml file",
            "2. Run: semgrep --config rule.yml --config p/owasp-top-10 <target>",
            "3. Run github_search_query on https://github.com/search",
            "4. For each match: assess source-to-sink data flow independently",
            "5. Score by exploitability — can it reach a more sensitive sink?",
        ],
    }


# --------------------------------------------------------------------------- #
# PoC scaffold generator
# --------------------------------------------------------------------------- #

def _poc_script_template(vuln_class, language, payload):
    """Return a language-appropriate PoC skeleton."""
    if language in ("python",):
        return f'''#!/usr/bin/env python3
"""
PoC for {vuln_class}.
Success indicator: observable output below proves exploitation.
"""
import sys

def main():
    print("[*] Starting PoC for {vuln_class}...")
    # --- Setup: establish session/auth if needed ---
    # TODO
    # --- Payload ---
    payload = {payload!r}
    # --- Trigger ---
    # TODO: send the request / invoke the action
    print("[*] Payload:", payload)
    # --- Verify ---
    # TODO: confirm exploitation via observable output
    print("[+] PoC complete. Check for success indicator.")

if __name__ == "__main__":
    main()
'''
    if language in ("javascript", "typescript"):
        return f'''#!/usr/bin/env node
/**
 * PoC for {vuln_class}.
 * Success indicator: observable output below proves exploitation.
 */
async function main() {{
  console.log("[*] Starting PoC for {vuln_class}...");
  // --- Setup ---
  // TODO
  const payload = {payload!r};
  console.log("[*] Payload:", payload);
  console.log("[+] PoC complete. Check for success indicator.");
}}
main();
'''
    if language == "go":
        return f'''package main

import "fmt"

func main() {{
    fmt.Println("[*] Starting PoC for {vuln_class}...")
    payload := {payload!r}
    fmt.Println("[*] Payload:", payload)
    fmt.Println("[+] PoC complete. Check for success indicator.")
}}
'''
    if language == "ruby":
        return f'''#!/usr/bin/env ruby
puts "[*] Starting PoC for {vuln_class}..."
payload = {payload!r}
puts "[*] Payload: #{{payload}}"
puts "[+] PoC complete. Check for success indicator."
'''
    if language == "php":
        return f'''<?php
echo "[*] Starting PoC for {vuln_class}...\\n";
$payload = {payload!r};
echo "[*] Payload: $payload\\n";
echo "[+] PoC complete. Check for success indicator.\\n";
'''
    if language == "java":
        return f'''public class Poc {{
    public static void main(String[] args) {{
        System.out.println("[*] Starting PoC for {vuln_class}...");
        String payload = {payload!r};
        System.out.println("[*] Payload: " + payload);
        System.out.println("[+] PoC complete. Check for success indicator.");
    }}
}}
'''
    return f"# PoC for {vuln_class}\n# payload: {payload}\n"


def _generate_poc_scaffold_impl(vuln_class, target_version, target_language, title,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                exploit_payload="# TODO: insert working payload"):
    """Generate Dockerfile + poc script + report draft for a confirmed finding."""
    safe_title = re.sub(r"[^a-zA-Z0-9_-]", "-", title)[:60]
    lang_map = {
        "python": ("python:3.11-slim", "poc.py", "python3 poc.py"),
        "javascript": ("node:20-slim", "poc.js", "node poc.js"),
        "typescript": ("node:20-slim", "poc.ts", "npx tsx poc.ts"),
        "go": ("golang:1.22-alpine", "poc.go", "go run poc.go"),
        "ruby": ("ruby:3.3-slim", "poc.rb", "ruby poc.rb"),
        "php": ("php:8.3-cli", "poc.php", "php poc.php"),
        "java": ("eclipse-temurin:21-jdk", "Poc.java", "java Poc.java"),
    }
    base_image, poc_filename, run_cmd = lang_map.get(
        target_language.lower(), ("python:3.11-slim", "poc.py", "python3 poc.py")
    )

    dockerfile = f'''FROM {base_image}
LABEL poc.title="{title}"
LABEL poc.vuln_class="{vuln_class}"
LABEL poc.target_version="{target_version}"

WORKDIR /poc
# Pin the exact vulnerable version here:
# RUN pip install vulnerable-lib=={target_version}

COPY {poc_filename} .
CMD ["sh", "-c", "{run_cmd}"]
'''

    poc_script = _poc_script_template(vuln_class, target_language, exploit_payload)

    report_draft = f'''# {title}

**Vulnerability Class:** {vuln_class}
**Target Version:** {target_version}
**Language:** {target_language}
**CVSS 3.1:** {cvss_vector}

## Impact

TODO: What an attacker can do right now. Impact first.

## Root Cause

TODO: One sentence. Where the trust assumption broke.

## Steps to Reproduce

```bash
docker build -t poc-{safe_title} .
docker run --rm poc-{safe_title}
```

## Proof of Concept

```bash
{run_cmd}
```

Expected output:
```
TODO: Insert the observable success indicator here
```

## Impact Scope

TODO: Affected users/systems. Downstream service access.

## Remediation

TODO: Specific fix, not "validate input."
'''

    return {
        "vuln_class": vuln_class,
        "target_version": target_version,
        "target_language": target_language,
        "title": title,
        "cvss_vector": cvss_vector,
        "files": {
            "Dockerfile": dockerfile,
            poc_filename: poc_script,
            "report_draft.md": report_draft,
        },
        "run_command": f"docker build -t poc-{safe_title} . && docker run --rm poc-{safe_title}",
    }


# --------------------------------------------------------------------------- #
# Session protocol
# --------------------------------------------------------------------------- #

SESSION_PROTOCOL = {
    "pre_session": {
        "title": "Pre-Session Setup (5 minutes, always)",
        "steps": [
            "DEFINE: Target [repo + version], Goal [C/I/A/ATO/RCE], Vuln class focus [1-2 from Tier 1], Time budget [hours]",
            "LOAD CONTEXT: Read last session notes, check new commits since last session, check related CVEs (30 days)",
            "TOOL SETUP: proxy running + scope configured, interactsh-client for OOB, custom Semgrep rules loaded, Docker env ready",
        ],
    },
    "rotation_rule": {
        "title": "The 20-Minute Rotation Rule",
        "rule": "Every 20 minutes ask: am I making progress toward the goal? If NO rotate: different endpoint/same class, same endpoint/different class, different component, or return to static analysis. 45-min hard stop on one parameter.",
    },
    "signal_logging": {
        "title": "Signal Logging — The Weird Inventory",
        "kinds": ["WEIRD", "TESTED", "DEFERRED", "GADGET"],
        "format": "[KIND][DATE][ENDPOINT] Description",
        "tool": "save_weird_log / read_weird_inventory",
    },
    "post_session": {
        "title": "Post-Session Checklist",
        "items": [
            "Save all proxy project files",
            "Update weird inventory with today's findings",
            "Write custom Semgrep rule for any pattern found today",
            "Run variant analysis on any confirmed findings",
            "Update deferred list with next-session entry points",
            "If finding confirmed: start PoC construction before closing",
            "Note: what assumption did the developer make that turned out wrong?",
        ],
    },
    "doctrine": [
        "Every session has a defined goal: C/I/A/ATO/RCE. Pick one before touching any tool.",
        "Automation handles recon surface. You handle logic, trust boundaries, architecture reasoning.",
        "A finding without a working PoC is a hypothesis, not a vulnerability.",
        "Highest-value bugs live at the intersection of two systems, roles, states, or timing windows.",
        "Work sink-to-source: find dangerous functions first, then trace user data to them.",
        "Every finding ships with a one-command Docker PoC.",
        "Run variant analysis before reporting — one bug should become 2-5 findings.",
        "If automation would have caught it, dig deeper.",
    ],
}


def _list_custom_rules_impl():
    """List bundled custom Semgrep rules."""
    rules = []
    if RULES_DIR.exists():
        for f in sorted(list(RULES_DIR.glob("*.yml")) + list(RULES_DIR.glob("*.yaml"))):
            rules.append({"id": f.stem, "path": str(f), "size": f.stat().st_size})
    return {"rules_dir": str(RULES_DIR), "count": len(rules), "rules": rules}


def _load_custom_rule_impl(rule_id):
    """Return a specific bundled custom rule."""
    for ext in (".yml", ".yaml"):
        p = RULES_DIR / f"{rule_id}{ext}"
        if p.exists():
            return {"id": rule_id, "path": str(p), "content": p.read_text()}
    return {"error": f"rule '{rule_id}' not found in {RULES_DIR}"}


# --------------------------------------------------------------------------- #
# MCP Server registration
# --------------------------------------------------------------------------- #

server = MCPServer(
    "security-research",
    version="2026.08",
    description="Elite vulnerability research MCP server — semgrep, codeql, race conditions, dependency confusion, variant analysis, PoC generation, session protocol",
    instructions=(
        "You are an elite security research agent. Use run_semgrep and run_codeql to surface structure "
        "before manual review. Work sink-to-source. Log anomalies with save_weird_log. Run variant_analysis "
        "on every confirmed finding. Generate Docker PoCs with generate_poc_scaffold. Follow get_session_protocol."
    ),
)


@server.tool()
def run_semgrep(target_path, custom_rule_yaml=None, rulesets=None, extra_args=None):
    """Run semgrep with custom + bundled rulesets. Returns structured JSON findings.

    Args:
        target_path: path or URL to scan
        custom_rule_yaml: raw YAML rule string to use (takes precedence over rulesets)
        rulesets: list of rule names/paths (e.g. ["custom-security-2026", "p/owasp-top-10"]).
            Also accepts a single string for convenience — auto-wrapped into a list.
        extra_args: extra CLI args for semgrep
    """
    # Accept a single string for convenience
    if rulesets is not None and isinstance(rulesets, str):
        rulesets = [rulesets]
    if extra_args is not None and isinstance(extra_args, str):
        extra_args = [extra_args]
    return _run_semgrep_impl(target_path, custom_rule_yaml, rulesets, extra_args)


@server.tool()
def run_codeql(repo_path, language, query_file=None, query_content=None):
    """Create a CodeQL database and run a taint-tracking query."""
    return _run_codeql_impl(repo_path, language, query_file, query_content)


@server.tool()
def race_condition_test(url, method="POST", payload=None, headers=None, parallel_count=50):
    """Fire N parallel requests to exploit TOCTOU / single-use-token race conditions."""
    return _race_condition_test_sync(url, method, payload, headers, parallel_count)


@server.tool()
def check_dependency_confusion(manifest_path):
    """Check an npm package.json for packages missing from the public registry."""
    return _check_dependency_confusion_impl(manifest_path)


@server.tool()
def save_weird_log(session_id, kind, endpoint, description, tested=None, deferred=None):
    """Append an anomaly to the session 'weird inventory'."""
    return _save_weird_log_impl(session_id, kind, endpoint, description, tested, deferred)


@server.tool()
def read_weird_inventory(session_id):
    """Return the current weird inventory for a session, grouped by kind."""
    return _read_weird_inventory_impl(session_id)


@server.tool()
def variant_analysis(vuln_class, root_cause_description, confirmed_location=None):
    """Given a confirmed vulnerability, emit a Semgrep rule + GitHub search query for variant hunting."""
    return _variant_analysis_impl(vuln_class, root_cause_description, confirmed_location)


@server.tool()
def get_session_protocol():
    """Return the pre/during/post-session protocol and operating doctrine for the agent."""
    return SESSION_PROTOCOL


@server.tool()
def generate_poc_scaffold(vuln_class, target_version, target_language, title,
                          cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                          exploit_payload="# TODO: insert working payload"):
    """Generate a Dockerfile + poc script + report draft for a confirmed finding."""
    return _generate_poc_scaffold_impl(vuln_class, target_version, target_language, title, cvss_vector, exploit_payload)


@server.tool()
def list_custom_rules():
    """List the bundled custom Semgrep rules."""
    return _list_custom_rules_impl()


@server.tool()
def load_custom_rule(rule_id):
    """Return a specific bundled custom rule YAML by id."""
    return _load_custom_rule_impl(rule_id)


if __name__ == "__main__":
    server.run(transport="stdio")
