#!/usr/bin/env python3
"""CSRF, Cache Poisoning, 403 Bypass tests."""

from __future__ import annotations
import logging
import subprocess

logger = logging.getLogger("web-attacks")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def test_csrf(target: str, url: str) -> dict:
    """Test for CSRF vulnerabilities."""
    findings = []

    # Check for SameSite cookie attribute
    rc, stdout, _ = _run(
        ["curl", "-s", "-I", "--max-time", "5", url],
        timeout=10,
    )
    if rc == 0 and stdout:
        set_cookie_found = False
        samesite_found = False
        for line in stdout.split("\n"):
            if "set-cookie" in line.lower():
                set_cookie_found = True
                if "samesite" in line.lower():
                    samesite_found = True
                    break
        if set_cookie_found and not samesite_found:
            findings.append({"type": "csrf_no_samesite", "severity": "medium"})

    return {"type": "csrf", "vulnerable": len(findings) > 0, "findings": findings}


def test_cache_poisoning(target: str, url: str) -> dict:
    """Test cache poisoning via unkeyed headers."""
    findings = []

    unkeyed_headers = [
        "X-Forwarded-Host", "X-Forwarded-For", "X-Forwarded-Proto",
        "X-Host", "X-Custom-IP-Authorization", "X-Original-URL", "X-Rewrite-URL",
    ]

    for header in unkeyed_headers:
        rc, stdout, _ = _run(
            ["curl", "-s", "--max-time", "5", "-H", f"{header}: evil.com", url],
            timeout=10,
        )
        if rc == 0 and stdout and "evil.com" in stdout:
            findings.append({"type": "cache_poisoning", "header": header, "severity": "high"})

    return {"type": "cache_poisoning", "vulnerable": len(findings) > 0, "findings": findings}


def test_403_bypass(target: str, url: str) -> dict:
    """Test 403 Forbidden bypass techniques."""
    findings = []

    bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]

    for headers in bypass_headers:
        hdr_args = []
        for k, v in headers.items():
            hdr_args.extend(["-H", f"{k}: {v}"])
        rc, stdout, _ = _run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}"] + hdr_args + ["--max-time", "5", url],
            timeout=10,
        )
        if rc == 0 and stdout.strip() == "200":
            findings.append({"type": "403_bypass", "headers": list(headers.keys()), "severity": "high"})

    # Path-based bypasses
    for suffix in ["/%2e/admin", "/admin/.", "/Admin", "/admin?", "/admin#", "/admin;/"]:
        rc, stdout, _ = _run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", url + suffix],
            timeout=5,
        )
        if rc == 0 and stdout.strip() == "200":
            findings.append({"type": "403_bypass_path", "suffix": suffix, "severity": "high"})

    return {"type": "403_bypass", "vulnerable": len(findings) > 0, "findings": findings}
