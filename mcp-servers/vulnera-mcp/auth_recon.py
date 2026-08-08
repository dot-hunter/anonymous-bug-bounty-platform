#!/usr/bin/env python3
"""Authenticated recon: session-based testing support."""

from __future__ import annotations
import json
import logging
import os
import subprocess

logger = logging.getLogger("auth-recon")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def _load_session(session_file: str) -> dict:
    """Load session from a JSON cookie file (Nuclei/burp-style)."""
    try:
        with open(session_file) as f:
            return json.load(f)
    except Exception:
        return {}


def build_curl_args(session: dict) -> list:
    """Convert a session dict into curl -H args.

    Session format:
    {"cookies": {"session": "abc123", "csrf": "xyz"},
     "headers": {"Authorization": "Bearer xxx", "X-CSRF-Token": "yyy"},
     "base_url": "https://app.example.com"}
    """
    args = []
    cookies = session.get("cookies", {})
    headers = session.get("headers", {})

    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        args.extend(["-H", f"Cookie: {cookie_str}"])

    for k, v in headers.items():
        args.extend(["-H", f"{k}: {v}"])

    return args


def session_recon(target: str, session_file: str, urls: list = None) -> dict:
    """Authenticated recon: probe URLs with session cookies/headers.

    Discovers endpoints that are only reachable when authenticated
    (401/403 anonymous vs 200/302 with session).
    """
    findings = []

    if not os.path.isfile(session_file):
        return {"type": "auth_recon", "error": f"session file not found: {session_file}"}

    session = _load_session(session_file)
    curl_args = build_curl_args(session)
    if not curl_args:
        return {"type": "auth_recon", "error": "no cookies or headers in session file"}

    if not urls:
        urls = [target]

    for url in urls:
        # Anonymous baseline
        rc_anon, out_anon, _ = _run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", url],
            timeout=10,
        )
        # Authenticated request
        rc_auth, out_auth, _ = _run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5"] + curl_args + [url],
            timeout=10,
        )

        anon_code = out_anon.strip()
        auth_code = out_auth.strip()

        if anon_code in ("401", "403") and auth_code in ("200", "302", "404"):
            findings.append(
                {
                    "type": "auth_gated_endpoint",
                    "url": url,
                    "anonymous": anon_code,
                    "authenticated": auth_code,
                    "severity": "info",
                    "detail": "Endpoint requires auth - now accessible with session. Test for BOLA/BFLA here.",
                }
            )
        elif anon_code == auth_code and anon_code == "200":
            findings.append(
                {
                    "type": "auth_not_required",
                    "url": url,
                    "status": anon_code,
                    "severity": "info",
                    "detail": "Endpoint accessible without auth - verify if data exposure is intended.",
                }
            )
        elif anon_code in ("200", "302") and auth_code in ("401", "403"):
            findings.append(
                {
                    "type": "session_rejected",
                    "url": url,
                    "anonymous": anon_code,
                    "authenticated": auth_code,
                    "severity": "medium",
                    "detail": "Authenticated request rejected - session may be invalid/expired or WAF filtering.",
                }
            )

    return {"type": "auth_recon", "vulnerable": None, "findings": findings, "session_keys": list(session.keys())}


def auth_bola_primer(target: str, session_file: str, base_urls: list = None) -> dict:
    """Generate a BOLA/BFLA test plan for authenticated endpoints.

    Given a session file and base URLs, produces the IDOR test matrix:
    object IDs to swap, admin-vs-user role checks, and method-level BFLA probes.
    """
    plan = {
        "session_file": session_file,
        "bola_matrix": [
            {
                "pattern": "sequential_object_id",
                "test": "Replace object ID in URL/body with neighboring IDs (id=1,2,3...) and check for cross-user data",
                "check": "Response contains another user's data (name, email, PII) -> BOLA",
            },
            {
                "pattern": "uuid_known",
                "test": "If UUIDs used, test unguessability by checking UUIDv1 timestamps or leaked IDs in JS/emails",
                "check": "Predictable UUIDs -> BOLA",
            },
            {
                "pattern": "batch_ids",
                "test": "Send array of IDs: {\"ids\": [\"1\",\"2\",\"3\"]} to bulk endpoints",
                "check": "Bulk data returned -> batch BOLA",
            },
        ],
        "bfla_matrix": [
            {
                "pattern": "role_upgrade",
                "test": "Call admin endpoints (/api/admin/users) with normal user session",
                "check": "200 instead of 403 -> BFLA",
            },
            {
                "pattern": "method_swap",
                "test": "Swap GET->POST/PUT/DELETE on user endpoints",
                "check": "State change allowed -> BFLA",
            },
            {
                "pattern": "hidden_admin_api",
                "test": "Probe /api/v1/admin/*, /internal/*, /manage/* with user session",
                "check": "Access granted -> BFLA",
            },
        ],
        "recommended_next": "Use test_bola / test_bfla tools against endpoints from session_recon output",
    }

    if base_urls:
        plan["target_urls"] = base_urls

    return {"type": "auth_bola_primer", "plan": plan}
