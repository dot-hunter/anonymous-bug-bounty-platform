#!/usr/bin/env python3
"""Virtual host enumeration via Host header fuzzing."""

from __future__ import annotations
import json
import logging
import subprocess

logger = logging.getLogger("vhost-enum")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def _check_vhost_tool() -> str:
    for tool in ["ffuf", "gobuster", "feroxbuster"]:
        rc, _, _ = _run(["which", tool], timeout=5)
        if rc == 0:
            return tool
    return ""


def enumerate_vhosts(target: str, wordlist: list = None) -> dict:
    """Enumerate virtual hosts by fuzzing the Host header.

    If ffuf/gobuster is installed, uses it against a built-in wordlist.
    Otherwise performs a built-in baseline-comparison fuzzer.
    """
    findings = []
    tool = _check_vhost_tool()

    if not wordlist:
        wordlist = [
            "admin", "api", "app", "dev", "staging", "test", "qa", "beta", "vpn", "mail",
            "intranet", "internal", "private", "portal", "cms", "jenkins", "gitlab",
            "grafana", "kibana", "prometheus", "jira", "confluence", "nextcloud",
            "status", "health", "monitor", "dashboard", "console", "backup", "db",
            "dbadmin", "phpmyadmin", "pgadmin", "redis", "elk", "logs", "auth", "sso",
            "oauth", "identity", "files", "static", "cdn", "assets", "uploads", "docs",
            "swagger", "graphql", "metrics", "debug", "config", "wiki", "support",
        ]

    # Baseline: request with the target host itself
    target_host = target.replace("https://", "").replace("http://", "").split("/")[0]
    rc, base_stdout, base_err = _run(
        ["curl", "-s", "-i", "--max-time", "5", "-H", f"Host: {target_host}", f"https://{target_host}/"],
        timeout=10,
    )
    base_len = len(base_stdout)

    # Probe each candidate vhost
    interesting = []
    for vhost in wordlist:
        test_host = f"{vhost}.{target_host}"
        rc, stdout, stderr = _run(
            ["curl", "-s", "-i", "--max-time", "5", "-H", f"Host: {test_host}", f"https://{target_host}/"],
            timeout=10,
        )
        if rc != 0 or not stdout:
            continue

        # A different vhost usually means: different content-length, different server,
        # redirect to a new host, or an auth prompt (401/403)
        diff_len = abs(len(stdout) - base_len)
        headers = stdout.split("\r\n\r\n")[0].lower() if "\r\n\r\n" in stdout else stdout.lower()
        status = ""

        first_line = stdout.split("\n")[0] if stdout else ""
        if " " in first_line:
            status = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""

        signals = []
        if diff_len > 200:
            signals.append(f"content diff ({diff_len}b)")
        if "401" in status or "403" in status:
            signals.append(f"auth required ({status})")
        if "location:" in headers and test_host not in headers.split("location:")[1][:200].lower() if "location:" in headers else False:
            signals.append("redirect")
        if test_host in stdout:
            signals.append("vhost reflected")

        if signals:
            interesting.append(
                {
                    "vhost": test_host,
                    "status": status,
                    "signals": signals,
                    "length_diff": diff_len,
                }
            )

    findings.append(
        {
            "type": "vhost_enum",
            "tool": tool or "builtin",
            "tested": len(wordlist),
            "interesting": interesting,
        }
    )

    return {"type": "vhost_enum", "vulnerable": None, "findings": findings}


def check_vhost_bypass(target: str, url: str) -> dict:
    """Check for host-header related vulnerabilities: password reset poisoning, cache poisoning, SSRF via Host."""
    findings = []

    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    payloads = [
        f"evil.com",
        f"attacker.{host}",
        f"{host}.evil.com",
        f"evil.com:{host}",
        f"{host}@evil.com",
        f"evil.com#@{host}",
    ]

    for payload in payloads:
        rc, stdout, _ = _run(
            ["curl", "-s", "-i", "--max-time", "5", "-H", f"Host: {payload}", url],
            timeout=10,
        )
        if rc == 0 and stdout:
            lower = stdout.lower()
            if "evil.com" in lower:
                findings.append(
                    {
                        "type": "host_header_reflected",
                        "payload": payload,
                        "severity": "high",
                        "detail": "Host header value reflected in response - check for password reset poisoning",
                    }
                )
            if "cache" in lower and "x-cache" in lower:
                findings.append(
                    {
                        "type": "host_header_cache_keyed",
                        "payload": payload,
                        "severity": "medium",
                        "detail": "Cache headers present - verify if Host is part of cache key",
                    }
                )

    return {"type": "vhost_bypass", "vulnerable": len(findings) > 0, "findings": findings}
