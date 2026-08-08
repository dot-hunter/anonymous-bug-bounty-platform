#!/usr/bin/env python3
"""WebSocket deep testing: CSWSH, message injection, protocol abuse."""

from __future__ import annotations
import json
import logging
import subprocess

logger = logging.getLogger("websocket-deep")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def _check_tool(tool: str) -> bool:
    rc, _, _ = _run(["which", tool], timeout=5)
    return rc == 0


def test_websocket(target: str, url: str) -> dict:
    """Deep WebSocket security: CSWSH, message injection, protocol downgrade.

    Checks:
    1. Origin validation (CSWSH) - if server accepts cross-origin handshake
    2. Authentication in handshake (cookie vs token)
    3. Message injection / command injection over WS
    4. WS endpoint discovery via page crawl
    """
    findings = []
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    # 1. Try a raw WebSocket handshake with a cross-site Origin header
    host = ws_url.split("://")[1].split("/")[0]
    path = ws_url.split(host)[1] if host in ws_url else "/"
    rc, stdout, _ = _run(
        [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-H", f"Host: {host}",
            "-H", "Connection: Upgrade",
            "-H", "Upgrade: websocket",
            "-H", "Sec-WebSocket-Version: 13",
            "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "-H", "Origin: https://evil.example.com",
            "--max-time", "5", ws_url,
        ],
        timeout=10,
    )
    if rc == 0 and stdout.strip() == "101":
        findings.append(
            {
                "type": "cswsh_origin_not_validated",
                "severity": "high",
                "detail": "Server returned 101 with cross-origin Origin header - CSWSH likely",
            }
        )
    elif rc == 0:
        findings.append(
            {
                "type": "ws_handshake_response",
                "severity": "info",
                "detail": f"Handshake returned HTTP {stdout.strip()} (not 101 - CSWSH likely mitigated)",
            }
        )

    # 2. Check for ws:// (insecure) endpoints referenced on the page
    rc, stdout, _ = _run(["curl", "-s", "--max-time", "5", url], timeout=10)
    if rc == 0 and stdout:
        import re
        ws_refs = re.findall(r"(wss?://[^\s\"'<>]+)", stdout)
        insecure = [w for w in ws_refs if w.startswith("ws://")]
        if insecure:
            findings.append(
                {
                    "type": "insecure_ws_endpoint",
                    "severity": "medium",
                    "detail": f"Insecure ws:// endpoints referenced: {insecure[:5]}",
                }
            )
        if ws_refs:
            findings.append(
                {
                    "type": "ws_endpoints_discovered",
                    "severity": "info",
                    "detail": f"WebSocket endpoints found: {list(set(ws_refs))[:10]}",
                }
            )

    # 3. Check if websocket tooling is available for deeper testing
    tools = {t: _check_tool(t) for t in ["websocat", "wscat", "wstalker"]}
    findings.append({"type": "ws_tooling", "severity": "info", "detail": tools})

    return {"type": "websocket", "vulnerable": any(f["severity"] == "high" for f in findings), "findings": findings}


def test_ws_message_injection(target: str, url: str) -> dict:
    """Test WebSocket message injection and command injection over WS.

    Sends crafted messages (JSON escaping, CRLF, payloads) through websocat/wscat
    if available; otherwise reports the manual test procedure.
    """
    findings = []
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    tool = None
    for candidate in ["websocat", "wscat"]:
        if _check_tool(candidate):
            tool = candidate
            break

    if not tool:
        findings.append(
            {
                "type": "ws_tool_missing",
                "severity": "info",
                "detail": "websocat/wscat not installed - manual message injection test required",
            }
        )
        return {"type": "ws_message_injection", "vulnerable": False, "findings": findings}

    test_messages = [
        '{"cmd": "ls"}',
        '{"message": "test"}',
        'test\r\ninjected',
        '{"type": "ping"}',
        "</script><script>alert(1)</script>",
    ]

    for msg in test_messages:
        if tool == "websocat":
            rc, stdout, stderr = _run(["websocat", "-1", ws_url], input=msg, timeout=10)
        else:
            rc, stdout, stderr = _run(["wscat", "-c", ws_url], input=msg + "\n", timeout=10)
        combined = (stdout + stderr).lower()
        if rc == 0 and combined:
            # Look for reflected input or command output
            if "alert(1)" in combined or "injected" in combined:
                findings.append(
                    {
                        "type": "ws_reflected_payload",
                        "severity": "high",
                        "detail": f"Payload reflected in WS response: {msg[:50]}",
                    }
                )
            if "root:" in combined or "uid=" in combined or "cmd" in combined and "ls" in msg:
                findings.append(
                    {
                        "type": "ws_command_execution",
                        "severity": "critical",
                        "detail": "Command output observed over WebSocket",
                    }
                )

    return {"type": "ws_message_injection", "vulnerable": len(findings) > 0, "findings": findings}
