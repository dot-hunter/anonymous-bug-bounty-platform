#!/usr/bin/env python3
"""
Shodan MCP Server — Real FastMCP server for Shodan internet intelligence.
Provides tools for host discovery, service enumeration, and vulnerability research.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from mcp.server import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("shodan-mcp")

SHODAN = shutil.which("shodan")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


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
    "shodan",
    version="2026.1",
    description="Shodan internet intelligence MCP server — host discovery, service enumeration, vulnerability research",
    instructions="You are a Shodan intelligence assistant. Use the available tools to discover internet-facing assets, services, and potential vulnerabilities.",
)


@server.tool()
def search(query: str, limit: int = 10) -> dict:
    """Search Shodan for internet-facing devices.
    
    Args:
        query: Shodan search query (e.g., 'apache', 'port:22', 'org:"Example Inc"')
        limit: Maximum results to return
    """
    if not SHODAN_API_KEY:
        return {
            "error": "SHODAN_API_KEY environment variable not set",
            "hint": "Set SHODAN_API_KEY in your environment or .env file",
            "query": query,
        }
    
    if not SHODAN or not Path(SHODAN).exists():
        return {"error": "shodan CLI not installed", "hint": "pip install shodan"}
    
    rc, stdout, stderr = _run(
        [SHODAN, "search", "--fields", "ip_str,port,hostnames,org,isp,vuln,data", "--limit", str(limit), "--color", "never", query],
        timeout=30,
    )
    
    results = []
    if rc == 0 and stdout:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("Searching") and not line.startswith("Total"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    results.append({
                        "ip": parts[0] if len(parts) > 0 else "",
                        "port": parts[1] if len(parts) > 1 else "",
                        "hostnames": parts[2] if len(parts) > 2 else "",
                        "org": parts[3] if len(parts) > 3 else "",
                        "isp": parts[4] if len(parts) > 4 else "",
                        "vulns": parts[5] if len(parts) > 5 else "",
                        "data": parts[6][:200] if len(parts) > 6 else "",
                    })
    
    return {
        "query": query,
        "total_results": len(results),
        "results": results,
    }


@server.tool()
def host_info(ip: str) -> dict:
    """Get detailed information about a specific IP address."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set"}
    
    if not SHODAN or not Path(SHODAN).exists():
        return {"error": "shodan CLI not installed"}
    
    rc, stdout, stderr = _run(
        [SHODAN, "host", "--color", "never", ip],
        timeout=30,
    )
    
    if rc == 0 and stdout:
        return {"ip": ip, "info": stdout[:3000]}
    
    return {"ip": ip, "error": stderr[:500] if stderr else "No results"}


@server.tool()
def dns_resolve(hostname: str) -> dict:
    """Resolve hostname to IP addresses using Shodan DNS."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set"}
    
    if not SHODAN or not Path(SHODAN).exists():
        return {"error": "shodan CLI not installed"}
    
    rc, stdout, _ = _run([SHODAN, "dns", "resolve", hostname], timeout=15)
    
    ips = []
    if rc == 0 and stdout:
        ips = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
    
    return {"hostname": hostname, "ips": ips}


@server.tool()
def dns_reverse(ip: str) -> dict:
    """Reverse DNS lookup for an IP address."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set"}
    
    if not SHODAN or not Path(SHODAN).exists():
        return {"error": "shodan CLI not installed"}
    
    rc, stdout, _ = _run([SHODAN, "dns", "reverse", ip], timeout=15)
    
    hostnames = []
    if rc == 0 and stdout:
        hostnames = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
    
    return {"ip": ip, "hostnames": hostnames}


@server.tool()
def search_filters() -> dict:
    """List available Shodan search filters."""
    return {
        "filters": [
            "asn", "city", "country", "cpe", "device", "geo", "has_ipv6",
            "has_screenshot", "has_ssl", "has_vuln", "hash", "hostname",
            "ip", "isp", "link", "net", "org", "os", "port", "postal",
            "product", "region", "scan", "shodan.module", "state", "version",
            "vuln",
        ],
        "examples": [
            {"query": "apache", "description": "Find Apache servers"},
            {"query": "port:22", "description": "Find SSH services"},
            {"query": "org:\"Example Inc\"", "description": "Find assets by organization"},
            {"query": "ssl.cert.subject.cn:example.com", "description": "Find by SSL certificate"},
            {"query": "http.title:\"Login\"", "description": "Find by page title"},
            {"query": "product:\"WordPress\"", "description": "Find by product"},
        ],
    }


@server.tool()
def account_info() -> dict:
    """Get Shodan API account information."""
    if not SHODAN_API_KEY:
        return {"error": "SHODAN_API_KEY not set"}
    
    if not SHODAN or not Path(SHODAN).exists():
        return {"error": "shodan CLI not installed"}
    
    rc, stdout, _ = _run([SHODAN, "info"], timeout=15)
    
    return {
        "api_key_configured": True,
        "info": stdout[:1000] if rc == 0 else "Could not retrieve",
    }


if __name__ == "__main__":
    server.run(transport="stdio")
