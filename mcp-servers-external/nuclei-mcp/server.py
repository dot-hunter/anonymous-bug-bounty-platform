#!/usr/bin/env python3
"""
Nuclei MCP Server — Real FastMCP server for Nuclei template scanning.
Provides tools to scan targets using Nuclei vulnerability scanner.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mcp.server import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("nuclei-mcp")

NUCLEI = shutil.which("nuclei") or str(Path.home() / "go" / "bin" / "nuclei")
TEMPLATES_DIR = Path.home() / "nuclei-templates"


def _run(cmd, timeout=120, input=None):
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"
    except Exception as exc:
        return -1, "", str(exc)


server = MCPServer(
    "nuclei",
    version="2026.1",
    description="Nuclei vulnerability scanner MCP server — template-based scanning with custom profiles",
    instructions="You are a Nuclei scanning assistant. Use the available tools to scan targets for vulnerabilities using Nuclei templates.",
)


@server.tool()
def scan_target(target: str, templates: list = None, severity: str = "critical,high", output_format: str = "json") -> dict:
    """Scan a target using Nuclei templates.
    
    Args:
        target: URL or host to scan
        templates: List of template IDs or paths (optional)
        severity: Severity filter (critical,high,medium,low,info)
        output_format: Output format (json, markdown)
    """
    if not NUCLEI or not Path(NUCLEI).exists():
        return {"error": "nuclei not installed", "hint": "Install from https://github.com/projectdiscovery/nuclei"}
    
    cmd = [NUCLEI, "-u", target, "-severity", severity, "-silent", "-no-color"]
    
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    elif TEMPLATES_DIR.exists():
        cmd.extend(["-t", str(TEMPLATES_DIR)])
    
    if output_format == "json":
        cmd.extend(["-jsonl", "-include-rr"])
    
    rc, stdout, stderr = _run(cmd, timeout=300)
    
    findings = []
    if rc == 0 and stdout:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "template_id": entry.get("template-id", ""),
                    "type": entry.get("type", ""),
                    "severity": entry.get("info", {}).get("severity", "unknown"),
                    "host": entry.get("host", ""),
                    "matched": entry.get("matched-at", ""),
                    "request": entry.get("request", "")[:500],
                    "response": entry.get("response", "")[:500],
                    "name": entry.get("info", {}).get("name", ""),
                    "description": entry.get("info", {}).get("description", "")[:300],
                })
            except json.JSONDecodeError:
                findings.append({"raw": line[:500]})
    
    return {
        "target": target,
        "returncode": rc,
        "total_findings": len(findings),
        "findings": findings,
        "severity_filter": severity,
    }


@server.tool()
def list_templates(category: str = None) -> dict:
    """List available Nuclei templates."""
    if not TEMPLATES_DIR.exists():
        return {"templates_dir": str(TEMPLATES_DIR), "exists": False, "count": 0, "templates": []}
    
    templates = []
    for yaml_file in TEMPLATES_DIR.rglob("*.yaml"):
        rel_path = str(yaml_file.relative_to(TEMPLATES_DIR))
        if category and category not in rel_path:
            continue
        templates.append(rel_path)
    
    return {
        "templates_dir": str(TEMPLATES_DIR),
        "exists": True,
        "count": len(templates),
        "templates": templates[:200],  # Cap for context
    }


@server.tool()
def scan_with_profile(target: str, profile: str = "recommended") -> dict:
    """Scan target using a predefined profile.
    
    Profiles: recommended, critical, cves, exposures, misconfigurations, pentest
    """
    profile_flags = {
        "recommended": ["-profile", "recommended"],
        "critical": ["-severity", "critical"],
        "cves": ["-tags", "cve"],
        "exposures": ["-tags", "exposure"],
        "misconfigurations": ["-tags", "misconfig"],
        "pentest": ["-tags", "cve,misconfig,exposure,default-login"],
    }
    
    if not NUCLEI or not Path(NUCLEI).exists():
        return {"error": "nuclei not installed"}
    
    cmd = [NUCLEI, "-u", target, "-silent", "-no-color", "-jsonl"]
    cmd.extend(profile_flags.get(profile, ["-profile", "recommended"]))
    
    rc, stdout, stderr = _run(cmd, timeout=300)
    
    findings = []
    if rc == 0 and stdout:
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                findings.append({
                    "template_id": entry.get("template-id", ""),
                    "severity": entry.get("info", {}).get("severity", "unknown"),
                    "host": entry.get("host", ""),
                    "name": entry.get("info", {}).get("name", ""),
                    "matched": entry.get("matched-at", ""),
                })
            except json.JSONDecodeError:
                pass
    
    return {
        "target": target,
        "profile": profile,
        "total_findings": len(findings),
        "findings": findings,
    }


@server.tool()
def update_templates() -> dict:
    """Update Nuclei templates to latest version."""
    if not NUCLEI or not Path(NUCLEI).exists():
        return {"error": "nuclei not installed"}
    
    rc, stdout, stderr = _run([NUCLEI, "-update-templates"], timeout=120)
    
    return {
        "updated": rc == 0,
        "output": stdout[:2000],
        "errors": stderr[:1000] if stderr else None,
    }


@server.tool()
def get_version() -> dict:
    """Get Nuclei version information."""
    if not NUCLEI or not Path(NUCLEI).exists():
        return {"installed": False}
    
    rc, stdout, _ = _run([NUCLEI, "-version"], timeout=10)
    return {
        "installed": True,
        "version": stdout.strip() if rc == 0 else "unknown",
    }


if __name__ == "__main__":
    server.run(transport="stdio")
