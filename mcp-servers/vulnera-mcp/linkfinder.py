#!/usr/bin/env python3
"""LinkFinder-style JS endpoint extraction."""

from __future__ import annotations
import json
import logging
import re
import subprocess

logger = logging.getLogger("linkfinder")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


# LinkFinder-style regexes (mirrors gerbenavdberg/LinkFinder endpoints.py)
ENDPOINT_PATTERNS = [
    (r"(?:https?://)?(?:\w+\.)?[\w\-\.]+\.\w+(?:/\S*)?", "full_url"),
    (r"/(?:api|v\d+|rest|graphql|admin|internal|private|ws|wss|socket|webhook|callback|oauth|auth|token|upload|download|export|import|search|query|debug|test)[^\s\"'`<>]*", "api_path"),
    (r"/[\w\-\.]+\.(?:js|json|xml|php|asp|aspx|jsp|do|action|cgi|py|rb|go|java|jar|war|wsdl|yaml|yml)[^\s\"'`<>]*", "file_ext"),
    (r"(?:fetch|axios|XMLHttpRequest|WebSocket|EventSource|$.ajax|$.get|$.post)\s*\(\s*[\"']([^\"']+)[\"']", "http_call"),
    (r"(?:url|endpoint|href|src|action|path|target|api|baseURL|baseUrl)\s*[:=]\s*[\"']([^\"']+)[\"']", "config_url"),
    (r"/(?:v\d+(?:\.\d+)?)(?:/[\w\-\.{}]+)+", "versioned_route"),
    (r"(?:get|post|put|delete|patch|head|options)\s*\(\s*[\"']([^\"']+)[\"']", "method_call"),
]

SECRET_PATTERNS = [
    (r"(?:api[_-]?key|apikey|secret|token|auth|bearer|password|passwd|pwd|client[_-]?secret|access[_-]?key)\s*[:=]\s*[\"'][^\"']{8,}[\"']", "secret_assignment"),
    (r"AIza[0-9A-Za-z\-_]{35}", "gcp_api_key"),
    (r"AKIA[0-9A-Z]{16}", "aws_access_key"),
    (r"sk-[0-9A-Za-z]{20,}", "openai_key"),
    (r"ghp_[0-9A-Za-z]{36}", "github_token"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "slack_token"),
]


def extract_from_js(js_url: str) -> dict:
    """Download a JS file and extract endpoints + secrets (LinkFinder-style)."""
    findings = {"js_url": js_url, "endpoints": [], "secrets": [], "parameters": [], "error": None}

    rc, stdout, _ = _run(["curl", "-s", "--max-time", "15", "-L", js_url], timeout=20)
    if rc != 0 or not stdout:
        findings["error"] = "failed to fetch JS"
        return findings

    content = stdout
    findings["size_bytes"] = len(content)

    # Extract endpoints
    seen = set()
    for pattern, ptype in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            ep = m.group(1) if m.groups() else m.group(0)
            if ep and ep not in seen and len(ep) < 300:
                seen.add(ep)
                findings["endpoints"].append({"type": ptype, "value": ep})

    # Extract secrets
    for pattern, stype in SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            findings["secrets"].append({"type": stype, "match": m.group(0)[:80]})

    # Extract parameter names from object literals
    params = set(re.findall(r"(?:params|query|data)\s*[:=]\s*\{\s*([^}]{5,500})\s*\}", content, re.IGNORECASE))
    for block in params:
        for p in re.findall(r"[\"']?(\w+)[\"']?\s*:", block):
            if len(p) > 2 and p not in ("true", "false", "null", "undefined"):
                findings["parameters"].append(p)

    # Dedupe endpoints by value
    unique = {}
    for e in findings["endpoints"]:
        unique.setdefault(e["value"], e)
    findings["endpoints"] = list(unique.values())
    findings["unique_endpoints"] = len(findings["endpoints"])

    return findings


def crawl_js_urls(base_url: str, js_hints: list = None) -> dict:
    """Crawl a page for JS files, then extract endpoints from each."""
    results = {"base_url": base_url, "js_files": [], "all_endpoints": [], "all_secrets": []}

    # If no hints, crawl the page
    if not js_hints:
        rc, stdout, _ = _run(["curl", "-s", "--max-time", "10", "-L", base_url], timeout=15)
        if rc == 0 and stdout:
            js_hints = list(set(re.findall(r"(?:src|href)=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", stdout, re.IGNORECASE)))

    for hint in js_hints:
        if hint.startswith("//"):
            hint = "https:" + hint
        elif hint.startswith("/"):
            from urllib.parse import urlparse
            parsed = urlparse(base_url)
            hint = f"{parsed.scheme}://{parsed.netloc}{hint}"
        elif not hint.startswith("http"):
            from urllib.parse import urlparse, urljoin
            hint = urljoin(base_url, hint)

        results["js_files"].append(hint)
        extraction = extract_from_js(hint)
        if extraction.get("error"):
            continue
        results["all_endpoints"].extend(extraction.get("endpoints", []))
        results["all_secrets"].extend(extraction.get("secrets", []))

    # Dedupe
    seen_ep, seen_sec = set(), []
    for ep in results["all_endpoints"]:
        if ep["value"] not in seen_ep:
            seen_ep.add(ep["value"])
            seen_sec.append(ep) if False else None
    results["all_endpoints"] = [e for e in results["all_endpoints"] if e["value"] in seen_ep or True]
    # proper dedupe
    deduped_ep, seen = [], set()
    for e in results["all_endpoints"]:
        if e["value"] not in seen:
            seen.add(e["value"])
            deduped_ep.append(e)
    results["all_endpoints"] = deduped_ep
    results["all_secrets"] = list({s["match"]: s for s in results["all_secrets"]}.values())
    results["total_endpoints"] = len(results["all_endpoints"])
    results["total_secrets"] = len(results["all_secrets"])

    return results
