#!/usr/bin/env python3
"""gf patterns integration: URL filtering and parameter extraction."""

from __future__ import annotations
import json
import logging
import re
import subprocess

logger = logging.getLogger("gf-patterns")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def _check_gf() -> bool:
    rc, _, _ = _run(["which", "gf"], timeout=5)
    return rc == 0


# Built-in gf-equivalent patterns (used when gf CLI is unavailable)
GF_PATTERNS = {
    "idor": [
        r"(?:id|user_id|account|account_id|uid|user|profile|member|client|customer|order|invoice|ticket|file_id|doc_id|res_id|resource|entity|ref|object_id)[=_/]",
        r"/api/.*/\d{3,}",
        r"(?:get|load|view|read|show|detail|download|export)[-_/]?(?:item|user|order|file|doc|record|profile)",
    ],
    "ssrf": [
        r"(?:url|uri|link|src|dest|redirect|target|callback|webhook|proxy|forward|next|path|endpoint|fetch|load|image_url|img|host|domain|dest_url|download)[=_/]",
    ],
    "xss": [
        r"(?:q|query|search|keyword|term|name|title|msg|message|comment|text|input|value|data|callback|jsonp|cb|return_url|redirect)[=_/]",
        r"<script|javascript:|onerror|onload|onclick|alert\(|document\.cookie",
    ],
    "sqli": [
        r"(?:id|user|name|email|search|q|query|type|page|sort|order|filter|category|cat|product|item|article|news|view)[=_/]",
    ],
    "redirect": [
        r"(?:redirect|return|return_url|rurl|dest|destination|next|target|url|link|out|go|jump|to)[=_/]",
    ],
    "lfi": [
        r"(?:file|filename|path|dir|page|template|include|doc|folder|style|lang|language|view|load|read|download)[=_/]",
        r"(?:\.\./|\.\.%2f|etc/passwd|\.php|\.txt|\.log)[=_/]",
    ],
    "rce": [
        r"(?:cmd|command|exec|run|shell|system|ping|host|ip|domain|nslookup|traceroute|whois)[=_/]",
    ],
    "ssti": [
        r"(?:template|tpl|view|page|name|content|message|welcome|greeting|theme|color)[=_/]",
        r"\{\{|\{%|#{",
    ],
    "interesting": [
        r"(?:api|v1|v2|admin|internal|private|debug|test|staging|dev|beta|swagger|graphql|_next|webpack|source|backup|config|env|token|key|secret|password|auth|login|signup|upload|export|import)[-_/]",
    ],
    "debug": [
        r"(?:debug|test|dev|beta|staging|qa|sandbox|internal|private|hidden|temp|tmp|backup|old|copy|\.bak|\.old|\.swp|\.git|\.env|config\.json|package\.json)",
    ],
}

PARAM_PRIORITY = {
    "idor": ["id", "user_id", "account_id", "uid", "order", "invoice", "file_id", "doc_id"],
    "ssrf": ["url", "uri", "link", "dest", "redirect", "webhook", "callback", "proxy", "image_url"],
    "xss": ["q", "search", "name", "title", "msg", "callback", "redirect"],
    "sqli": ["id", "name", "email", "search", "q", "type", "sort", "filter"],
    "redirect": ["redirect", "return_url", "next", "dest", "url"],
    "lfi": ["file", "filename", "path", "page", "include", "template"],
    "rce": ["cmd", "command", "exec", "ping", "host", "ip"],
}


def filter_urls_gf(urls: list, pattern_type: str = "idor") -> dict:
    """Filter URLs by gf-style pattern type. Accepts list of URLs."""
    patterns = GF_PATTERNS.get(pattern_type, GF_PATTERNS["interesting"])
    matched = []
    for u in urls:
        try:
            if any(re.search(p, u, re.IGNORECASE) for p in patterns):
                matched.append(u)
        except Exception:
            continue
    return {"type": pattern_type, "total": len(urls), "matched": len(matched), "urls": matched}


def run_gf_patterns(urls: list, pattern_types: list = None) -> dict:
    """Run gf patterns over a URL list. Uses gf CLI if installed, else built-in regexes."""
    if pattern_types is None:
        pattern_types = list(GF_PATTERNS.keys())

    results = {}
    if _check_gf():
        # Use gf CLI if available
        rc, stdout, _ = _run(["gf", "--list"], timeout=10)
        if rc == 0:
            results["gf_cli"] = "available"
    else:
        results["gf_cli"] = "not_installed_using_builtin"

    for pt in pattern_types:
        res = filter_urls_gf(urls, pt)
        results[pt] = res

    return results


def extract_interesting_params(urls: list) -> dict:
    """Extract and rank interesting parameters from URLs."""
    param_counts = {}
    for u in urls:
        try:
            query = u.split("?", 1)[1] if "?" in u else ""
            for pair in query.split("&"):
                if "=" in pair:
                    p = pair.split("=", 1)[0]
                    param_counts[p] = param_counts.get(p, 0) + 1
        except Exception:
            continue

    ranked = sorted(param_counts.items(), key=lambda x: -x[1])

    # Tag high-priority params
    priority_map = {}
    for vuln, params in PARAM_PRIORITY.items():
        for p in params:
            priority_map[p] = vuln

    tagged = []
    for p, count in ranked:
        tag = priority_map.get(p)
        if tag or count >= 2:
            tagged.append({"param": p, "count": count, "potential": tag})

    return {"total_params": len(param_counts), "interesting": tagged[:50]}
