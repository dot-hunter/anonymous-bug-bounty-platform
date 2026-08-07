#!/usr/bin/env python3
"""AppProfile Builder — Flow mapping + trust boundary analysis (P1-B)."""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("app-profile")


def build_app_profile(target: str, live_hosts: list, js_endpoints: list, api_schema: dict = None) -> dict:
    """Build a structured application profile before dispatching specialist tests.
    
    Maps application flows, identifies trust boundaries, and identifies
    high-value parameters for targeted testing.
    
    Args:
        target: Target domain
        live_hosts: List of live host URLs from recon
        js_endpoints: List of endpoints extracted from JavaScript
        api_schema: Optional OpenAPI/GraphQL schema dict
    
    Returns:
        Structured AppProfile dict
    """
    profile = {
        "target": target,
        "tech_stack": _detect_tech_stack(live_hosts, api_schema),
        "trust_boundaries": _identify_trust_boundaries(live_hosts, js_endpoints),
        "high_value_parameters": _identify_high_value_params(js_endpoints, api_schema),
        "hypothesis_targets": [],
        "authentication_detected": _detect_auth(live_hosts, js_endpoints),
        "api_version_detected": _detect_api_versions(js_endpoints),
    }

    # Generate hypothesis targets from profile
    profile["hypothesis_targets"] = _generate_hypothesis_targets(profile)

    return profile


def _detect_tech_stack(live_hosts: list, api_schema: dict = None) -> list:
    """Detect technology stack from live hosts and schema."""
    techs = []
    tech_signatures = {
        "Next.js": ["_next/", "next.js"],
        "React": ["react", "reactdom"],
        "Vue": ["vue.js", "vue-router"],
        "Angular": ["angular", "ng-"],
        "Spring Boot": ["actuator", "spring"],
        "Django": ["django", "csrfmiddlewaretoken"],
        "Flask": ["flask", "werkzeug"],
        "Express": ["express", "x-powered-by: Express"],
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "GraphQL": ["graphql", "__typename"],
        "PostgreSQL": ["postgresql", "psql"],
        "MySQL": ["mysql", "mariadb"],
        "MongoDB": ["mongodb", "mongoose"],
        "Redis": ["redis", "rediscloud"],
        "AWS": ["amazonaws", "aws.amazon", "cloudfront"],
        "GCP": ["googleapis", "appspot", "google cloud"],
        "Azure": ["azure", "azurewebsites", "microsoft"],
    }

    all_text = " ".join(live_hosts).lower()
    if api_schema:
        all_text += " " + json.dumps(api_schema).lower()

    for tech, signatures in tech_signatures.items():
        for sig in signatures:
            if sig.lower() in all_text:
                techs.append(tech)
                break

    return list(set(techs))


def _identify_trust_boundaries(live_hosts: list, js_endpoints: list) -> list:
    """Identify trust boundaries from endpoints."""
    boundaries = []

    # Check for auth-related endpoints
    auth_patterns = ["/login", "/auth", "/oauth", "/signin", "/token", "/session"]
    admin_patterns = ["/admin", "/manage", "/dashboard", "/control", "/moderator"]
    api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]

    all_endpoints = " ".join(live_hosts + js_endpoints).lower()

    has_auth = any(p in all_endpoints for p in auth_patterns)
    has_admin = any(p in all_endpoints for p in admin_patterns)
    has_api = any(p in all_endpoints for p in api_patterns)

    if has_auth:
        boundaries.append("unauthenticated → authenticated")
    if has_admin:
        boundaries.append("user → admin")
    if has_api:
        boundaries.append("client → API server")

    # Check for multi-tenant indicators
    tenant_patterns = ["/org/", "/team/", "/workspace/", "/tenant/", "/account/"]
    if any(p in all_endpoints for p in tenant_patterns):
        boundaries.append("tenant → tenant")

    return boundaries


def _identify_high_value_params(js_endpoints: list, api_schema: dict = None) -> list:
    """Identify high-value parameters for targeted testing."""
    high_value = []

    # IDOR candidates
    id_params = ["id", "user_id", "order_id", "account_id", "document_id", "file_id", "report_id"]
    for ep in js_endpoints:
        for param in id_params:
            if param in ep.lower():
                high_value.append({
                    "url": ep,
                    "param": param,
                    "type": "IDOR_CANDIDATE",
                    "priority": "high",
                })

    # SSRF candidates
    ssrf_params = ["url", "uri", "link", "src", "redirect", "callback", "webhook", "feed"]
    for ep in js_endpoints:
        for param in ssrf_params:
            if param in ep.lower():
                high_value.append({
                    "url": ep,
                    "param": param,
                    "type": "SSRF_CANDIDATE",
                    "priority": "high",
                })

    # SQLi candidates
    sqli_params = ["sort", "order", "filter", "search", "query", "category", "page"]
    for ep in js_endpoints:
        for param in sqli_params:
            if param in ep.lower():
                high_value.append({
                    "url": ep,
                    "param": param,
                    "type": "SQLI_CANDIDATE",
                    "priority": "medium",
                })

    return high_value


def _detect_auth(live_hosts: list, js_endpoints: list) -> dict:
    """Detect authentication mechanisms."""
    all_text = " ".join(live_hosts + js_endpoints).lower()
    auth = {
        "detected": False,
        "type": None,
        "endpoints": [],
    }

    if "jwt" in all_text or "bearer" in all_text or "authorization" in all_text:
        auth["detected"] = True
        auth["type"] = "bearer_token"
    if "session" in all_text or "cookie" in all_text:
        auth["detected"] = True
        auth["type"] = auth["type"] or "session_cookie"
    if "api_key" in all_text or "apikey" in all_text:
        auth["detected"] = True
        auth["type"] = auth["type"] or "api_key"

    return auth


def _detect_api_versions(js_endpoints: list) -> list:
    """Detect API versions from endpoints."""
    versions = []
    for ep in js_endpoints:
        if "/v1/" in ep or "/v1?" in ep:
            versions.append("v1")
        if "/v2/" in ep or "/v2?" in ep:
            versions.append("v2")
        if "/v3/" in ep or "/v3?" in ep:
            versions.append("v3")
    return list(set(versions))


def _generate_hypothesis_targets(profile: dict) -> list:
    """Generate hypothesis targets from the AppProfile."""
    targets = []

    # IDOR targets
    for param in profile.get("high_value_parameters", []):
        if param["type"] == "IDOR_CANDIDATE":
            targets.append({
                "type": "idor",
                "url": param["url"],
                "param": param["param"],
                "confidence": 0.5,
            })

    # SSRF targets
    for param in profile.get("high_value_parameters", []):
        if param["type"] == "SSRF_CANDIDATE":
            targets.append({
                "type": "ssrf",
                "url": param["url"],
                "param": param["param"],
                "confidence": 0.4,
            })

    # SQLi targets
    for param in profile.get("high_value_parameters", []):
        if param["type"] == "SQLI_CANDIDATE":
            targets.append({
                "type": "sqli",
                "url": param["url"],
                "param": param["param"],
                "confidence": 0.3,
            })

    # Auth-based targets
    if profile.get("authentication_detected", {}).get("detected"):
        targets.append({
            "type": "auth_bypass",
            "description": "Test authentication bypass via method switching",
            "confidence": 0.3,
        })

    # API version targets
    versions = profile.get("api_version_detected", [])
    if len(versions) > 1:
        targets.append({
            "type": "api_version_fallback",
            "description": f"Older API versions {versions[:-1]} may lack auth checks present in {versions[-1]}",
            "confidence": 0.4,
        })

    return targets
