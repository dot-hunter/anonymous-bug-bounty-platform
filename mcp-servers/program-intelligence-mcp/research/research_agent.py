"""
Research Agent — automatically create research dossiers.

Collects publicly available information:
  Official Documentation, Developer Documentation, API Documentation,
  OpenAPI, Swagger, GitHub, GitHub Organization, SDKs,
  Public NPM Packages, Mobile Apps, robots.txt, sitemap.xml,
  DNS, Certificate Transparency, Subdomains, Headers,
  Framework Detection, JavaScript, Public Endpoints,
  Cloud Providers, Authentication Flows.

Stores findings. Prevents duplicate research.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("program-intelligence.research")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class ResearchAgent:
    """Generates and manages research dossiers for programs."""

    def __init__(self, research_dir: Path | None = None):
        self.research_dir = research_dir or (DATA_DIR / "research")
        self.research_dir.mkdir(parents=True, exist_ok=True)

    def generate_dossier(self, program: dict, force: bool = False) -> dict:
        """Generate a research dossier for a program."""
        handle = program.get("handle", "")
        if not handle:
            return {"error": "Program has no handle"}

        dossier_path = self.research_dir / f"{handle}.json"

        # Check for cached dossier
        if not force and dossier_path.exists():
            try:
                cached = json.loads(dossier_path.read_text())
                # Use cache if less than 7 days old
                if time.time() - cached.get("generated_at", 0) < 604800:
                    cached["from_cache"] = True
                    return cached
            except (json.JSONDecodeError, OSError):
                pass

        # Generate fresh dossier
        dossier: dict[str, Any] = {
            "handle": handle,
            "name": program.get("name", ""),
            "platform": program.get("platform", ""),
            "generated_at": time.time(),
            "from_cache": False,
            "sections": {},
        }

        # ── Section 1: Official Documentation ─────────────────────────────
        docs = program.get("documentation", []) or []
        dev_docs = program.get("developer_docs", "") or []
        dossier["sections"]["documentation"] = {
            "official_docs": docs,
            "developer_docs": dev_docs,
            "sdks": program.get("sdks", []) or [],
        }

        # ── Section 2: GitHub Intelligence ────────────────────────────────
        github_repos = program.get("github", []) or []
        dossier["sections"]["github"] = {
            "known_repositories": github_repos,
            "notes": "Use agent-reach osint.github_search for org discovery and repo analysis.",
        }

        # ── Section 3: API & GraphQL ──────────────────────────────────────
        apis = program.get("public_apis", []) or []
        graphql = program.get("graphql", []) or []
        dossier["sections"]["api"] = {
            "public_apis": apis,
            "graphql_endpoints": graphql,
            "has_swagger": any("swagger" in str(a).lower() or "openapi" in str(a).lower() for a in apis),
        }

        # ── Section 4: Technology Stack ───────────────────────────────────
        tech_stack = program.get("technology_stack", []) or []
        intelligence = program.get("intelligence", {}) or {}
        dossier["sections"]["technology"] = {
            "known_stack": tech_stack,
            "inferred_frameworks": intelligence.get("frameworks", []),
            "inferred_cloud": intelligence.get("cloud_providers", []),
            "inferred_cdn": intelligence.get("cdn", []),
            "architecture_type": intelligence.get("architecture_type", ""),
        }

        # ── Section 5: Authentication ────────────────────────────────────
        auth = program.get("authentication", {}) or {}
        dossier["sections"]["authentication"] = {
            "known_auth_types": auth,
            "inferred_auth_methods": intelligence.get("auth_methods", []),
        }

        # ── Section 6: Assets & Scope ────────────────────────────────────
        dossier["sections"]["assets"] = {
            "domains": program.get("domains", []) or [],
            "wildcards": program.get("wildcards", []) or [],
            "subdomains": program.get("subdomains", []) or [],
            "cloud_assets": program.get("cloud_assets", {}) or {},
            "javascript_assets": program.get("javascript_assets", []) or [],
            "out_of_scope": program.get("out_of_scope", []) or [],
        }

        # ── Section 7: Recon Recommendations ─────────────────────────────
        dossier["sections"]["recon_recommendations"] = self._generate_recon_recommendations(program)

        # ── Section 8: Suggested Research Actions ────────────────────────
        dossier["sections"]["suggested_actions"] = self._generate_suggested_actions(program)

        # Save dossier
        try:
            dossier_path.write_text(json.dumps(dossier, indent=2, default=str))
        except OSError as exc:
            logger.warning("Failed to save dossier for %s: %s", handle, exc)

        return dossier

    def get_dossier(self, handle: str) -> dict | None:
        """Retrieve a cached dossier without regenerating."""
        dossier_path = self.research_dir / f"{handle}.json"
        if dossier_path.exists():
            try:
                return json.loads(dossier_path.read_text())
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def count_dossiers(self) -> int:
        """Count generated dossiers."""
        return len(list(self.research_dir.glob("*.json")))

    def _generate_recon_recommendations(self, program: dict) -> list[str]:
        """Generate recon recommendations based on program data."""
        recommendations = []

        domains = program.get("domains", []) or []
        wildcards = program.get("wildcards", []) or []

        if wildcards:
            recommendations.append(f"Wildcard scope detected ({len(wildcards)} wildcards) — broad attack surface")
            recommendations.append("Run subdomain enumeration: subfinder + amass on wildcard domains")

        if domains:
            recommendations.append(f"{len(domains)} explicit domains in scope — direct recon targets")

        intelligence = program.get("intelligence", {}) or {}
        graphql = program.get("graphql", []) or []
        if intelligence.get("has_graphql") or graphql:
            recommendations.append("GraphQL detected — prioritize GraphQL security testing (introspection, batching, IDOR)")

        if intelligence.get("has_rest_api"):
            recommendations.append("REST API detected — map API surface with swagger/openapi if available")

        if intelligence.get("cloud_providers"):
            providers = intelligence["cloud_providers"]
            recommendations.append(f"Cloud providers detected: {', '.join(providers)} — scan for misconfigurations")

        if intelligence.get("frameworks"):
            frameworks = intelligence["frameworks"]
            recommendations.append(f"Frameworks detected: {', '.join(frameworks)} — check for known CVEs")

        github_repos = program.get("github", []) or []
        if github_repos:
            recommendations.append(f"{len(github_repos)} known GitHub repos — audit for secrets and internal URLs")

        return recommendations

    def _generate_suggested_actions(self, program: dict) -> list[dict]:
        """Generate suggested research actions."""
        actions: list[dict] = []

        domains = program.get("domains", []) or []
        wildcards = program.get("wildcards", []) or []

        # DNS/Certificate Transparency
        if domains or wildcards:
            targets = domains[:3] + wildcards[:2]
            actions.append({
                "action": "certificate_transparency",
                "description": f"Query Certificate Transparency logs for subdomains",
                "targets": targets,
                "tool": "crt.sh or subfinder -d",
            })

        # robots.txt / sitemap.xml
        if domains:
            actions.append({
                "action": "robots_sitemap",
                "description": "Fetch robots.txt and sitemap.xml for hidden endpoints",
                "targets": domains[:3],
                "tool": "curl or agent-reach osint.web_fetch",
            })

        # GitHub search
        name = program.get("name", program.get("handle", ""))
        if name:
            actions.append({
                "action": "github_search",
                "description": f"Search GitHub for {name} repos, issues, and secrets",
                "targets": [name],
                "tool": "agent-reach osint.github_search",
            })

        # Wayback Machine
        if domains:
            actions.append({
                "action": "wayback_machine",
                "description": "Query Wayback Machine for historical URLs and endpoints",
                "targets": domains[:3],
                "tool": "recon.gau or waybackurls",
            })

        # JavaScript analysis
        js_assets = program.get("javascript_assets", []) or []
        if js_assets:
            actions.append({
                "action": "js_analysis",
                "description": f"Analyze {len(js_assets)} known JS assets for endpoints and secrets",
                "targets": js_assets[:5],
                "tool": "js.download/beautify/endpoints/secrets",
            })

        return actions
