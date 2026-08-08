"""
Program Enricher — automatically enrich programs with inferred technology intelligence.

Infers: Frameworks, Cloud Providers, CDN, JavaScript Libraries, Authentication,
GraphQL, REST APIs, SPA, Microservices, Mobile Backends, Technology fingerprints.

NEVER overwrites discovered data. Only appends intelligence.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("program-intelligence.enrichment")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Technology fingerprint database ───────────────────────────────────────────
# Maps patterns to technology categories for inference

FRAMEWORK_PATTERNS = {
    # Web frameworks
    "react": ["react", "reactjs", "react.js", "jsx", "next.js", "nextjs", "gatsby"],
    "angular": ["angular", "angularjs", "angular.js", "ng-"],
    "vue": ["vue", "vuejs", "vue.js", "nuxt", "nuxtjs"],
    "svelte": ["svelte", "sveltekit"],
    "django": ["django", "django-rest", "drf"],
    "flask": ["flask", "jinja2"],
    "rails": ["rails", "ruby-on-rails", "erb"],
    "laravel": ["laravel", "blade", "php"],
    "express": ["express", "expressjs", "node.js", "nodejs"],
    "fastapi": ["fastapi", "pydantic"],
    "spring": ["spring", "spring-boot", "springboot"],
    "aspnet": ["asp.net", "dotnet", ".net", "csharp"],
    "go": ["golang", "go-"],
}

CLOUD_PATTERNS = {
    "aws": ["amazonaws", "aws", "amazon", "cloudfront", "s3.amazonaws"],
    "gcp": ["googleapis", "google-cloud", "gcloud", "appspot", "googleusercontent"],
    "azure": ["azure", "microsoftonline", "windows.net", "azurewebsites"],
    "cloudflare": ["cloudflare", "cf-dns", "cdnjs"],
    "heroku": ["heroku", "herokuapp"],
    "vercel": ["vercel", "vercel.app"],
    "netlify": ["netlify", "netlify.app"],
}

CDN_PATTERNS = {
    "cloudflare": ["cloudflare", "cdnjs.cloudflare.com"],
    "akamai": ["akamai", "akamaized", "akamaihd"],
    "fastly": ["fastly", "fastly.net"],
    "amazon_cloudfront": ["cloudfront.net"],
    "google_cdn": ["googleapis.com", "gstatic.com"],
    "jsdelivr": ["jsdelivr.net"],
    "unpkg": ["unpkg.com"],
}

AUTH_PATTERNS = {
    "oauth": ["oauth", "oauth2", "openid", "openid-connect"],
    "jwt": ["jwt", "json-web-token", "bearer"],
    "saml": ["saml", "saml2", "okta", "onelogin"],
    "mfa": ["mfa", "2fa", "totp", "authenticator", "duo"],
    "basic_auth": ["basic-auth", "www-authenticate"],
    "api_key": ["api-key", "x-api-key", "apikey"],
    "session": ["session", "cookie", "set-cookie"],
}

GRAPHQL_INDICATORS = ["graphql", "/graphql", "graphql-api", "apollo", "hasura", "gql"]

SPA_INDICATORS = ["react", "angular", "vue", "svelte", "ember", "backbone"]

MOBILE_BACKEND_INDICATORS = ["api.", "graphql", "rest.", "backend.", "mobile-api"]


class ProgramEnricher:
    """Enriches programs with inferred technology intelligence."""

    def __init__(self):
        self.fingerprint_db = self._load_fingerprint_db()

    def _load_fingerprint_db(self) -> dict:
        """Load the fingerprint database."""
        return {
            "frameworks": FRAMEWORK_PATTERNS,
            "cloud": CLOUD_PATTERNS,
            "cdn": CDN_PATTERNS,
            "auth": AUTH_PATTERNS,
            "graphql": GRAPHQL_INDICATORS,
            "spa": SPA_INDICATORS,
            "mobile_backend": MOBILE_BACKEND_INDICATORS,
        }

    def enrich(self, program: dict) -> dict:
        """
        Enrich a single program with inferred intelligence.
        Never overwrites discovered data — only appends.
        """
        enriched = dict(program)
        existing_intelligence = enriched.get("intelligence") or {}
        if not isinstance(existing_intelligence, dict):
            existing_intelligence = {}

        new_intelligence: dict[str, Any] = {}
        fields_added: list[str] = []

        # ── Infer from domains ────────────────────────────────────────────
        domains = program.get("domains", []) or []
        wildcards = program.get("wildcards", []) or []
        all_domains = domains + wildcards
        domain_str = " ".join(all_domains).lower()

        # Cloud providers from domains
        cloud_from_domains = self._infer_from_patterns(domain_str, CLOUD_PATTERNS)
        if cloud_from_domains:
            new_intelligence["cloud_providers"] = list(set(
                existing_intelligence.get("cloud_providers", []) + cloud_from_domains
            ))
            if "cloud_providers" not in existing_intelligence:
                fields_added.append("cloud_providers")

        # CDN from domains
        cdn_from_domains = self._infer_from_patterns(domain_str, CDN_PATTERNS)
        if cdn_from_domains:
            new_intelligence["cdn"] = list(set(
                existing_intelligence.get("cdn", []) + cdn_from_domains
            ))
            if "cdn" not in existing_intelligence:
                fields_added.append("cdn")

        # ── Infer from technology stack ───────────────────────────────────
        tech_stack = program.get("technology_stack", []) or []
        tech_str = " ".join(str(t) for t in tech_stack).lower()

        # Frameworks
        frameworks = self._infer_from_patterns(tech_str, FRAMEWORK_PATTERNS)
        if frameworks:
            new_intelligence["frameworks"] = list(set(
                existing_intelligence.get("frameworks", []) + frameworks
            ))
            if "frameworks" not in existing_intelligence:
                fields_added.append("frameworks")

        # ── Infer from authentication data ────────────────────────────────
        auth = program.get("authentication", {}) or {}
        if isinstance(auth, dict):
            auth_types = auth.get("types", []) or []
            auth_str = " ".join(str(a) for a in auth_types).lower()
            inferred_auth = self._infer_from_patterns(auth_str, AUTH_PATTERNS)
            if inferred_auth:
                new_intelligence["auth_methods"] = list(set(
                    existing_intelligence.get("auth_methods", []) + inferred_auth
                ))
                if "auth_methods" not in existing_intelligence:
                    fields_added.append("auth_methods")

        # ── Infer from public APIs ────────────────────────────────────────
        apis = program.get("public_apis", []) or []
        graphql = program.get("graphql", []) or []
        if graphql:
            new_intelligence["has_graphql"] = True
            new_intelligence["graphql_endpoints"] = list(set(
                existing_intelligence.get("graphql_endpoints", []) + graphql
            ))
            if "has_graphql" not in existing_intelligence:
                fields_added.append("has_graphql")
        if apis:
            new_intelligence["has_rest_api"] = True
            new_intelligence["api_endpoints"] = list(set(
                existing_intelligence.get("api_endpoints", []) + apis
            ))
            if "has_rest_api" not in existing_intelligence:
                fields_added.append("has_rest_api")

        # ── Infer architecture type ───────────────────────────────────────
        all_tech = " ".join(
            [tech_str, domain_str, " ".join(str(g) for g in graphql), " ".join(str(a) for a in apis)]
        ).lower()

        arch_type = self._infer_architecture(all_tech)
        if arch_type:
            new_intelligence["architecture_type"] = arch_type
            if "architecture_type" not in existing_intelligence:
                fields_added.append("architecture_type")

        # ── Infer mobile backend likelihood ───────────────────────────────
        mobile_backend_score = self._score_mobile_backend(program, all_tech)
        if mobile_backend_score > 0.3:
            new_intelligence["mobile_backend_likelihood"] = mobile_backend_score
            if "mobile_backend_likelihood" not in existing_intelligence:
                fields_added.append("mobile_backend_likelihood")

        # ── Merge intelligence (new never overwrites existing) ────────────
        merged_intelligence = {**existing_intelligence, **new_intelligence}
        enriched["intelligence"] = merged_intelligence
        enriched["_intelligence_added"] = fields_added
        enriched["last_updated"] = time.time()

        return enriched

    def enrich_all(self, discovery: Any, max_results: int = 50) -> dict:
        """Enrich all programs in the discovery database."""
        programs = discovery.list_programs(max_results=max_results * 10)
        enriched_count = 0
        skipped_count = 0
        total_fields = 0

        for prog in programs:
            handle = prog.get("handle", "")
            if not handle:
                continue
            try:
                enriched = self.enrich(prog)
                fields_added = enriched.get("_intelligence_added", [])
                if fields_added:
                    discovery.update_program(handle, enriched)
                    enriched_count += 1
                    total_fields += len(fields_added)
                else:
                    skipped_count += 1
            except Exception as exc:
                logger.warning("Failed to enrich %s: %s", handle, exc)
                skipped_count += 1

        return {
            "enriched": enriched_count,
            "skipped": skipped_count,
            "fields_added_total": total_fields,
        }

    def _infer_from_patterns(self, text: str, patterns: dict[str, list[str]]) -> list[str]:
        """Infer technologies from text using pattern matching."""
        found = []
        for tech, keywords in patterns.items():
            for keyword in keywords:
                if keyword in text:
                    found.append(tech)
                    break
        return found

    def _infer_architecture(self, tech_str: str) -> str:
        """Infer the application architecture type."""
        scores = {
            "spa": 0,
            "microservices": 0,
            "monolith": 0,
            "mobile_backend": 0,
        }

        for indicator in SPA_INDICATORS:
            if indicator in tech_str:
                scores["spa"] += 1
        if "graphql" in tech_str or "api" in tech_str:
            scores["microservices"] += 1
        if "django" in tech_str or "rails" in tech_str or "laravel" in tech_str:
            scores["monolith"] += 1
        if "api." in tech_str or "graphql" in tech_str:
            scores["mobile_backend"] += 1

        max_score = max(scores.values())
        if max_score == 0:
            return ""
        return max(scores, key=scores.get)  # type: ignore[arg-type]

    def _score_mobile_backend(self, program: dict, tech_str: str) -> float:
        """Score the likelihood that a program has a mobile backend."""
        score = 0.0

        # Check for mobile apps in assets
        assets = program.get("assets", []) or []
        for asset in assets:
            asset_str = json.dumps(asset).lower() if not isinstance(asset, str) else asset.lower()
            if "ios" in asset_str or "android" in asset_str or "mobile" in asset_str:
                score += 0.3

        # Check for API indicators
        if "graphql" in tech_str:
            score += 0.2
        if "api" in tech_str:
            score += 0.1
        if "rest" in tech_str:
            score += 0.1

        # Check tags
        tags = [t.lower() for t in (program.get("tags", []) or [])]
        if "mobile" in tags:
            score += 0.3
        if "api" in tags:
            score += 0.1

        return min(score, 1.0)
