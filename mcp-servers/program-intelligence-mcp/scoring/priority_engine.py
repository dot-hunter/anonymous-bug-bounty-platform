"""
Program Priority Engine — generate weighted scores.

Inputs:
  Attack Surface, Reward, Scope Breadth, Documentation, API Presence,
  GraphQL, Cloud Assets, Technology Match, GitHub, Recent Changes,
  Historical Findings, Confidence

Outputs:
  Priority Score, Priority Tier, Reasoning, Recommended Next Action
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("program-intelligence.scoring")


# ── Weight configuration ──────────────────────────────────────────────────────
# Weights sum to 1.0 for interpretability

WEIGHTS = {
    "attack_surface": 0.20,
    "reward": 0.15,
    "scope_breadth": 0.10,
    "documentation": 0.05,
    "api_presence": 0.10,
    "graphql": 0.05,
    "cloud_assets": 0.05,
    "technology_match": 0.10,
    "github": 0.05,
    "recent_changes": 0.05,
    "historical_findings": 0.05,
    "confidence": 0.05,
}

# Tier thresholds
TIER_THRESHOLDS = {
    "critical": 0.85,
    "high": 0.70,
    "medium": 0.50,
    "low": 0.30,
}


class PriorityEngine:
    """Scores and ranks programs by priority."""

    def score_program(self, program: dict) -> dict:
        """Score a single program. Returns score, tier, reasoning, next_action."""
        scores: dict[str, float] = {}
        reasoning: list[str] = []

        # ── Attack Surface (0-1) ─────────────────────────────────────────
        domains = len(program.get("domains", []) or [])
        wildcards = len(program.get("wildcards", []) or [])
        subdomains = len(program.get("subdomains", []) or [])
        surface_score = min((domains * 0.05 + wildcards * 0.15 + subdomains * 0.01), 1.0)
        scores["attack_surface"] = surface_score
        if wildcards > 0:
            reasoning.append(f"{wildcards} wildcard scopes (broad surface)")
        if domains > 5:
            reasoning.append(f"{domains} explicit domains")

        # ── Reward (0-1) ─────────────────────────────────────────────────
        max_bounty = program.get("max_bounty") or 0
        base_bounty = program.get("base_bounty") or 0
        bounty = max_bounty or base_bounty
        if bounty >= 50000:
            reward_score = 1.0
        elif bounty >= 10000:
            reward_score = 0.8
        elif bounty >= 5000:
            reward_score = 0.6
        elif bounty >= 1000:
            reward_score = 0.4
        elif bounty > 0:
            reward_score = 0.2
        else:
            reward_score = 0.0
        scores["reward"] = reward_score
        if bounty > 0:
            reasoning.append(f"Max bounty: ${bounty:,}")

        # ── Scope Breadth (0-1) ──────────────────────────────────────────
        scope_items = len(program.get("scope", []) or [])
        if isinstance(program.get("scope"), dict):
            scope_items = len(program["scope"].get("domains", [])) + len(program["scope"].get("wildcards", []))
        scope_score = min(scope_items * 0.1, 1.0)
        scores["scope_breadth"] = scope_score

        # ── Documentation (0-1) ──────────────────────────────────────────
        docs = program.get("documentation", []) or []
        dev_docs = 1 if program.get("developer_docs") else 0
        sdks = len(program.get("sdks", []) or [])
        doc_score = min((len(docs) * 0.1 + dev_docs * 0.3 + sdks * 0.1), 1.0)
        scores["documentation"] = doc_score
        if docs or sdks:
            reasoning.append(f"Rich documentation ({len(docs)} docs, {sdks} SDKs)")

        # ── API Presence (0-1) ───────────────────────────────────────────
        apis = program.get("public_apis", []) or []
        api_score = min(len(apis) * 0.2, 1.0)
        scores["api_presence"] = api_score
        if apis:
            reasoning.append(f"{len(apis)} public APIs documented")

        # ── GraphQL (0-1) ────────────────────────────────────────────────
        graphql = program.get("graphql", []) or []
        gql_score = 1.0 if graphql else 0.0
        scores["graphql"] = gql_score
        if graphql:
            reasoning.append("GraphQL endpoint (high-value target)")

        # ── Cloud Assets (0-1) ───────────────────────────────────────────
        cloud = program.get("cloud_assets", {}) or {}
        if isinstance(cloud, dict):
            cloud_count = len(cloud.get("providers", []) or [])
        else:
            cloud_count = len(cloud) if isinstance(cloud, list) else 0
        cloud_score = min(cloud_count * 0.25, 1.0)
        scores["cloud_assets"] = cloud_score

        # ── Technology Match (0-1) ───────────────────────────────────────
        tech_stack = program.get("technology_stack", []) or []
        intelligence = program.get("intelligence", {}) or {}
        frameworks = intelligence.get("frameworks", []) or []
        # More frameworks = more potential attack surface
        tech_score = min((len(tech_stack) + len(frameworks)) * 0.1, 1.0)
        scores["technology_match"] = tech_score

        # ── GitHub (0-1) ─────────────────────────────────────────────────
        repos = program.get("github", []) or []
        gh_score = min(len(repos) * 0.2, 1.0)
        scores["github"] = gh_score
        if repos:
            reasoning.append(f"{len(repos)} known GitHub repos")

        # ── Recent Changes (0-1) ─────────────────────────────────────────
        last_updated = program.get("last_updated", 0)
        if isinstance(last_updated, (int, float)):
            age_days = (time.time() - last_updated) / 86400
            changes_score = max(0, 1.0 - (age_days / 30))  # Higher if recently updated
        else:
            changes_score = 0.5
        scores["recent_changes"] = changes_score

        # ── Historical Findings (0-1) ────────────────────────────────────
        notes = program.get("historical_notes", []) or []
        hist_score = min(len(notes) * 0.2, 1.0)
        scores["historical_findings"] = hist_score

        # ── Confidence (0-1) ─────────────────────────────────────────────
        confidence = program.get("confidence", 0.5)
        if isinstance(confidence, (int, float)):
            scores["confidence"] = float(confidence)
        else:
            scores["confidence"] = 0.5

        # ── Compute weighted total ───────────────────────────────────────
        total_score = sum(scores.get(k, 0) * w for k, w in WEIGHTS.items())
        total_score = round(min(max(total_score, 0.0), 1.0), 4)

        # ── Determine tier ───────────────────────────────────────────────
        tier = self._score_to_tier(total_score)

        # ── Recommended next action ──────────────────────────────────────
        next_action = self._recommend_next_action(program, scores, tier)

        return {
            "total_score": total_score,
            "tier": tier,
            "component_scores": scores,
            "reasoning": reasoning,
            "recommended_next_action": next_action,
            "scored_at": time.time(),
        }

    def rank_programs(
        self,
        discovery: Any,
        top_n: int = 20,
        platform: str | None = None,
        min_score: float | None = None,
    ) -> list[dict]:
        """Rank all programs by priority score."""
        programs = discovery.list_programs(platform=platform, max_results=1000)
        scored = []

        for prog in programs:
            try:
                score = self.score_program(prog)
                scored.append({
                    "handle": prog.get("handle", ""),
                    "name": prog.get("name", ""),
                    "platform": prog.get("platform", ""),
                    "score": score["total_score"],
                    "tier": score["tier"],
                    "reasoning": score["reasoning"],
                    "recommended_next_action": score["recommended_next_action"],
                })
            except Exception as exc:
                logger.warning("Failed to score %s: %s", prog.get("handle"), exc)

        # Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)

        # Apply min_score filter
        if min_score is not None:
            scored = [s for s in scored if s["score"] >= min_score]

        return scored[:top_n]

    def _score_to_tier(self, score: float) -> str:
        """Convert a numeric score to a tier label."""
        for tier, threshold in sorted(TIER_THRESHOLDS.items(), key=lambda x: -x[1]):
            if score >= threshold:
                return tier
        return "very_low"

    def _recommend_next_action(self, program: dict, scores: dict, tier: str) -> str:
        """Generate a recommended next action based on scores."""
        if tier in ("critical", "high"):
            # Find the highest component score
            max_component = max(
                ["attack_surface", "api_presence", "graphql", "cloud_assets", "github"],
                key=lambda k: scores.get(k, 0),
            )
            if max_component == "attack_surface":
                return "Start recon: subdomain enumeration on wildcard domains"
            elif max_component == "api_presence":
                return "Map API surface: swagger/openapi discovery + endpoint fuzzing"
            elif max_component == "graphql":
                return "GraphQL testing: introspection, batching, field-level IDOR"
            elif max_component == "cloud_assets":
                return "Cloud scanning: S3/secrets/terraform exposure"
            elif max_component == "github":
                return "GitHub audit: repo secrets, internal URLs, config leaks"
            return "Full recon + hunt cycle"
        elif tier == "medium":
            return "Research dossier generation + targeted recon"
        elif tier == "low":
            return "Passive intel collection + monitor for scope changes"
        else:
            return "Monitor for program changes"
