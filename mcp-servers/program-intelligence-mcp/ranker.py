"""
WordPress Target Ranker — prioritize in-scope WordPress assets.

Scoring model (per the extension spec):

  base                    +30  (WordPress in scope)
  +5 per detected plugin  capped +20
  +5 theme detected       (one-time, capped +5)
  +10 REST API enabled
  +10 login page exposed
  +15 program offers bounties (high reward)
  +5  wildcard scope entry
  cap                    100

Output is a prioritized list of WordPress targets for a program with
full provenance (why each score component was added).
"""

from __future__ import annotations

import logging
from typing import Any

from normalizer import ScopeNormalizer
from resolver import AuthorizationResolver

logger = logging.getLogger("program-intelligence.ranker")

BASE_WP = 30
PLUGIN_SCORE = 5
PLUGIN_CAP = 20
THEME_SCORE = 5
REST_SCORE = 10
LOGIN_SCORE = 10
BOUNTY_SCORE = 15
WILDCARD_SCORE = 5
MAX_SCORE = 100


class WordPressRanker:
    """Ranks WordPress targets by exploit-relevant features."""

    @classmethod
    def rank_target(cls, program: dict, fingerprint: dict) -> dict:
        """Score a single fingerprint against a program.

        Args:
            program:     program dict (normalized scope).
            fingerprint: output of WordPressFingerprinter.fingerprint().

        Returns:
            dict with target, url, score, components (per-component points),
            reasons, is_wordpress.
        """
        url = fingerprint.get("url") or ""
        if not fingerprint.get("is_wordpress"):
            return {
                "target": url,
                "url": url,
                "is_wordpress": False,
                "score": 0,
                "components": [],
                "reasons": ["Not WordPress"],
            }

        scope = program.get("scope")
        if not isinstance(scope, dict):
            scope = ScopeNormalizer.normalize_scope(scope, program)

        components: list[dict[str, Any]] = [{"name": "base_wordpress", "points": BASE_WP, "reason": "WordPress in scope"}]
        reasons = ["WordPress detected"]

        # Plugins
        plugins = fingerprint.get("plugins", [])
        plugin_points = min(len(plugins) * PLUGIN_SCORE, PLUGIN_CAP)
        if plugin_points:
            components.append({
                "name": "plugins",
                "points": plugin_points,
                "reason": f"{len(plugins)} plugins: {', '.join(plugins[:10])}",
            })
            reasons.append(f"{len(plugins)} plugin(s) detected")

        # Theme
        themes = fingerprint.get("themes", [])
        if themes:
            components.append({
                "name": "theme",
                "points": THEME_SCORE,
                "reason": f"theme: {themes[0]}",
            })
            reasons.append("theme detected")

        # REST API
        if fingerprint.get("rest_api"):
            components.append({
                "name": "rest_api",
                "points": REST_SCORE,
                "reason": f"REST API at {fingerprint['rest_api']}",
            })
            reasons.append("REST API enabled")

        # Login page
        if fingerprint.get("login_page"):
            components.append({
                "name": "login_page",
                "points": LOGIN_SCORE,
                "reason": f"login page at {fingerprint['login_page']}",
            })
            reasons.append("login page exposed")

        # Bounty program (high reward)
        bounty = cls._program_bounty(program)
        if bounty:
            components.append({
                "name": "bounty_program",
                "points": BOUNTY_SCORE,
                "reason": f"program offers bounties (max={bounty})",
            })
            reasons.append("bounty program")

        # Wildcard scope
        if scope.get("wildcards"):
            components.append({
                "name": "wildcard_scope",
                "points": WILDCARD_SCORE,
                "reason": f"wildcard scope: {', '.join(scope['wildcards'][:3])}",
            })
            reasons.append("wildcard in scope")

        total = min(sum(c["points"] for c in components), MAX_SCORE)
        return {
            "target": url,
            "url": url,
            "is_wordpress": True,
            "score": total,
            "max_score": MAX_SCORE,
            "components": components,
            "reasons": reasons,
            "authorized": fingerprint.get("authorized", True),
            "version": fingerprint.get("version"),
        }

    @classmethod
    def rank_program_targets(cls, program: dict, fingerprints: list[dict]) -> list[dict]:
        """Score all fingerprints for a program and sort desc by score."""
        ranked = [cls.rank_target(program, fp) for fp in fingerprints]
        ranked.sort(key=lambda r: r.get("score", 0), reverse=True)
        return ranked

    @staticmethod
    def _program_bounty(program: dict) -> int | str | None:
        reward = program.get("reward") or {}
        if isinstance(reward, dict):
            max_b = reward.get("max")
            if max_b:
                return max_b
            base = reward.get("base")
            if base:
                return base
        return program.get("max_bounty")
