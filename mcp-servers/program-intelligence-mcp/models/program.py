"""
Normalized Program Model.

Every discovered program becomes a Program with these fields:
Program Name, Platform, Reward, Scope, Out Of Scope, Policy, Safe Harbor,
Assets, Domains, Subdomains, Wildcards, Cloud Assets, GitHub, Public APIs,
GraphQL, JavaScript Assets, Documentation, Developer Docs, SDKs,
Technology Stack, Authentication, Priority, Research Status, Recon Status,
Historical Notes, Tags, Confidence, Last Updated.
"""

from __future__ import annotations

import time
from typing import Any


class ProgramSchema:
    """Schema definition for a normalized program."""

    FIELDS = [
        "handle",
        "name",
        "platform",
        "url",
        "reward",
        "base_bounty",
        "max_bounty",
        "scope",
        "out_of_scope",
        "policy",
        "safe_harbor",
        "assets",
        "domains",
        "subdomains",
        "wildcards",
        "cloud_assets",
        "github",
        "public_apis",
        "graphql",
        "javascript_assets",
        "documentation",
        "developer_docs",
        "sdks",
        "technology_stack",
        "authentication",
        "priority",
        "research_status",
        "recon_status",
        "historical_notes",
        "tags",
        "confidence",
        "last_updated",
        "intelligence",
    ]

    @classmethod
    def normalize(cls, raw: dict) -> dict:
        """Normalize a raw program dict into the standard schema."""
        normalized = {field: None for field in cls.FIELDS}

        # Map common field names
        normalized["handle"] = raw.get("handle", raw.get("slug", raw.get("id", "")))
        normalized["name"] = raw.get("name", raw.get("title", normalized["handle"]))
        normalized["platform"] = raw.get("platform", raw.get("source", None))
        normalized["url"] = raw.get("url", raw.get("link", raw.get("program_url", "")))

        # Rewards
        reward = raw.get("reward", {})
        if isinstance(reward, dict):
            normalized["reward"] = reward
            normalized["base_bounty"] = reward.get("base", raw.get("base_bounty", raw.get("minimum_bounty")))
            normalized["max_bounty"] = reward.get("max", raw.get("max_bounty"))
        else:
            normalized["reward"] = {"base": reward} if reward else None
            normalized["base_bounty"] = raw.get("base_bounty", raw.get("minimum_bounty"))
            normalized["max_bounty"] = raw.get("max_bounty")

        # Scope — handle both dict-scope and flat-scope formats
        scope = raw.get("scope")
        if isinstance(scope, dict) and scope:
            normalized["scope"] = scope
            normalized["domains"] = scope.get("domains", raw.get("domains", []))
            normalized["wildcards"] = scope.get("wildcards", raw.get("wildcards", []))
            normalized["out_of_scope"] = scope.get("out_of_scope", scope.get("excluded", raw.get("out_of_scope", [])))
        else:
            normalized["scope"] = scope if scope is not None else []
            normalized["domains"] = raw.get("domains", [])
            normalized["wildcards"] = raw.get("wildcards", [])
            normalized["out_of_scope"] = raw.get("out_of_scope", [])

        normalized["policy"] = raw.get("policy", raw.get("policy_url", ""))
        normalized["safe_harbor"] = raw.get("safe_harbor", raw.get("safe_harbour", False))
        normalized["assets"] = raw.get("assets", [])
        normalized["subdomains"] = raw.get("subdomains", [])
        normalized["cloud_assets"] = raw.get("cloud_assets", raw.get("cloud", {}))
        normalized["github"] = raw.get("github", raw.get("repositories", raw.get("repos", [])))
        normalized["public_apis"] = raw.get("public_apis", raw.get("apis", []))
        normalized["graphql"] = raw.get("graphql", [])
        normalized["javascript_assets"] = raw.get("javascript_assets", raw.get("js_assets", []))
        normalized["documentation"] = raw.get("documentation", raw.get("docs", []))
        normalized["developer_docs"] = raw.get("developer_docs", raw.get("dev_docs", ""))
        normalized["sdks"] = raw.get("sdks", raw.get("sdk", []))
        normalized["technology_stack"] = raw.get("technology_stack", raw.get("tech_stack", raw.get("tech", [])))
        normalized["authentication"] = raw.get("authentication", raw.get("auth", {}))
        normalized["priority"] = raw.get("priority", None)
        normalized["research_status"] = raw.get("research_status", "not_started")
        normalized["recon_status"] = raw.get("recon_status", "not_started")
        normalized["historical_notes"] = raw.get("historical_notes", raw.get("notes", []))
        normalized["tags"] = raw.get("tags", [])
        normalized["confidence"] = raw.get("confidence", 0.5)
        normalized["last_updated"] = raw.get("last_updated", time.time())

        # Intelligence (added by enricher)
        if "intelligence" in raw:
            normalized["intelligence"] = raw["intelligence"]

        return normalized

    @classmethod
    def validate(cls, program: dict) -> tuple[bool, list[str]]:
        """Validate a program dict against the schema. Returns (is_valid, errors)."""
        errors = []
        if not program.get("handle"):
            errors.append("Missing required field: handle")
        if not program.get("name"):
            errors.append("Missing required field: name")
        if not program.get("platform"):
            errors.append("Missing required field: platform")
        return (len(errors) == 0, errors)


class Program:
    """Represents a single bug bounty program with full intelligence."""

    def __init__(self, data: dict):
        self.data = ProgramSchema.normalize(data)

    @property
    def handle(self) -> str:
        return self.data.get("handle", "")

    @property
    def name(self) -> str:
        return self.data.get("name", "")

    @property
    def platform(self) -> str:
        return self.data.get("platform", "")

    @property
    def domains(self) -> list:
        return self.data.get("domains", []) or []

    @property
    def wildcards(self) -> list:
        return self.data.get("wildcards", []) or []

    @property
    def max_bounty(self) -> int | None:
        return self.data.get("max_bounty")

    @property
    def tags(self) -> list:
        return self.data.get("tags", []) or []

    @property
    def confidence(self) -> float:
        return self.data.get("confidence", 0.5)

    def to_dict(self) -> dict:
        return dict(self.data)

    def update(self, updates: dict) -> None:
        """Update program data. Never overwrites discovered data with None."""
        for key, value in updates.items():
            if value is not None:
                self.data[key] = value
        self.data["last_updated"] = time.time()
