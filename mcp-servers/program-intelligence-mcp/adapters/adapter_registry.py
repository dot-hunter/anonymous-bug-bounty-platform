"""
Adapter Registry — connector interfaces for existing MCP servers.

Every intelligence component is modular.
New connectors are installable without changing existing code.
Supports future connectors via registration.

Adapters bridge between the Program Intelligence MCP and existing MCP servers:
  - vulnera-mcp: recon, testing, cloud, JS, graph
  - bounty-directory: program listing, ranking, details
  - agent-reach: OSINT, social media, GitHub intelligence
  - hackerone: public GraphQL, hacktivity, program stats
  - security-research: semgrep, codeql, race conditions, variant analysis
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("program-intelligence.adapters")


class AdapterInfo:
    """Information about a registered adapter."""

    def __init__(self, name: str, adapter_type: str, config: dict | None = None):
        self.name = name
        self.adapter_type = adapter_type
        self.config = config or {}
        self.registered_at = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.adapter_type,
            "config": self.config,
        }


class AdapterRegistry:
    """Manages connector adapters for existing MCP servers."""

    def __init__(self):
        self.adapters: dict[str, AdapterInfo] = {}
        self._register_builtin_adapters()

    def _register_builtin_adapters(self) -> None:
        """Register adapters for existing MCP servers."""
        # These are informational — they document the interface
        # The actual MCP calls go through the existing MCP servers
        self.adapters["vulnera-mcp"] = AdapterInfo(
            name="vulnera-mcp",
            adapter_type="recon_and_testing",
            config={
                "capabilities": [
                    "recon.subfinder", "recon.amass", "recon.httpx",
                    "recon.gau", "recon.ffuf", "recon.fingerprint",
                    "test.xss", "test.sqli", "test.idor", "test.csp",
                    "api.graphql", "api.rate_limit", "api.bola",
                    "auth.jwt", "auth.oauth", "auth.session",
                    "cloud.bucket_enum", "cloud.scan_secrets", "cloud.terraform",
                    "js.download", "js.beautify", "js.endpoints", "js.secrets",
                    "graph.ingest", "graph.patterns", "graph.attack_paths",
                ],
                "description": "Full-stack vulnerability assessment and recon",
            },
        )
        self.adapters["bounty-directory"] = AdapterInfo(
            name="bounty-directory",
            adapter_type="program_directory",
            config={
                "capabilities": [
                    "directory.stats", "directory.filter", "directory.rank",
                    "directory.get", "directory.search",
                ],
                "description": "Bug bounty program directory and ranking",
            },
        )
        self.adapters["agent-reach"] = AdapterInfo(
            name="agent-reach",
            adapter_type="osint",
            config={
                "capabilities": [
                    "osint.twitter_search", "osint.twitter_user",
                    "osint.reddit_search", "osint.youtube_search",
                    "osint.github_search", "osint.github_repo", "osint.github_issues",
                    "osint.bilibili_search", "osint.xhs_search",
                    "osint.web_search", "osint.web_fetch",
                ],
                "description": "Zero-API-fee OSINT and internet intelligence",
            },
        )
        self.adapters["hackerone"] = AdapterInfo(
            name="hackerone",
            adapter_type="platform_api",
            config={
                "capabilities": [
                    "hacktivity_search", "program_search", "program_stats",
                    "program_policy", "recent_disclosed", "recent_resolved",
                    "top_bounties", "new_programs",
                ],
                "description": "HackerOne public GraphQL API and hacktivity",
            },
        )
        self.adapters["security-research"] = AdapterInfo(
            name="security-research",
            adapter_type="static_analysis",
            config={
                "capabilities": [
                    "run_semgrep", "run_codeql", "race_condition_test",
                    "variant_analysis", "generate_poc_scaffold",
                    "save_weird_log", "read_weird_inventory",
                    "check_dependency_confusion",
                ],
                "description": "Elite security research: Semgrep, CodeQL, race conditions, PoC",
            },
        )
        self.adapters["nuclei"] = AdapterInfo(
            name="nuclei",
            adapter_type="scanner",
            config={
                "capabilities": [
                    "nuclei_scan", "list_templates", "update_templates",
                ],
                "description": "Nuclei template-based vulnerability scanner",
            },
        )
        self.adapters["interactsh"] = AdapterInfo(
            name="interactsh",
            adapter_type="oob",
            config={
                "capabilities": [
                    "generate_sqli_payload", "generate_ssrf_payload",
                    "generate_xxe_payload", "poll_interactions", "get_history",
                ],
                "description": "OOB interaction testing for blind vuln detection",
            },
        )
        self.adapters["shodan"] = AdapterInfo(
            name="shodan",
            adapter_type="internet_intel",
            config={
                "capabilities": [
                    "shodan_search", "shodan_host", "search_vulns",
                ],
                "description": "Internet-wide asset discovery and vulnerability search",
            },
        )

    def register(self, name: str, adapter_type: str, config: dict | None = None) -> None:
        """Register a new adapter."""
        self.adapters[name] = AdapterInfo(name=name, adapter_type=adapter_type, config=config)
        logger.info("Registered adapter: %s (type: %s)", name, adapter_type)

    def get(self, name: str) -> AdapterInfo | None:
        """Get an adapter by name."""
        return self.adapters.get(name)

    def list_adapters(self) -> list[dict]:
        """List all registered adapters."""
        return [a.to_dict() for a in self.adapters.values()]

    def count(self) -> int:
        """Count registered adapters."""
        return len(self.adapters)

    def get_capabilities(self, name: str) -> list[str]:
        """Get capabilities of a specific adapter."""
        adapter = self.adapters.get(name)
        if adapter:
            return adapter.config.get("capabilities", [])
        return []
