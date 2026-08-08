"""
Security.txt provider — VDP / policy discovery via security.txt.

Fetches the standard /.well-known/security.txt resource for a given
domain to determine whether it publishes a disclosure policy, safe
harbor statement, or VDP. This is *read-only* authorized discovery:
security.txt exists precisely to tell researchers whether testing is
welcome. No payloads, no scanning.

Each domain checked produces one lightweight "program" entry carrying
the policy fields (contact, policy, safe_harbor, expires).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from providers.base import BaseProvider

logger = logging.getLogger("program-intelligence.providers.securitytxt")

SECURITY_TXT_PATH = "/.well-known/security.txt"
SECURITY_TXT_ALT = "/security.txt"
FIELD_RE = re.compile(r"^([A-Za-z-]+):\s*(.+)$")


class SecurityTxtProvider(BaseProvider):
    """Provider for security.txt policy discovery."""

    name = "securitytxt"
    cache_key = "securitytxt_programs_cache"

    def discover(self, domains: list[str] | None = None) -> list[dict]:
        """Discover disclosure policies for the given domains.

        Args:
            domains: list of hostnames to check. If None, returns cached results
                     (or [] if no cache — this provider is domain-driven).
        """
        if not domains:
            cached = self._load_cache()
            return cached or []

        programs: list[dict] = []
        for domain in domains:
            policy = self._fetch_policy(domain)
            if policy:
                programs.append(policy)

        if programs:
            self._save_cache(programs)
        return programs

    def _fetch_policy(self, domain: str) -> dict | None:
        """Fetch and parse security.txt for a domain. Returns normalized program dict or None."""
        domain = (domain or "").strip().lower()
        if not domain:
            return None

        body = None
        fetched_path = None
        for path in (SECURITY_TXT_PATH, SECURITY_TXT_ALT):
            for scheme in ("https://", "http://"):
                resp = self._get(f"{scheme}{domain}{path}", timeout=10.0)
                if resp is not None and resp.status_code == 200:
                    text = resp.text[:20000]
                    if text.strip():
                        body = text
                        fetched_path = path
                        break
            if body:
                break

        if body is None:
            return None

        fields = self._parse(body)
        contact = fields.get("contact")
        if not contact:
            return None

        policy_url = fields.get("policy", fields.get("hiring", ""))
        expires = fields.get("expires", "")

        return self._normalize(
            {
                "handle": f"securitytxt-{domain}",
                "name": f"{domain} security.txt policy",
                "platform": "securitytxt",
                "url": f"https://{domain}{fetched_path}",
                "reward": {"base": 0},
                "scope": {"domains": [domain], "wildcards": [], "assets": [], "out_of_scope": []},
                "policy": policy_url,
                "safe_harbor": self._has_safe_harbor(body),
                "tags": ["vdp", "securitytxt"],
                "authentication": {"contact": contact, "expires": expires},
                "confidence": 0.8,
            }
        )

    def _parse(self, body: str) -> dict:
        """Parse security.txt key-value fields."""
        fields: dict[str, str] = {}
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = FIELD_RE.match(line)
            if match:
                fields.setdefault(match.group(1).lower(), match.group(2).strip())
        return fields

    def _has_safe_harbor(self, body: str) -> bool:
        """Detect a safe-harbor statement in the body."""
        lowered = body.lower()
        return "safe harbor" in lowered or "safe-harbor" in lowered or "safe_harbor" in lowered
