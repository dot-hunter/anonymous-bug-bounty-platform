#!/usr/bin/env python3
"""Scope Guard — Validates all targets against program scope before testing."""

from __future__ import annotations
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("scope-guard")

SCOPE_FILE = Path.home() / ".config" / "vulnera-mcp" / "scope.json"


class ScopeGuard:
    """Validates targets against authorized program scope."""

    def __init__(self, scope_file=None):
        self.scope_file = scope_file or SCOPE_FILE
        self.scope = self._load_scope()

    def _load_scope(self):
        if self.scope_file.exists():
            try:
                return json.loads(self.scope_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"domains": [], "ips": [], "excluded": [], "wildcard": [], "cidr": []}

    def save_scope(self, domains=None, ips=None, excluded=None, wildcard=None, cidr=None):
        self.scope = {
            "domains": domains or [],
            "ips": ips or [],
            "excluded": excluded or [],
            "wildcard": wildcard or [],
            "cidr": cidr or [],
        }
        self.scope_file.write_text(json.dumps(self.scope, indent=2))

    def is_in_scope(self, target):
        """Check if target is within authorized scope. Returns (bool, reason)."""
        if not self.scope.get("domains") and not self.scope.get("wildcard"):
            # No scope configured — warn but allow
            return True, "no_scope_configured"

        parsed = urlparse(target if "://" in target else f"https://{target}")
        hostname = parsed.netloc.split(":")[0]

        # Check exclusions first
        for exc in self.scope.get("excluded", []):
            if exc in hostname:
                return False, f"excluded:{exc}"

        # Check wildcard scopes
        for wc in self.scope.get("wildcard", []):
            if wc.startswith("*."):
                base = wc[2:]
                if hostname == base or hostname.endswith("." + base):
                    return True, f"wildcard:{wc}"

        # Check exact domains
        for domain in self.scope.get("domains", []):
            if hostname == domain or hostname.endswith("." + domain):
                return True, f"domain:{domain}"

        # Check IP ranges
        for ip in self.scope.get("ips", []):
            if hostname == ip:
                return True, f"ip:{ip}"

        return False, "not_in_scope"

    def assert_in_scope(self, target):
        """Raise exception if target is out of scope."""
        allowed, reason = self.is_in_scope(target)
        if not allowed:
            raise PermissionError(
                f"Target '{target}' is OUT OF SCOPE (reason: {reason}). "
                f"Update scope.json to authorize this target."
            )
        return True


# Global instance
guard = ScopeGuard()
