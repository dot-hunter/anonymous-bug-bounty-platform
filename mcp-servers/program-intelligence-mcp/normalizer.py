"""
Scope Normalizer — canonical bug-bounty scope representation.

Turns heterogeneous scope input (dict-scope, flat lists, dataset rows,
program pages) into a single canonical shape:

    {
      "domains":      ["example.com"],
      "wildcards":    ["*.example.com"],
      "assets":       ["https://api.example.com", "app://mobile"],
      "subdomains":   ["sub.example.com"],
      "out_of_scope": ["example.com/admin"],
    }

The normalizer is *purely syntactic*: it does not test anything. It is
the foundation for authorization resolution (resolver.py) and WordPress
target discovery (wordpress.py).
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("program-intelligence.normalizer")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


class ScopeNormalizer:
    """Normalizes scope input into a canonical dict."""

    @classmethod
    def normalize_scope(cls, scope: Any, raw: dict | None = None) -> dict:
        """Normalize any scope shape into the canonical form.

        Args:
            scope: dict (scope block) or list (flat scope entries) or None.
            raw:   optional raw program dict for fallback fields.
        """
        raw = raw or {}
        out: dict[str, list] = {
            "domains": [],
            "wildcards": [],
            "assets": [],
            "subdomains": [],
            "out_of_scope": [],
        }

        entries: list[str] = []
        if isinstance(scope, dict):
            for key in ("domains", "wildcards", "assets", "subdomains", "out_of_scope", "excluded", "in_scope"):
                vals = scope.get(key, [])
                if isinstance(vals, list):
                    for v in vals:
                        if isinstance(v, str):
                            entries.append((key, v.strip()))
                        elif isinstance(v, dict):
                            ident = v.get("asset_identifier") or v.get("uri") or v.get("name") or v.get("endpoint")
                            if ident:
                                entries.append((key, str(ident).strip()))
        elif isinstance(scope, list):
            for v in scope:
                if isinstance(v, str):
                    entries.append(("assets", v.strip()))
                elif isinstance(v, dict):
                    ident = v.get("asset_identifier") or v.get("uri") or v.get("name") or v.get("endpoint")
                    if ident:
                        entries.append(("assets", str(ident).strip()))

        # Fallback: pull from raw program dict fields
        for key in ("domains", "wildcards", "subdomains", "out_of_scope", "assets"):
            if not entries and raw.get(key):
                for v in raw.get(key, []):
                    if isinstance(v, str):
                        entries.append((key, v.strip()))

        for key, value in entries:
            if not value:
                continue
            if key in ("out_of_scope", "excluded"):
                out["out_of_scope"].append(value)
            elif key == "domains":
                out["domains"].append(value)
            elif key == "wildcards":
                out["wildcards"].append(value)
            elif key == "subdomains":
                out["subdomains"].append(value)
            else:
                cls._bucket_asset(value, out)

        # Reclassify anything that looks like a domain/wildcard in assets
        cls._reclassify(out)

        # Dedupe preserving order
        for k in out:
            out[k] = list(dict.fromkeys(out[k]))
        return out

    # ── helpers ──────────────────────────────────────────────────────────────
    @classmethod
    def _bucket_asset(cls, value: str, out: dict) -> None:
        """Classify an asset string into domains/wildcards/assets."""
        host = value
        if "://" in value:
            parsed = urlparse(value)
            host = parsed.netloc or parsed.path
            if parsed.scheme in ("http", "https") and host:
                # URL asset: keep in assets (URL-level scope), but also note host
                out["assets"].append(value)
                return
        host = host.split("/")[0].strip().lower()
        if host.startswith("*."):
            out["wildcards"].append(host)
        elif cls._looks_like_domain(host):
            out["domains"].append(host)
        else:
            out["assets"].append(value)

    @classmethod
    def _reclassify(cls, out: dict) -> None:
        """Move domain/wildcard-shaped entries from assets into proper buckets."""
        cleaned: list[str] = []
        for asset in out["assets"]:
            host = asset
            if "://" in asset:
                host = urlparse(asset).netloc or urlparse(asset).path
            host = host.split("/")[0].strip().lower()
            if host.startswith("*."):
                out["wildcards"].append(host)
            elif cls._looks_like_domain(host):
                out["domains"].append(host)
            else:
                cleaned.append(asset)
        out["assets"] = cleaned

    @staticmethod
    def _looks_like_domain(host: str) -> bool:
        """Heuristic: does this look like a domain (has dot, no spaces)?."""
        if not host or " " in host or "/" in host:
            return False
        if host.count(".") >= 1 and not host[0].isdigit():
            return bool(DOMAIN_RE.match(host))
        return False

    @classmethod
    def normalize_program(cls, raw: dict) -> dict:
        """Normalize a full raw program dict: scope + metadata."""
        scope = raw.get("scope")
        normalized_scope = cls.normalize_scope(scope, raw)
        return {
            "handle": raw.get("handle", raw.get("slug", "")),
            "name": raw.get("name", ""),
            "platform": raw.get("platform", ""),
            "url": raw.get("url", ""),
            "reward": raw.get("reward", {}),
            "max_bounty": raw.get("max_bounty"),
            "scope": normalized_scope,
            "source": raw.get("source", "unknown"),
        }
