"""
HackerOne provider — public program scope discovery.

Reads the public bounty-targets-data dataset (arkadiyt/bounty-targets-data),
which mirrors HackerOne's *public* program pages daily. This is published,
authorized-discovery data: the same source used by bbscope and friends.
No credentials are used. Results are cached 24h locally.

If a local cache file exists (e.g. written by the hackerone-mcp server),
it is preferred over the dataset mirror.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from providers.base import BaseProvider, DATA_DIR

logger = logging.getLogger("program-intelligence.providers.hackerone")

# Public dataset mirror of HackerOne program pages (updated daily).
DATASET_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "master/data/hackerone_data.json"
)


class HackerOneProvider(BaseProvider):
    """Provider for HackerOne public programs."""

    name = "hackerone"
    cache_key = "hackerone_programs_cache"

    def discover(self) -> list[dict]:
        return self._with_cache(self._fetch, key=self.cache_key)

    def _fetch(self) -> list[dict]:
        # 1. Prefer a local cache written by another tool (hackerone-mcp etc.)
        local = self._load_local_cache()
        if local:
            return self._dedupe([self._normalize(p) for p in local])

        # 2. Fall back to the public dataset mirror.
        resp = self._get(DATASET_URL)
        if resp is None:
            logger.info("HackerOne: dataset unavailable, no local cache. Returning []")
            return []

        try:
            rows = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("HackerOne: dataset parse failed: %s", exc)
            return []

        programs: list[dict] = []
        for row in rows if isinstance(rows, list) else []:
            normalized = self._normalize(self._map_row(row))
            if normalized:
                programs.append(normalized)
        return self._dedupe(programs)

    def _load_local_cache(self) -> list[dict]:
        """Load hackerone programs from a local JSON file if present."""
        candidates = [
            DATA_DIR / "hackerone_cache.json",
            DATA_DIR / "hackerone_programs.json",
            # Written by _save_cache(key="hackerone_programs_cache") — the
            # canonical 24h cache this provider itself produces.
            DATA_DIR / f"{self.cache_key}.json",
        ]
        for path in candidates:
            if path.exists():
                try:
                    data = json.loads(path.read_text())
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict):
                        return data.get("programs", data.get("data", []))
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("HackerOne: local cache read failed: %s", exc)
        return []

    def _map_row(self, row: dict) -> dict:
        """Map a dataset row to raw program fields."""
        # arkadiyt hackerone rows: {"name": ..., "url": ..., "disabled": bool,
        # "offers_bounties": bool, "scope": {"in_scope": [{"asset_type": ..., "asset_identifier": ...}],
        # "out_of_scope": [...]}}
        scope = row.get("scope", {})
        in_scope = scope.get("in_scope", []) if isinstance(scope, dict) else []
        out_scope = scope.get("out_of_scope", []) if isinstance(scope, dict) else []

        domains: list[str] = []
        wildcards: list[str] = []
        assets: list[str] = []
        for item in in_scope:
            ident = (item.get("asset_identifier") or "").strip()
            if not ident:
                continue
            a_type = (item.get("asset_type") or "").lower()
            if a_type == "wildcard":
                wildcards.append(ident)
            elif a_type in ("url", "api"):
                assets.append(ident)
            elif a_type == "domain":
                domains.append(ident)
            else:
                assets.append(ident)

        oos = [
            (item.get("asset_identifier") or "").strip()
            for item in out_scope
            if item.get("asset_identifier")
        ]

        return {
            "handle": (row.get("url") or "").rstrip("/").split("/")[-1],
            "name": row.get("name"),
            "platform": "HackerOne",
            "url": row.get("url"),
            "reward": {"base": 500 if row.get("offers_bounties") else 0},
            "scope": {
                "domains": domains,
                "wildcards": wildcards,
                "assets": assets,
                "out_of_scope": oos,
            },
            "tags": ["bounty" if row.get("offers_bounties") else "vdp"],
            "confidence": 0.9,
        }
