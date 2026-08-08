"""
YesWeHack provider — public program scope discovery.

Reads the public bounty-targets-data dataset (arkadiyt/bounty-targets-data),
which mirrors YesWeHack's public program pages. Authorized-discovery data,
no credentials, 24h local cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from providers.base import BaseProvider, DATA_DIR

logger = logging.getLogger("program-intelligence.providers.yeswehack")

DATASET_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "master/data/yeswehack_data.json"
)


class YesWeHackProvider(BaseProvider):
    """Provider for YesWeHack public programs."""

    name = "yeswehack"
    cache_key = "yeswehack_programs_cache"

    def discover(self) -> list[dict]:
        return self._with_cache(self._fetch, key=self.cache_key)

    def _fetch(self) -> list[dict]:
        local = self._load_local_cache()
        if local:
            return self._dedupe([self._normalize(p) for p in local])

        resp = self._get(DATASET_URL)
        if resp is None:
            logger.info("YesWeHack: dataset unavailable, no local cache. Returning []")
            return []

        try:
            rows = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("YesWeHack: dataset parse failed: %s", exc)
            return []

        programs: list[dict] = []
        for row in rows if isinstance(rows, list) else []:
            normalized = self._normalize(self._map_row(row))
            if normalized:
                programs.append(normalized)
        return self._dedupe(programs)

    def _load_local_cache(self) -> list[dict]:
        candidates = [
            DATA_DIR / "yeswehack_cache.json",
            DATA_DIR / "yeswehack_programs.json",
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
                    logger.warning("YesWeHack: local cache read failed: %s", exc)
        return []

    def _map_row(self, row: dict) -> dict:
        # arkadiyt yeswehack rows: {"name": ..., "url": ..., "max_bounty": ...,
        # "min_bounty": ..., "domains": [...], "scopes": [...]}
        handle = (row.get("url") or "").rstrip("/").split("/")[-1]
        domains = row.get("domains", []) if isinstance(row, dict) else []
        scopes = row.get("scopes", []) if isinstance(row, dict) else []

        wildcards: list[str] = []
        plain: list[str] = []
        for d in domains:
            d = (d or "").strip()
            if d.startswith("*."):
                wildcards.append(d)
            else:
                plain.append(d)

        assets: list[str] = []
        for s in scopes if isinstance(scopes, list) else []:
            if isinstance(s, dict):
                uri = (s.get("scope") or s.get("uri") or "").strip()
                if uri and uri not in plain and uri not in wildcards:
                    assets.append(uri)
            elif isinstance(s, str):
                s = s.strip()
                if s and s not in plain and s not in wildcards:
                    assets.append(s)

        return {
            "handle": handle or (row.get("name") or "").lower().replace(" ", "-"),
            "name": row.get("name"),
            "platform": "YesWeHack",
            "url": row.get("url"),
            "reward": {
                "base": row.get("min_bounty"),
                "max": row.get("max_bounty"),
            },
            "scope": {
                "domains": plain,
                "wildcards": wildcards,
                "assets": assets,
                "out_of_scope": [],
            },
            "confidence": 0.9,
        }
