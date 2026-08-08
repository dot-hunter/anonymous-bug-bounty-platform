"""
Bugcrowd provider — public program scope discovery.

Reads the public bounty-targets-data dataset (arkadiyt/bounty-targets-data),
which mirrors Bugcrowd's public program pages. Authorized-discovery data,
no credentials, 24h local cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from providers.base import BaseProvider, DATA_DIR

logger = logging.getLogger("program-intelligence.providers.bugcrowd")

DATASET_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "master/data/bugcrowd_data.json"
)


class BugcrowdProvider(BaseProvider):
    """Provider for Bugcrowd public programs."""

    name = "bugcrowd"
    cache_key = "bugcrowd_programs_cache"

    def discover(self) -> list[dict]:
        return self._with_cache(self._fetch, key=self.cache_key)

    def _fetch(self) -> list[dict]:
        local = self._load_local_cache()
        if local:
            return self._dedupe([self._normalize(p) for p in local])

        resp = self._get(DATASET_URL)
        if resp is None:
            logger.info("Bugcrowd: dataset unavailable, no local cache. Returning []")
            return []

        try:
            rows = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("Bugcrowd: dataset parse failed: %s", exc)
            return []

        programs: list[dict] = []
        for row in rows if isinstance(rows, list) else []:
            normalized = self._normalize(self._map_row(row))
            if normalized:
                programs.append(normalized)
        return self._dedupe(programs)

    def _load_local_cache(self) -> list[dict]:
        candidates = [
            DATA_DIR / "bugcrowd_cache.json",
            DATA_DIR / "bugcrowd_programs.json",
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
                    logger.warning("Bugcrowd: local cache read failed: %s", exc)
        return []

    def _map_row(self, row: dict) -> dict:
        # arkadiyt bugcrowd rows: {"name": ..., "url": ..., "targets": [{"name": ...,
        # "uri": ..., "in_scope": bool, "type": ..., "description": ...}]}
        handle = (row.get("url") or "").rstrip("/").split("/")[-1]
        targets = row.get("targets", []) if isinstance(row, dict) else []

        domains: list[str] = []
        wildcards: list[str] = []
        assets: list[str] = []
        oos: list[str] = []
        for t in targets:
            uri = (t.get("uri") or "").strip()
            if not uri:
                continue
            if not t.get("in_scope", True):
                oos.append(uri)
                continue
            t_type = (t.get("type") or "").lower()
            if t_type == "website" and "*." in uri:
                wildcards.append(uri)
            elif t_type == "website":
                domains.append(uri)
            else:
                assets.append(uri)

        return {
            "handle": handle or (row.get("name") or "").lower().replace(" ", "-"),
            "name": row.get("name"),
            "platform": "Bugcrowd",
            "url": row.get("url"),
            "reward": {"base": None},
            "scope": {
                "domains": domains,
                "wildcards": wildcards,
                "assets": assets,
                "out_of_scope": oos,
            },
            "confidence": 0.9,
        }
