"""
Intigriti provider — public program scope discovery.

Reads the public bounty-targets-data dataset (arkadiyt/bounty-targets-data),
which mirrors Intigriti's public program pages. Authorized-discovery data,
no credentials, 24h local cache.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from providers.base import BaseProvider, DATA_DIR

logger = logging.getLogger("program-intelligence.providers.intigriti")

DATASET_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "master/data/intigriti_data.json"
)


class IntigritiProvider(BaseProvider):
    """Provider for Intigriti public programs."""

    name = "intigriti"
    cache_key = "intigriti_programs_cache"

    def discover(self) -> list[dict]:
        return self._with_cache(self._fetch, key=self.cache_key)

    def _fetch(self) -> list[dict]:
        local = self._load_local_cache()
        if local:
            return self._dedupe([self._normalize(p) for p in local])

        resp = self._get(DATASET_URL)
        if resp is None:
            logger.info("Intigriti: dataset unavailable, no local cache. Returning []")
            return []

        try:
            rows = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning("Intigriti: dataset parse failed: %s", exc)
            return []

        programs: list[dict] = []
        for row in rows if isinstance(rows, list) else []:
            normalized = self._normalize(self._map_row(row))
            if normalized:
                programs.append(normalized)
        return self._dedupe(programs)

    def _load_local_cache(self) -> list[dict]:
        candidates = [
            DATA_DIR / "intigriti_cache.json",
            DATA_DIR / "intigriti_programs.json",
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
                    logger.warning("Intigriti: local cache read failed: %s", exc)
        return []

    def _map_row(self, row: dict) -> dict:
        # arkadiyt intigriti rows: {"name": ..., "url": ..., "max_bounty": ...,
        # "min_bounty": ..., "domains": [...], "targets": [...]}
        # The row carries a stable handle/company_handle. URL-based handle
        # derivation is unreliable: every intigriti program URL ends in
        # "/detail", which would collapse all programs into one handle.
        handle = (
            row.get("handle")
            or row.get("company_handle")
            or (row.get("url") or "").rstrip("/").split("/")[-1]
            or (row.get("name") or "").lower().replace(" ", "-")
        )
        domains = row.get("domains", []) if isinstance(row, dict) else []
        targets = row.get("targets", []) if isinstance(row, dict) else []

        wildcards: list[str] = []
        plain: list[str] = []
        for d in domains:
            d = (d or "").strip()
            if d.startswith("*."):
                wildcards.append(d)
            else:
                plain.append(d)

        assets: list[str] = []
        for t in targets if isinstance(targets, list) else []:
            uri = (t.get("uri") or t.get("endpoint") or "").strip()
            if uri and uri not in plain and uri not in wildcards:
                assets.append(uri)

        return {
            "handle": handle,
            "name": row.get("name"),
            "platform": "Intigriti",
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
