"""
Base Provider — shared fetching, caching, and normalization helpers.

Providers are *authorized discovery* sources. They only fetch publicly
published program data. All network access uses a short timeout, a
neutral User-Agent, and a 24h on-disk cache under the program-intelligence
data dir. Never sends credentials; never performs active testing.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import requests

from models.program import ProgramSchema

logger = logging.getLogger("program-intelligence.providers")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)

USER_AGENT = "ProgramIntelligenceProvider/1.0 (+authorized discovery; bug bounty scope data)"
CACHE_TTL = 86400  # 24 hours


class BaseProvider:
    """Base class for all providers."""

    name = "base"
    cache_key = "base_cache"

    def discover(self) -> list[dict]:
        """Discover programs. Must be implemented by subclasses."""
        raise NotImplementedError

    # ── HTTP helpers ─────────────────────────────────────────────────────────
    def _get(self, url: str, timeout: float = 15.0) -> requests.Response | None:
        """GET a URL with a neutral UA and short timeout. Returns None on failure."""
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=timeout,
            )
            if resp.status_code != 200:
                logger.warning("%s: HTTP %s from %s", self.name, resp.status_code, url)
                return None
            return resp
        except requests.RequestException as exc:
            logger.warning("%s: request failed %s: %s", self.name, url, exc)
            return None

    # ── Cache helpers ────────────────────────────────────────────────────────
    def _cache_ttl(self) -> int:
        """Cache TTL from policy (default 24h)."""
        try:
            from config import load_config
            return int(load_config()["providers"].get("cache_ttl", CACHE_TTL))
        except Exception:
            return CACHE_TTL

    def _load_cache(self, key: str | None = None) -> list[dict] | None:
        """Load cached programs if fresh. Returns None if missing/stale."""
        cache_path = DATA_DIR / f"{key or self.cache_key}.json"
        if not cache_path.exists():
            return None
        try:
            cached = json.loads(cache_path.read_text())
            if time.time() - cached.get("timestamp", 0) < self._cache_ttl():
                return cached.get("programs", [])
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("%s: cache read failed: %s", self.name, exc)
        return None

    def _save_cache(self, programs: list[dict], key: str | None = None) -> None:
        """Persist programs to cache with a timestamp."""
        cache_path = DATA_DIR / f"{key or self.cache_key}.json"
        try:
            cache_path.write_text(
                json.dumps(
                    {"timestamp": time.time(), "programs": programs},
                    indent=2,
                    default=str,
                )
            )
        except OSError as exc:
            logger.warning("%s: cache write failed: %s", self.name, exc)

    def _with_cache(self, fetch: Any, key: str | None = None) -> list[dict]:
        """Cache-then-fetch wrapper."""
        cached = self._load_cache(key)
        if cached is not None:
            return cached
        programs = fetch() or []
        if programs:
            self._save_cache(programs, key)
        return programs

    # ── Normalization helpers ────────────────────────────────────────────────
    def _normalize(self, raw: dict) -> dict | None:
        """Normalize a raw program entry. Adds provider provenance."""
        raw.setdefault("platform", self.name)
        raw["source"] = f"provider:{self.name}"
        try:
            normalized = ProgramSchema.normalize(raw)
            # ProgramSchema only keeps FIELDS; restore provenance fields.
            normalized["source"] = raw.get("source")
            normalized["provenance"] = {
                "provider": self.name,
                "raw_handle": raw.get("handle"),
            }
            return normalized
        except Exception as exc:
            logger.warning("%s: normalize failed: %s", self.name, exc)
            return None

    def _dedupe(self, programs: list[dict]) -> list[dict]:
        """Dedupe by handle. First occurrence wins."""
        seen: dict[str, dict] = {}
        for prog in programs:
            handle = (prog.get("handle") or "").strip().lower()
            if handle and handle not in seen:
                seen[handle] = prog
        return list(seen.values())
