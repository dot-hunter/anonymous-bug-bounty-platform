"""
Discovery Engine — connector architecture.

Every connector outputs one normalized schema.
Supported connector types:
  - projectdiscovery (ProjectDiscovery Public Programs)
  - firebounty (FireBounty)
  - securitytxt (Security.txt Discovery)
  - standalone (Standalone Programs)
  - future (Future Connectors via adapter registration)

Connector interface:
  discover()  -> list[dict]   # Discover programs
  update()    -> int          # Update existing entries
  normalize() -> dict         # Normalize to schema
  detect_changes() -> dict    # Detect changes since last run
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from models.program import ProgramSchema

logger = logging.getLogger("program-intelligence.discovery")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class DiscoveryEngine:
    """Main discovery engine. Manages connectors and the local program database."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or (DATA_DIR / "programs_db.json")
        self._ensure_db()
        self.connectors: dict[str, Any] = {}
        self._register_builtin_connectors()

    def _ensure_db(self) -> None:
        """Ensure the database file exists."""
        if not self.db_path.exists():
            self.db_path.write_text(json.dumps({"programs": [], "last_updated": 0}, indent=2))

    def _load_db(self) -> dict:
        """Load the database."""
        try:
            return json.loads(self.db_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {"programs": [], "last_updated": 0}

    def _save_db(self, db: dict) -> None:
        """Save the database."""
        db["last_updated"] = time.time()
        try:
            self.db_path.write_text(json.dumps(db, indent=2, default=str))
        except OSError as exc:
            logger.error("Failed to save DB: %s", exc)

    def _register_builtin_connectors(self) -> None:
        """Register built-in connectors."""
        self.connectors["projectdiscovery"] = ProjectDiscoveryConnector(self)
        self.connectors["firebounty"] = FireBountyConnector(self)
        self.connectors["securitytxt"] = SecurityTxtConnector(self)
        self.connectors["standalone"] = StandaloneConnector(self)

    def register_connector(self, name: str, connector: Any) -> None:
        """Register a new connector at runtime."""
        self.connectors[name] = connector

    def discover(self, connector: str = "all", max_results: int = 50) -> list[dict]:
        """Run discovery across connectors."""
        all_programs: list[dict] = []

        if connector == "all":
            for name, conn in self.connectors.items():
                try:
                    results = conn.discover()
                    for r in results:
                        normalized = conn.normalize(r)
                        if normalized:
                            all_programs.append(normalized)
                except Exception as exc:
                    logger.warning("Connector %s failed: %s", name, exc)
        else:
            conn = self.connectors.get(connector)
            if conn:
                results = conn.discover()
                for r in results:
                    normalized = conn.normalize(r)
                    if normalized:
                        all_programs.append(normalized)
            else:
                logger.warning("Unknown connector: %s", connector)

        # Merge into DB
        self._merge_programs(all_programs[:max_results])
        return all_programs[:max_results]

    def discover_new(self, connector: str = "all", max_results: int = 50) -> list[dict]:
        """Discover programs not yet in the local database."""
        db = self._load_db()
        existing_handles = {p.get("handle", "") for p in db.get("programs", [])}

        all_programs = self.discover(connector=connector, max_results=max_results * 3)
        new_programs = [p for p in all_programs if p.get("handle", "") not in existing_handles]
        return new_programs[:max_results]

    def _merge_programs(self, programs: list[dict]) -> int:
        """Merge discovered programs into the database. Returns count of new programs."""
        db = self._load_db()
        existing = {p.get("handle", ""): i for i, p in enumerate(db.get("programs", []))}
        added = 0

        for prog in programs:
            handle = prog.get("handle", "")
            if not handle:
                continue
            if handle in existing:
                # Update existing (keep discovered data, append intelligence)
                idx = existing[handle]
                existing_prog = db["programs"][idx]
                merged = self._merge_program_data(existing_prog, prog)
                db["programs"][idx] = merged
            else:
                db["programs"].append(prog)
                added += 1

        self._save_db(db)
        return added

    def _merge_program_data(self, existing: dict, new: dict) -> dict:
        """
        Merge new data into existing program.
        - Never overwrites discovered data with None/empty
        - Updatable fields always refresh when new value is non-empty
        - Intelligence is deep-merged
        - last_updated always refreshed
        """
        merged = dict(existing)

        # Fields that are expected to change and should always be updated
        updatable_fields = {
            "name", "url", "max_bounty", "base_bounty", "reward",
            "policy", "safe_harbor", "research_status", "recon_status",
            "confidence", "tags",
        }

        for key, value in new.items():
            if value is None or value == [] or value == {}:
                continue  # Skip empty values — never overwrite with None

            if key == "last_updated":
                merged[key] = value
                continue

            if key == "intelligence" and isinstance(merged.get("intelligence"), dict) and isinstance(value, dict):
                # Deep merge intelligence
                merged["intelligence"] = {**merged["intelligence"], **value}
                continue

            if key in updatable_fields:
                # Always update updatable fields if new value is non-empty
                merged[key] = value
            elif merged.get(key) is None or merged.get(key) == [] or merged.get(key) == {}:
                # For non-updatable fields, only fill in if currently empty
                merged[key] = value

        merged["last_updated"] = time.time()
        return merged

    def get_program(self, handle: str) -> dict | None:
        """Get a single program by handle."""
        db = self._load_db()
        for p in db.get("programs", []):
            if p.get("handle", "") == handle:
                return p
        return None

    def list_programs(
        self,
        platform: str | None = None,
        min_bounty: int | None = None,
        has_wildcard: bool | None = None,
        tag: str | None = None,
        max_results: int = 50,
    ) -> list[dict]:
        """List programs with optional filters."""
        db = self._load_db()
        programs = db.get("programs", [])

        if platform:
            programs = [p for p in programs if p.get("platform", "").lower() == platform.lower()]
        if min_bounty is not None:
            programs = [
                p for p in programs
                if (p.get("max_bounty") or p.get("base_bounty") or 0) >= min_bounty
            ]
        if has_wildcard is not None:
            programs = [
                p for p in programs
                if bool(p.get("wildcards", [])) == has_wildcard
            ]
        if tag:
            programs = [
                p for p in programs
                if tag.lower() in [t.lower() for t in (p.get("tags", []) or [])]
            ]

        return programs[:max_results]

    def update_program(self, handle: str, updates: dict) -> bool:
        """Update a program with new data."""
        db = self._load_db()
        for i, p in enumerate(db.get("programs", [])):
            if p.get("handle", "") == handle:
                db["programs"][i] = self._merge_program_data(p, updates)
                self._save_db(db)
                return True
        return False

    def count(self) -> int:
        """Count total programs."""
        db = self._load_db()
        return len(db.get("programs", []))

    def count_by_platform(self) -> dict[str, int]:
        """Count programs by platform."""
        db = self._load_db()
        counts: dict[str, int] = {}
        for p in db.get("programs", []):
            platform = p.get("platform", "unknown")
            counts[platform] = counts.get(platform, 0) + 1
        return counts

    def count_enriched(self) -> int:
        """Count programs with intelligence data."""
        db = self._load_db()
        return sum(1 for p in db.get("programs", []) if p.get("intelligence"))


# ──────────────────────────────────────────────────────────────────────────────
# CONNECTORS
# ──────────────────────────────────────────────────────────────────────────────


class BaseConnector:
    """Base class for all connectors."""

    def __init__(self, engine: DiscoveryEngine):
        self.engine = engine

    def discover(self) -> list[dict]:
        """Discover programs. Must be implemented by subclasses."""
        raise NotImplementedError

    def normalize(self, raw: dict) -> dict | None:
        """Normalize a raw program entry. Can be overridden."""
        try:
            return ProgramSchema.normalize(raw)
        except Exception:
            return None

    def update(self) -> int:
        """Update existing entries. Returns count updated."""
        return 0

    def detect_changes(self, old: dict, new: dict) -> dict:
        """Detect changes between old and new data."""
        changes = {}
        for key in set(list(old.keys()) + list(new.keys())):
            if old.get(key) != new.get(key):
                changes[key] = {"old": old.get(key), "new": new.get(key)}
        return changes


class ProjectDiscoveryConnector(BaseConnector):
    """Connector for ProjectDiscovery Public Programs (via Chaos API or public data)."""

    def discover(self) -> list[dict]:
        """Discover programs from ProjectDiscovery public data."""
        programs = []

        # Try to use bbscope-style data or public program lists
        # First check if we have a local cache
        cache_path = DATA_DIR / "projectdiscovery_cache.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                if time.time() - cached.get("timestamp", 0) < 86400:  # 24h cache
                    return cached.get("programs", [])
            except (json.JSONDecodeError, OSError):
                pass

        # Use bounty-targets-data format (arkadiyt/bounty-targets-data)
        # This is a known public dataset
        bounty_targets_path = DATA_DIR / "bounty_targets_data.json"
        if bounty_targets_path.exists():
            try:
                data = json.loads(bounty_targets_path.read_text())
                for item in data if isinstance(data, list) else []:
                    programs.append(item)
            except (json.JSONDecodeError, OSError):
                pass

        # Also check for hackerone public programs via hackerone-mcp style data
        h1_cache = DATA_DIR / "hackerone_programs_cache.json"
        if h1_cache.exists():
            try:
                data = json.loads(h1_cache.read_text())
                for item in data if isinstance(data, list) else []:
                    programs.append(item)
            except (json.JSONDecodeError, OSError):
                pass

        # If no cache, return empty (will be populated by hackerone MCP)
        if not programs:
            logger.info("ProjectDiscoveryConnector: No local cache found. Use hackerone MCP for live data.")

        return programs

    def normalize(self, raw: dict) -> dict | None:
        """Normalize ProjectDiscovery data."""
        raw["platform"] = raw.get("platform", "HackerOne")
        raw["source"] = "projectdiscovery"
        if "handle" not in raw and "slug" in raw:
            raw["handle"] = raw["slug"]
        return super().normalize(raw)


class FireBountyConnector(BaseConnector):
    """Connector for FireBounty (firebounty.com) — aggregates VDPs and bug bounty programs."""

    FIREBOUNTY_API = "https://firebounty.com/api/v1"

    def discover(self) -> list[dict]:
        """Discover programs from FireBounty."""
        programs = []

        # Check local cache first
        cache_path = DATA_DIR / "firebounty_cache.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                if time.time() - cached.get("timestamp", 0) < 86400:
                    return cached.get("programs", [])
            except (json.JSONDecodeError, OSError):
                pass

        # Try to fetch from FireBounty API (public)
        curl_path = shutil.which("curl")
        if curl_path:
            try:
                result = subprocess.run(
                    [curl_path, "-s", f"{self.FIREBOUNTY_API}/programs?limit=100"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        programs = data
                    elif isinstance(data, dict) and "programs" in data:
                        programs = data["programs"]
                    elif isinstance(data, dict) and "data" in data:
                        programs = data["data"]
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
                logger.debug("FireBounty API fetch failed: %s", exc)

        # Cache results
        if programs:
            try:
                cache_path.write_text(json.dumps({
                    "timestamp": time.time(),
                    "programs": programs,
                }, indent=2))
            except OSError:
                pass

        if not programs:
            logger.info("FireBountyConnector: No live data fetched. Cache will be used when available.")

        return programs

    def normalize(self, raw: dict) -> dict | None:
        """Normalize FireBounty data."""
        raw["platform"] = raw.get("platform", raw.get("source", "Independent"))
        raw["source"] = "firebounty"
        if "handle" not in raw:
            raw["handle"] = raw.get("slug", raw.get("id", raw.get("name", "").lower().replace(" ", "-")))
        return super().normalize(raw)


class SecurityTxtConnector(BaseConnector):
    """Connector for Security.txt Discovery — finds programs via well-known security.txt."""

    def discover(self) -> list[dict]:
        """Discover programs from security.txt lookups."""
        programs = []

        # Check cache
        cache_path = DATA_DIR / "securitytxt_cache.json"
        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                if time.time() - cached.get("timestamp", 0) < 86400:
                    return cached.get("programs", [])
            except (json.JSONDecodeError, OSError):
                pass

        # Look for any pre-collected security.txt data
        # In a full implementation, this would scan known domains for security.txt
        # and extract policy/disclosure contacts
        logger.info("SecurityTxtConnector: Scanning for security.txt disclosures.")

        # Check if there's a collected dataset
        st_data = DATA_DIR / "securitytxt_data.json"
        if st_data.exists():
            try:
                data = json.loads(st_data.read_text())
                for item in data if isinstance(data, list) else []:
                    programs.append(item)
            except (json.JSONDecodeError, OSError):
                pass

        return programs

    def normalize(self, raw: dict) -> dict | None:
        """Normalize security.txt data."""
        raw["platform"] = raw.get("platform", "Independent")
        raw["source"] = "securitytxt"
        if "handle" not in raw:
            raw["handle"] = raw.get("domain", raw.get("url", "").replace("https://", "").replace("http://", "").split("/")[0])
        return super().normalize(raw)


class StandaloneConnector(BaseConnector):
    """Connector for Standalone Programs — manually added or custom programs."""

    STANDALONE_FILE = DATA_DIR / "standalone_programs.json"

    def discover(self) -> list[dict]:
        """Discover standalone programs from local config."""
        if self.STANDALONE_FILE.exists():
            try:
                data = json.loads(self.STANDALONE_FILE.read_text())
                return data.get("programs", []) if isinstance(data, dict) else data
            except (json.JSONDecodeError, OSError):
                pass
        return []

    def add_program(self, program: dict) -> None:
        """Add a standalone program."""
        programs = self.discover()
        programs.append(program)
        try:
            self.STANDALONE_FILE.write_text(json.dumps({"programs": programs}, indent=2, default=str))
        except OSError as exc:
            logger.error("Failed to save standalone program: %s", exc)

    def normalize(self, raw: dict) -> dict | None:
        """Normalize standalone program data."""
        raw["platform"] = raw.get("platform", "Independent")
        raw["source"] = "standalone"
        if "handle" not in raw:
            raw["handle"] = raw.get("name", "").lower().replace(" ", "-")
        return super().normalize(raw)
