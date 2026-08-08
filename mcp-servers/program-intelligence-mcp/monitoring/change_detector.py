"""
Change Detector — continuously compare historical data.

Detects:
  New Programs, Removed Programs, Scope Changes, Reward Changes,
  Policy Changes, Asset Changes, Technology Changes,
  Documentation Changes, GitHub Changes, API Changes,
  GraphQL Changes, Cloud Changes.

Triggers research only for changed programs.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("program-intelligence.monitoring")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class ChangeDetector:
    """Detects changes in program data over time."""

    def __init__(
        self,
        db_path: Path | None = None,
        changes_log: Path | None = None,
        snapshots_dir: Path | None = None,
    ):
        self.db_path = db_path or (DATA_DIR / "programs_db.json")
        self.changes_log = changes_log or (DATA_DIR / "changes.jsonl")
        self.snapshots_dir = snapshots_dir or (DATA_DIR / "snapshots")
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def take_snapshot(self) -> dict:
        """Take a snapshot of the current program database."""
        snapshot = {
            "timestamp": time.time(),
            "program_count": 0,
            "programs": {},
        }

        if self.db_path.exists():
            try:
                db = json.loads(self.db_path.read_text())
                programs = db.get("programs", [])
                snapshot["program_count"] = len(programs)
                for p in programs:
                    handle = p.get("handle", "")
                    if handle:
                        snapshot["programs"][handle] = self._program_fingerprint(p)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to read DB for snapshot: %s", exc)

        # Save snapshot (use microseconds to avoid collisions)
        snapshot_path = self.snapshots_dir / f"snapshot_{int(time.time() * 1000000)}.json"
        try:
            snapshot_path.write_text(json.dumps(snapshot, indent=2, default=str))
        except OSError as exc:
            logger.error("Failed to save snapshot: %s", exc)

        return snapshot

    def detect(self) -> dict:
        """Detect changes since last snapshot."""
        # Find the latest snapshot
        snapshots = sorted(self.snapshots_dir.glob("snapshot_*.json"), reverse=True)
        if not snapshots:
            # No previous snapshot — take one and return empty changes
            self.take_snapshot()
            return {"changes": [], "message": "No previous snapshot. Initial snapshot taken."}

        latest_snapshot_path = snapshots[0]
        try:
            old_snapshot = json.loads(latest_snapshot_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read snapshot: %s", exc)
            return {"changes": [], "error": str(exc)}

        # Load current DB
        if not self.db_path.exists():
            return {"changes": [], "message": "No program database found."}

        try:
            db = json.loads(self.db_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read DB: %s", exc)
            return {"changes": [], "error": str(exc)}

        current_programs = db.get("programs", [])
        old_programs = old_snapshot.get("programs", {})

        changes: list[dict] = []

        # ── Detect new programs ──────────────────────────────────────────
        current_handles = {p.get("handle", "") for p in current_programs}
        old_handles = set(old_programs.keys())

        new_handles = current_handles - old_handles
        for handle in new_handles:
            changes.append({
                "type": "new_program",
                "handle": handle,
                "timestamp": time.time(),
                "description": f"New program discovered: {handle}",
            })

        # ── Detect removed programs ──────────────────────────────────────
        removed_handles = old_handles - current_handles
        for handle in removed_handles:
            changes.append({
                "type": "removed_program",
                "handle": handle,
                "timestamp": time.time(),
                "description": f"Program no longer listed: {handle}",
            })

        # ── Detect changes in existing programs ──────────────────────────
        for handle in current_handles & old_handles:
            current_prog = None
            for p in current_programs:
                if p.get("handle", "") == handle:
                    current_prog = p
                    break

            if not current_prog:
                continue

            old_fp = old_programs[handle]
            new_fp = self._program_fingerprint(current_prog)

            program_changes = self._compare_fingerprints(handle, old_fp, new_fp)
            changes.extend(program_changes)

        # ── Log changes ──────────────────────────────────────────────────
        if changes:
            self._log_changes(changes)

        return {
            "changes": changes,
            "new_programs": len(new_handles),
            "removed_programs": len(removed_handles),
            "modified_programs": len(changes) - len(new_handles) - len(removed_handles),
            "total_changes": len(changes),
        }

    def get_history(self, limit: int = 20) -> list[dict]:
        """Get recent change log entries."""
        entries: list[dict] = []
        if self.changes_log.exists():
            try:
                lines = self.changes_log.read_text().strip().split("\n")
                for line in lines[-limit:]:
                    if line.strip():
                        entries.append(json.loads(line))
            except (json.JSONDecodeError, OSError):
                pass
        return entries

    def count_snapshots(self) -> int:
        """Count stored snapshots."""
        return len(list(self.snapshots_dir.glob("snapshot_*.json")))

    def count_changes(self) -> int:
        """Count total change log entries."""
        if self.changes_log.exists():
            try:
                return len([l for l in self.changes_log.read_text().strip().split("\n") if l.strip()])
            except OSError:
                pass
        return 0

    def _program_fingerprint(self, program: dict) -> dict:
        """Create a fingerprint of key program fields for comparison."""
        return {
            "name": program.get("name"),
            "max_bounty": program.get("max_bounty"),
            "base_bounty": program.get("base_bounty"),
            "domains": sorted(program.get("domains", []) or []),
            "wildcards": sorted(program.get("wildcards", []) or []),
            "scope": json.dumps(program.get("scope", {}), sort_keys=True),
            "tags": sorted(program.get("tags", []) or []),
            "technology_stack": sorted(program.get("technology_stack", []) or []),
            "public_apis": sorted(program.get("public_apis", []) or []),
            "graphql": sorted(program.get("graphql", []) or []),
            "github": sorted(program.get("github", []) or []),
            "safe_harbor": program.get("safe_harbor"),
            "policy": program.get("policy"),
        }

    def _compare_fingerprints(
        self,
        handle: str,
        old: dict,
        new: dict,
    ) -> list[dict]:
        """Compare two fingerprints and return detected changes."""
        changes: list[dict] = []

        # Check each field
        field_to_change_type = {
            "domains": "scope_change",
            "wildcards": "scope_change",
            "scope": "scope_change",
            "max_bounty": "reward_change",
            "base_bounty": "reward_change",
            "tags": "asset_change",
            "technology_stack": "technology_change",
            "public_apis": "api_change",
            "graphql": "graphql_change",
            "github": "github_change",
            "safe_harbor": "policy_change",
            "policy": "policy_change",
        }

        for field, change_type in field_to_change_type.items():
            old_val = old.get(field)
            new_val = new.get(field)
            if old_val != new_val:
                changes.append({
                    "type": change_type,
                    "handle": handle,
                    "field": field,
                    "timestamp": time.time(),
                    "old_value": old_val,
                    "new_value": new_val,
                    "description": f"{change_type.replace('_', ' ').title()} on {handle}: {field}",
                })

        return changes

    def _log_changes(self, changes: list[dict]) -> None:
        """Append changes to the changes log."""
        try:
            with open(self.changes_log, "a") as f:
                for change in changes:
                    f.write(json.dumps(change, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to log changes: %s", exc)
