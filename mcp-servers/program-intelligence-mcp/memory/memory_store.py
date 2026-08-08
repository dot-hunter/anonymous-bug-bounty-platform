"""
Memory Store — additive memory collections.

Types:
  Program Memory, Research Memory, Recon Memory, Technology Memory,
  Framework Memory, Historical Memory, Pattern Memory,
  Successful Techniques, Failed Techniques, Duplicate Avoidance.

Extends memory only. Never replaces.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("program-intelligence.memory")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Valid memory types
MEMORY_TYPES = [
    "program",
    "research",
    "recon",
    "technology",
    "framework",
    "historical",
    "pattern",
    "success",
    "failure",
    "duplicate_avoidance",
]


class MemoryStore:
    """Manages additive memory collections."""

    def __init__(self, memory_dir: Path | None = None):
        self.memory_dir = memory_dir or (DATA_DIR / "memory")
        self.memory_dir.mkdir(parents=True, exist_ok=True)

    def _memory_path(self, memory_type: str) -> Path:
        """Get the file path for a memory type."""
        return self.memory_dir / f"{memory_type}.jsonl"

    def save(self, memory_type: str, key: str, data: dict) -> None:
        """Save a memory entry. Appends to the memory collection."""
        if memory_type not in MEMORY_TYPES:
            raise ValueError(
                f"Unknown memory type: {memory_type}. Valid: {MEMORY_TYPES}"
            )

        entry = {
            "key": key,
            "data": data,
            "timestamp": time.time(),
        }

        path = self._memory_path(memory_type)
        try:
            with open(path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to save memory: %s", exc)

    def get(self, memory_type: str, key: str) -> dict | None:
        """Get a memory entry by key (returns most recent)."""
        path = self._memory_path(memory_type)
        if not path.exists():
            return None

        entries = self._read_all(path)
        # Return the most recent entry with matching key
        for entry in reversed(entries):
            if entry.get("key") == key:
                return entry.get("data")
        return None

    def search(self, memory_type: str, query: str = "", limit: int = 20) -> list[dict]:
        """Search memory entries by type with optional value matching."""
        path = self._memory_path(memory_type)
        if not path.exists():
            return []

        entries = self._read_all(path)
        results: list[dict] = []

        for entry in entries:
            if query:
                # Search in both key and data
                entry_str = json.dumps({"key": entry.get("key", ""), **entry.get("data", {})}).lower()
                if query.lower() not in entry_str:
                    continue
            results.append(entry)
            if len(results) >= limit:
                break

        return results

    def list_all(self, memory_type: str) -> list[dict]:
        """List all entries for a memory type."""
        path = self._memory_path(memory_type)
        if not path.exists():
            return []
        return self._read_all(path)

    def count(self) -> int:
        """Count total memory entries across all types."""
        total = 0
        for memory_type in MEMORY_TYPES:
            path = self._memory_path(memory_type)
            if path.exists():
                try:
                    total += len([l for l in path.read_text().strip().split("\n") if l.strip()])
                except OSError:
                    pass
        return total

    def count_by_type(self) -> dict[str, int]:
        """Count entries by memory type."""
        counts: dict[str, int] = {}
        for memory_type in MEMORY_TYPES:
            path = self._memory_path(memory_type)
            if path.exists():
                try:
                    counts[memory_type] = len([l for l in path.read_text().strip().split("\n") if l.strip()])
                except OSError:
                    counts[memory_type] = 0
            else:
                counts[memory_type] = 0
        return counts

    def _read_all(self, path: Path) -> list[dict]:
        """Read all entries from a JSONL file."""
        entries: list[dict] = []
        try:
            for line in path.read_text().strip().split("\n"):
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
        return entries
