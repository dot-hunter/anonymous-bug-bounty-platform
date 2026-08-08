"""Tests for Change Detector."""

import json
import pytest
import time
from pathlib import Path

from monitoring.change_detector import ChangeDetector


@pytest.fixture
def temp_dirs(tmp_path):
    """Create temporary directories for testing."""
    return {
        "db_path": tmp_path / "programs_db.json",
        "changes_log": tmp_path / "changes.jsonl",
        "snapshots_dir": tmp_path / "snapshots",
    }


@pytest.fixture
def detector(temp_dirs):
    """Create a ChangeDetector instance."""
    temp_dirs["snapshots_dir"].mkdir(exist_ok=True)
    return ChangeDetector(
        db_path=temp_dirs["db_path"],
        changes_log=temp_dirs["changes_log"],
        snapshots_dir=temp_dirs["snapshots_dir"],
    )


@pytest.fixture
def sample_db(temp_dirs):
    """Create a sample database."""
    db = {
        "programs": [
            {
                "handle": "test1",
                "name": "Test 1",
                "platform": "HackerOne",
                "max_bounty": 5000,
                "domains": ["test1.com"],
                "wildcards": ["*.test1.com"],
                "tags": ["web"],
                "technology_stack": ["react"],
                "public_apis": [],
                "graphql": [],
                "github": [],
                "safe_harbor": True,
                "policy": "https://test1.com/policy",
            },
            {
                "handle": "test2",
                "name": "Test 2",
                "platform": "Bugcrowd",
                "max_bounty": 1000,
                "domains": ["test2.com"],
                "wildcards": [],
                "tags": ["api"],
                "technology_stack": ["django"],
                "public_apis": ["https://api.test2.com"],
                "graphql": [],
                "github": [],
                "safe_harbor": False,
                "policy": "",
            },
        ],
        "last_updated": time.time(),
    }
    temp_dirs["db_path"].write_text(json.dumps(db, indent=2))
    return db


class TestChangeDetector:
    """Test the ChangeDetector class."""

    def test_take_snapshot(self, detector, sample_db):
        """Test taking a snapshot."""
        snapshot = detector.take_snapshot()
        assert snapshot["program_count"] == 2
        assert "test1" in snapshot["programs"]
        assert "test2" in snapshot["programs"]

    def test_snapshot_creates_file(self, detector, sample_db, temp_dirs):
        """Test that snapshot creates a file."""
        detector.take_snapshot()
        snapshots = list(temp_dirs["snapshots_dir"].glob("snapshot_*.json"))
        assert len(snapshots) == 1

    def test_detect_no_previous_snapshot(self, detector, sample_db):
        """Test detect with no previous snapshot."""
        result = detector.detect()
        assert result["changes"] == []
        assert "message" in result

    def test_detect_new_program(self, detector, sample_db):
        """Test detecting a new program."""
        # Take initial snapshot
        detector.take_snapshot()

        # Modify DB to add a new program
        db = json.loads(detector.db_path.read_text())
        db["programs"].append({
            "handle": "new_program",
            "name": "New Program",
            "platform": "HackerOne",
            "max_bounty": 10000,
            "domains": ["new.com"],
            "wildcards": ["*.new.com"],
            "tags": ["web"],
            "technology_stack": [],
            "public_apis": [],
            "graphql": [],
            "github": [],
            "safe_harbor": True,
            "policy": "",
        })
        detector.db_path.write_text(json.dumps(db, indent=2))

        result = detector.detect()
        new_program_changes = [c for c in result["changes"] if c["type"] == "new_program"]
        assert len(new_program_changes) == 1
        assert new_program_changes[0]["handle"] == "new_program"

    def test_detect_removed_program(self, detector, sample_db):
        """Test detecting a removed program."""
        # Take initial snapshot
        detector.take_snapshot()

        # Remove a program
        db = json.loads(detector.db_path.read_text())
        db["programs"] = [p for p in db["programs"] if p["handle"] != "test2"]
        detector.db_path.write_text(json.dumps(db, indent=2))

        result = detector.detect()
        removed_changes = [c for c in result["changes"] if c["type"] == "removed_program"]
        assert len(removed_changes) == 1
        assert removed_changes[0]["handle"] == "test2"

    def test_detect_scope_change(self, detector, sample_db):
        """Test detecting a scope change."""
        # Take initial snapshot
        detector.take_snapshot()

        # Modify domains
        db = json.loads(detector.db_path.read_text())
        for p in db["programs"]:
            if p["handle"] == "test1":
                p["domains"] = ["test1.com", "newdomain.com"]
        detector.db_path.write_text(json.dumps(db, indent=2))

        result = detector.detect()
        scope_changes = [c for c in result["changes"] if c["type"] == "scope_change"]
        assert len(scope_changes) >= 1

    def test_detect_reward_change(self, detector, sample_db):
        """Test detecting a reward change."""
        # Take initial snapshot
        detector.take_snapshot()

        # Modify bounty
        db = json.loads(detector.db_path.read_text())
        for p in db["programs"]:
            if p["handle"] == "test1":
                p["max_bounty"] = 10000
        detector.db_path.write_text(json.dumps(db, indent=2))

        result = detector.detect()
        reward_changes = [c for c in result["changes"] if c["type"] == "reward_change"]
        assert len(reward_changes) >= 1

    def test_get_history_empty(self, detector):
        """Test getting history when empty."""
        entries = detector.get_history()
        assert entries == []

    def test_get_history_with_entries(self, detector, sample_db):
        """Test getting history with entries."""
        # Create a change and log it
        detector.take_snapshot()
        db = json.loads(detector.db_path.read_text())
        db["programs"].append({
            "handle": "new_prog",
            "name": "New",
            "platform": "HackerOne",
        })
        detector.db_path.write_text(json.dumps(db, indent=2))
        detector.detect()

        entries = detector.get_history()
        assert len(entries) > 0

    def test_count_snapshots(self, detector, sample_db):
        """Test counting snapshots."""
        assert detector.count_snapshots() == 0
        detector.take_snapshot()
        assert detector.count_snapshots() == 1
        detector.take_snapshot()
        assert detector.count_snapshots() == 2

    def test_count_changes(self, detector, sample_db):
        """Test counting changes."""
        assert detector.count_changes() == 0
        detector.take_snapshot()
        db = json.loads(detector.db_path.read_text())
        db["programs"].append({"handle": "new", "name": "New", "platform": "HackerOne"})
        detector.db_path.write_text(json.dumps(db, indent=2))
        detector.detect()
        assert detector.count_changes() > 0

    def test_program_fingerprint(self, detector):
        """Test program fingerprinting."""
        program = {
            "handle": "test",
            "name": "Test",
            "max_bounty": 5000,
            "domains": ["a.com", "b.com"],
            "wildcards": ["*.test.com"],
        }
        fp = detector._program_fingerprint(program)
        assert fp["name"] == "Test"
        assert fp["max_bounty"] == 5000
        assert "a.com" in fp["domains"]
        assert "*.test.com" in fp["wildcards"]
