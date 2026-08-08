"""Tests for Discovery Engine."""

import json
import pytest
import tempfile
import time
from pathlib import Path

from discovery.engine import DiscoveryEngine, ProjectDiscoveryConnector, FireBountyConnector, SecurityTxtConnector, StandaloneConnector


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database path."""
    return tmp_path / "test_programs_db.json"


@pytest.fixture
def engine(temp_db):
    """Create a DiscoveryEngine with temp db."""
    return DiscoveryEngine(db_path=temp_db)


class TestDiscoveryEngine:
    """Test the main DiscoveryEngine class."""

    def test_init_creates_db(self, temp_db):
        """Test that initialization creates the DB file."""
        engine = DiscoveryEngine(db_path=temp_db)
        assert temp_db.exists()

    def test_count_empty(self, engine):
        """Test counting empty database."""
        assert engine.count() == 0

    def test_list_programs_empty(self, engine):
        """Test listing programs when empty."""
        result = engine.list_programs()
        assert result == []

    def test_get_program_not_found(self, engine):
        """Test getting a non-existent program."""
        assert engine.get_program("nonexistent") is None

    def test_count_by_platform_empty(self, engine):
        """Test counting by platform when empty."""
        assert engine.count_by_platform() == {}

    def test_count_enriched_empty(self, engine):
        """Test counting enriched when empty."""
        assert engine.count_enriched() == 0

    def test_register_connector(self, engine):
        """Test registering a custom connector."""

        class CustomConnector:
            def discover(self):
                return [{"handle": "custom", "name": "Custom Program", "platform": "Test"}]

            def normalize(self, raw):
                return raw

        engine.register_connector("custom", CustomConnector())
        assert "custom" in engine.connectors

    def test_discover_connector_all(self, engine):
        """Test discover with 'all' connector (will use built-in connectors)."""
        # Built-in connectors return empty without external data
        results = engine.discover(connector="all")
        assert isinstance(results, list)

    def test_discover_unknown_connector(self, engine):
        """Test discover with unknown connector."""
        results = engine.discover(connector="nonexistent")
        assert results == []

    def test_discover_new_empty(self, engine):
        """Test discover_new when DB is empty."""
        results = engine.discover_new()
        assert isinstance(results, list)


class TestProjectDiscoveryConnector:
    """Test ProjectDiscovery connector."""

    def test_discover_no_cache(self, engine):
        """Test discovery without cache."""
        conn = ProjectDiscoveryConnector(engine)
        results = conn.discover()
        assert isinstance(results, list)

    def test_normalize(self, engine):
        """Test normalization."""
        conn = ProjectDiscoveryConnector(engine)
        raw = {"slug": "test", "name": "Test", "platform": "HackerOne"}
        result = conn.normalize(raw)
        assert result is not None
        assert result["handle"] == "test"


class TestFireBountyConnector:
    """Test FireBounty connector."""

    def test_discover_no_cache(self, engine):
        """Test discovery without cache."""
        conn = FireBountyConnector(engine)
        results = conn.discover()
        assert isinstance(results, list)


class TestSecurityTxtConnector:
    """Test Security.txt connector."""

    def test_discover_no_data(self, engine):
        """Test discovery without data."""
        conn = SecurityTxtConnector(engine)
        results = conn.discover()
        assert isinstance(results, list)


class TestStandaloneConnector:
    """Test Standalone connector."""

    def test_discover_empty(self, engine, tmp_path):
        """Test discovery with no standalone programs."""
        conn = StandaloneConnector(engine)
        # Override the file path to use tmp_path for test isolation
        conn.STANDALONE_FILE = tmp_path / "standalone_programs.json"
        results = conn.discover()
        assert results == []

    def test_add_program(self, engine, tmp_path):
        """Test adding a standalone program."""
        conn = StandaloneConnector(engine)
        # Override the file path to use tmp_path
        conn.STANDALONE_FILE = tmp_path / "standalone_programs.json"
        conn.add_program({"handle": "custom", "name": "Custom Program", "platform": "Independent"})
        results = conn.discover()
        assert len(results) == 1
        assert results[0]["handle"] == "custom"


class TestBaseConnector:
    """Test base connector functionality."""

    def test_discover_raises(self, engine):
        """Test that base discover raises NotImplementedError."""
        from discovery.engine import BaseConnector
        conn = BaseConnector(engine)
        with pytest.raises(NotImplementedError):
            conn.discover()

    def test_normalize_default(self, engine):
        """Test default normalization."""
        from discovery.engine import BaseConnector
        conn = BaseConnector(engine)
        result = conn.normalize({"handle": "test", "name": "Test"})
        assert result is not None
        assert result["handle"] == "test"

    def test_update_returns_zero(self, engine):
        """Test default update returns 0."""
        from discovery.engine import BaseConnector
        conn = BaseConnector(engine)
        assert conn.update() == 0

    def test_detect_changes(self, engine):
        """Test change detection."""
        from discovery.engine import BaseConnector
        conn = BaseConnector(engine)
        old = {"name": "Old", "domains": ["a.com"]}
        new = {"name": "New", "domains": ["b.com"]}
        changes = conn.detect_changes(old, new)
        assert "name" in changes
        assert "domains" in changes
