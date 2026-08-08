"""Tests for Memory Store."""

import pytest
from memory.memory_store import MemoryStore, MEMORY_TYPES


@pytest.fixture
def store(tmp_path):
    """Create a MemoryStore with temp directory."""
    return MemoryStore(memory_dir=tmp_path / "memory")


class TestMemoryStore:
    """Test the MemoryStore class."""

    def test_save_and_get(self, store):
        """Test saving and retrieving memory."""
        store.save("pattern", "test-pattern", {"findings": 3, "technique": "idor"})
        entry = store.get("pattern", "test-pattern")
        assert entry is not None
        assert entry["findings"] == 3
        assert entry["technique"] == "idor"

    def test_get_not_found(self, store):
        """Test getting non-existent memory."""
        entry = store.get("pattern", "nonexistent")
        assert entry is None

    def test_search(self, store):
        """Test searching memory."""
        store.save("pattern", "graphql-idor", {"findings": 3})
        store.save("pattern", "rest-idor", {"findings": 5})
        store.save("pattern", "graphql-ssrf", {"findings": 1})

        results = store.search("pattern", query="graphql")
        assert len(results) == 2

    def test_search_empty_query(self, store):
        """Test search with empty query returns all."""
        store.save("pattern", "test1", {"a": 1})
        store.save("pattern", "test2", {"b": 2})

        results = store.search("pattern", query="")
        assert len(results) == 2

    def test_list_all(self, store):
        """Test listing all entries."""
        store.save("pattern", "test1", {"a": 1})
        store.save("pattern", "test2", {"b": 2})

        entries = store.list_all("pattern")
        assert len(entries) == 2

    def test_list_all_empty(self, store):
        """Test listing all when empty."""
        entries = store.list_all("nonexistent_type")
        assert entries == []

    def test_count(self, store):
        """Test counting entries."""
        assert store.count() == 0
        store.save("pattern", "test1", {"a": 1})
        assert store.count() == 1
        store.save("success", "test2", {"b": 2})
        assert store.count() == 2

    def test_count_by_type(self, store):
        """Test counting by type."""
        store.save("pattern", "test1", {"a": 1})
        store.save("pattern", "test2", {"b": 2})
        store.save("success", "test3", {"c": 3})

        counts = store.count_by_type()
        assert counts["pattern"] == 2
        assert counts["success"] == 1

    def test_invalid_memory_type(self, store):
        """Test that invalid memory type raises error."""
        with pytest.raises(ValueError, match="Unknown memory type"):
            store.save("invalid_type", "key", {})

    def test_all_memory_types(self, store):
        """Test that all memory types work."""
        for mem_type in MEMORY_TYPES:
            store.save(mem_type, "test-key", {"data": "test"})
            entry = store.get(mem_type, "test-key")
            assert entry is not None
            assert entry["data"] == "test"

    def test_additive_memory(self, store):
        """Test that memory is additive (multiple saves)."""
        store.save("pattern", "test", {"version": 1})
        store.save("pattern", "test", {"version": 2})

        # Get should return the most recent
        entry = store.get("pattern", "test")
        assert entry["version"] == 2

        # List should show both
        entries = store.list_all("pattern")
        assert len(entries) == 2

    def test_search_with_limit(self, store):
        """Test search with limit."""
        for i in range(10):
            store.save("pattern", f"test-{i}", {"index": i})

        results = store.search("pattern", limit=5)
        assert len(results) == 5
