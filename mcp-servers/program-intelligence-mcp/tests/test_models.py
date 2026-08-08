"""Tests for Program Intelligence data models."""

import pytest
import time
from models.program import Program, ProgramSchema


class TestProgramSchema:
    """Test the ProgramSchema normalization and validation."""

    def test_normalize_minimal(self):
        """Test normalizing a minimal program dict."""
        raw = {"handle": "test", "name": "Test Program"}
        result = ProgramSchema.normalize(raw)
        assert result["handle"] == "test"
        assert result["name"] == "Test Program"
        # Platform defaults to None when not provided (caller can set "unknown")
        assert result["platform"] is None or result["platform"] == "unknown"
        assert result["last_updated"] is not None

    def test_normalize_full(self):
        """Test normalizing a full program dict."""
        raw = {
            "handle": "uber",
            "name": "Uber",
            "platform": "HackerOne",
            "url": "https://hackerone.com/uber",
            "base_bounty": 500,
            "max_bounty": 50000,
            "scope": {"domains": ["*.uber.com"], "wildcards": ["*.uber.com"]},
            "tags": ["transport", "mobility"],
        }
        result = ProgramSchema.normalize(raw)
        assert result["handle"] == "uber"
        assert result["name"] == "Uber"
        assert result["platform"] == "HackerOne"
        assert result["max_bounty"] == 50000
        assert "*.uber.com" in result["domains"]
        assert "*.uber.com" in result["wildcards"]

    def test_normalize_from_slug(self):
        """Test normalizing when handle comes from slug."""
        raw = {"slug": "tinder", "name": "Tinder", "platform": "HackerOne"}
        result = ProgramSchema.normalize(raw)
        assert result["handle"] == "tinder"

    def test_normalize_reward_dict(self):
        """Test normalizing when reward is a dict."""
        raw = {
            "handle": "test",
            "name": "Test",
            "reward": {"base": 1000, "max": 10000},
        }
        result = ProgramSchema.normalize(raw)
        assert result["base_bounty"] == 1000
        assert result["max_bounty"] == 10000

    def test_normalize_reward_flat(self):
        """Test normalizing when reward is flat values."""
        raw = {
            "handle": "test",
            "name": "Test",
            "base_bounty": 500,
            "max_bounty": 5000,
        }
        result = ProgramSchema.normalize(raw)
        assert result["base_bounty"] == 500
        assert result["max_bounty"] == 5000

    def test_validate_valid_program(self):
        """Test validation with valid program."""
        valid, errors = ProgramSchema.validate({"handle": "test", "name": "Test", "platform": "HackerOne"})
        assert valid is True
        assert len(errors) == 0

    def test_validate_missing_handle(self):
        """Test validation with missing handle."""
        valid, errors = ProgramSchema.validate({"name": "Test", "platform": "HackerOne"})
        assert valid is False
        assert any("handle" in e for e in errors)

    def test_validate_missing_name(self):
        """Test validation with missing name."""
        valid, errors = ProgramSchema.validate({"handle": "test", "platform": "HackerOne"})
        assert valid is False
        assert any("name" in e for e in errors)

    def test_validate_missing_platform(self):
        """Test validation with missing platform."""
        valid, errors = ProgramSchema.validate({"handle": "test", "name": "Test"})
        assert valid is False
        assert any("platform" in e for e in errors)

    def test_fields_list_complete(self):
        """Test that all required fields are in the schema."""
        required = [
            "handle", "name", "platform", "url", "reward", "scope",
            "out_of_scope", "policy", "safe_harbor", "assets", "domains",
            "subdomains", "wildcards", "cloud_assets", "github", "public_apis",
            "graphql", "javascript_assets", "documentation", "developer_docs",
            "sdks", "technology_stack", "authentication", "priority",
            "research_status", "recon_status", "historical_notes", "tags",
            "confidence", "last_updated", "intelligence",
        ]
        for field in required:
            assert field in ProgramSchema.FIELDS, f"Missing field: {field}"


class TestProgram:
    """Test the Program class."""

    def test_create_program(self):
        """Test creating a Program instance."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne"})
        assert prog.handle == "test"
        assert prog.name == "Test"

    def test_to_dict(self):
        """Test converting Program to dict."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne"})
        d = prog.to_dict()
        assert d["handle"] == "test"
        assert d["name"] == "Test"

    def test_update(self):
        """Test updating program data."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne"})
        prog.update({"max_bounty": 10000})
        assert prog.max_bounty == 10000

    def test_update_does_not_overwrite_with_none(self):
        """Test that update does not overwrite with None."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne", "max_bounty": 5000})
        prog.update({"max_bounty": None})
        assert prog.max_bounty == 5000

    def test_domains_property(self):
        """Test domains property."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne", "domains": ["a.com", "b.com"]})
        assert prog.domains == ["a.com", "b.com"]

    def test_wildcards_property(self):
        """Test wildcards property."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne", "wildcards": ["*.test.com"]})
        assert prog.wildcards == ["*.test.com"]

    def test_tags_property(self):
        """Test tags property."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne", "tags": ["web", "api"]})
        assert prog.tags == ["web", "api"]

    def test_confidence_property(self):
        """Test confidence property."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne", "confidence": 0.8})
        assert prog.confidence == 0.8

    def test_confidence_default(self):
        """Test confidence default value."""
        prog = Program({"handle": "test", "name": "Test", "platform": "HackerOne"})
        assert prog.confidence == 0.5
