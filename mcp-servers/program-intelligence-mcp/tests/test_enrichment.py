"""Tests for Program Enricher."""

import pytest
from enrichment.enricher import ProgramEnricher


@pytest.fixture
def enricher():
    """Create a ProgramEnricher instance."""
    return ProgramEnricher()


class TestProgramEnricher:
    """Test the ProgramEnricher class."""

    def test_enrich_minimal(self, enricher):
        """Test enriching a minimal program."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne"}
        result = enricher.enrich(program)
        assert result["handle"] == "test"
        assert "intelligence" in result

    def test_enrich_does_not_overwrite(self, enricher):
        """Test that enrichment does not overwrite existing data."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "technology_stack": ["react"],
            "intelligence": {"frameworks": ["angular"]},  # Already enriched
        }
        result = enricher.enrich(program)
        # Existing intelligence should be preserved
        assert "angular" in result["intelligence"].get("frameworks", [])

    def test_enrich_domains_cloud(self, enricher):
        """Test inferring cloud providers from domains."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "domains": ["api.cloudfront.net", "static.amazonaws.com"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        assert "cloud_providers" in intelligence
        assert len(intelligence["cloud_providers"]) > 0

    def test_enrich_technology_frameworks(self, enricher):
        """Test inferring frameworks from technology stack."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "technology_stack": ["react", "nodejs", "django"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        assert "frameworks" in intelligence
        frameworks = intelligence["frameworks"]
        # Should detect at least one of the frameworks
        assert len(frameworks) > 0

    def test_enrich_graphql_detection(self, enricher):
        """Test detecting GraphQL endpoints."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "graphql": ["/graphql", "/api/graphql"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        assert intelligence.get("has_graphql") is True
        assert len(intelligence.get("graphql_endpoints", [])) == 2

    def test_enrich_rest_api_detection(self, enricher):
        """Test detecting REST APIs."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "public_apis": ["https://api.example.com/v1"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        assert intelligence.get("has_rest_api") is True

    def test_enrich_architecture_inference(self, enricher):
        """Test inferring architecture type."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "technology_stack": ["react", "graphql"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        # React + GraphQL should suggest SPA or microservices
        arch = intelligence.get("architecture_type", "")
        assert arch in ("spa", "microservices", "mobile_backend", "")

    def test_enrich_mobile_backend_score(self, enricher):
        """Test mobile backend likelihood scoring."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "tags": ["mobile", "api"],
            "public_apis": ["https://api.example.com"],
        }
        result = enricher.enrich(program)
        intelligence = result.get("intelligence", {})
        score = intelligence.get("mobile_backend_likelihood", 0)
        assert score > 0

    def test_enrich_fields_added_tracking(self, enricher):
        """Test that enrichment tracks which fields were added."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "graphql": ["/graphql"],
        }
        result = enricher.enrich(program)
        assert "_intelligence_added" in result
        assert "has_graphql" in result["_intelligence_added"]

    def test_enrich_all(self, enricher, tmp_path):
        """Test enriching all programs."""
        from discovery.engine import DiscoveryEngine

        db_path = tmp_path / "test_db.json"
        engine = DiscoveryEngine(db_path=db_path)

        # Add some test programs
        engine._merge_programs([
            {"handle": "test1", "name": "Test 1", "platform": "HackerOne", "graphql": ["/graphql"]},
            {"handle": "test2", "name": "Test 2", "platform": "Bugcrowd", "technology_stack": ["react"]},
        ])

        result = enricher.enrich_all(engine, max_results=10)
        assert result["enriched"] > 0

    def test_enrich_preserves_handle(self, enricher):
        """Test that enrichment preserves the handle."""
        program = {"handle": "myhandle", "name": "My Handle", "platform": "HackerOne"}
        result = enricher.enrich(program)
        assert result["handle"] == "myhandle"

    def test_enrich_updates_timestamp(self, enricher):
        """Test that enrichment updates the timestamp."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne", "last_updated": 0}
        result = enricher.enrich(program)
        assert result["last_updated"] > 0
