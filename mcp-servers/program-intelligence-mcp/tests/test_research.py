"""Tests for Research Agent."""

import json
import pytest
from pathlib import Path

from research.research_agent import ResearchAgent


@pytest.fixture
def agent(tmp_path):
    """Create a ResearchAgent with temp directory."""
    return ResearchAgent(research_dir=tmp_path / "research")


@pytest.fixture
def sample_program():
    """Create a sample program for testing."""
    return {
        "handle": "testprog",
        "name": "Test Program",
        "platform": "HackerOne",
        "domains": ["testprog.com", "api.testprog.com"],
        "wildcards": ["*.testprog.com"],
        "documentation": ["https://docs.testprog.com"],
        "developer_docs": "https://dev.testprog.com",
        "sdks": ["python-sdk", "js-sdk"],
        "public_apis": ["https://api.testprog.com/v1"],
        "graphql": ["/graphql"],
        "github": ["testprog/core", "testprog/api"],
        "technology_stack": ["react", "nodejs"],
        "authentication": {"types": ["oauth", "jwt"]},
        "javascript_assets": ["https://testprog.com/app.js"],
        "cloud_assets": {"providers": ["aws"]},
        "out_of_scope": ["blog.testprog.com"],
    }


class TestResearchAgent:
    """Test the ResearchAgent class."""

    def test_generate_dossier(self, agent, sample_program):
        """Test generating a research dossier."""
        dossier = agent.generate_dossier(sample_program)
        assert dossier["handle"] == "testprog"
        assert dossier["name"] == "Test Program"
        assert "sections" in dossier

    def test_dossier_has_documentation_section(self, agent, sample_program):
        """Test dossier includes documentation section."""
        dossier = agent.generate_dossier(sample_program)
        assert "documentation" in dossier["sections"]
        assert len(dossier["sections"]["documentation"]["official_docs"]) > 0

    def test_dossier_has_github_section(self, agent, sample_program):
        """Test dossier includes GitHub section."""
        dossier = agent.generate_dossier(sample_program)
        assert "github" in dossier["sections"]
        assert len(dossier["sections"]["github"]["known_repositories"]) == 2

    def test_dossier_has_api_section(self, agent, sample_program):
        """Test dossier includes API section."""
        dossier = agent.generate_dossier(sample_program)
        assert "api" in dossier["sections"]
        assert dossier["sections"]["api"]["has_swagger"] is False

    def test_dossier_has_technology_section(self, agent, sample_program):
        """Test dossier includes technology section."""
        dossier = agent.generate_dossier(sample_program)
        assert "technology" in dossier["sections"]
        assert "react" in dossier["sections"]["technology"]["known_stack"]

    def test_dossier_has_authentication_section(self, agent, sample_program):
        """Test dossier includes authentication section."""
        dossier = agent.generate_dossier(sample_program)
        assert "authentication" in dossier["sections"]

    def test_dossier_has_assets_section(self, agent, sample_program):
        """Test dossier includes assets section."""
        dossier = agent.generate_dossier(sample_program)
        assert "assets" in dossier["sections"]
        assert len(dossier["sections"]["assets"]["domains"]) == 2
        assert len(dossier["sections"]["assets"]["wildcards"]) == 1

    def test_dossier_has_recon_recommendations(self, agent, sample_program):
        """Test dossier includes recon recommendations."""
        dossier = agent.generate_dossier(sample_program)
        assert "recon_recommendations" in dossier["sections"]
        recs = dossier["sections"]["recon_recommendations"]
        assert len(recs) > 0

    def test_dossier_has_suggested_actions(self, agent, sample_program):
        """Test dossier includes suggested actions."""
        dossier = agent.generate_dossier(sample_program)
        assert "suggested_actions" in dossier["sections"]
        actions = dossier["sections"]["suggested_actions"]
        assert len(actions) > 0

    def test_dossier_saves_to_disk(self, agent, sample_program):
        """Test that dossier is saved to disk."""
        agent.generate_dossier(sample_program)
        dossier_path = agent.research_dir / "testprog.json"
        assert dossier_path.exists()

    def test_get_dossier_cached(self, agent, sample_program):
        """Test retrieving cached dossier."""
        agent.generate_dossier(sample_program)
        cached = agent.get_dossier("testprog")
        assert cached is not None
        assert cached["handle"] == "testprog"

    def test_get_dossier_not_found(self, agent):
        """Test retrieving non-existent dossier."""
        cached = agent.get_dossier("nonexistent")
        assert cached is None

    def test_count_dossiers(self, agent, sample_program):
        """Test counting dossiers."""
        assert agent.count_dossiers() == 0
        agent.generate_dossier(sample_program)
        assert agent.count_dossiers() == 1

    def test_generate_dossier_minimal_program(self, agent):
        """Test generating dossier for minimal program."""
        minimal = {"handle": "minimal", "name": "Minimal", "platform": "HackerOne"}
        dossier = agent.generate_dossier(minimal)
        assert dossier["handle"] == "minimal"
        assert "sections" in dossier

    def test_generate_dossier_no_handle(self, agent):
        """Test generating dossier without handle."""
        result = agent.generate_dossier({"name": "No Handle"})
        assert "error" in result

    def test_recon_recommendations_wildcards(self, agent):
        """Test recon recommendations for wildcard programs."""
        program = {
            "handle": "wild",
            "name": "Wild",
            "platform": "HackerOne",
            "wildcards": ["*.wild.com", "*.api.wild.com"],
        }
        dossier = agent.generate_dossier(program)
        recs = dossier["sections"]["recon_recommendations"]
        assert any("Wildcard" in r or "wildcard" in r for r in recs)

    def test_recon_recommendations_graphql(self, agent):
        """Test recon recommendations for GraphQL programs."""
        program = {
            "handle": "gql",
            "name": "GQL",
            "platform": "HackerOne",
            "graphql": ["/graphql"],
        }
        dossier = agent.generate_dossier(program)
        recs = dossier["sections"]["recon_recommendations"]
        assert any("GraphQL" in r or "graphql" in r for r in recs)

    def test_suggested_actions_certificate_transparency(self, agent, sample_program):
        """Test suggested actions include certificate transparency."""
        dossier = agent.generate_dossier(sample_program)
        actions = dossier["sections"]["suggested_actions"]
        action_types = [a["action"] for a in actions]
        assert "certificate_transparency" in action_types

    def test_suggested_actions_github_search(self, agent, sample_program):
        """Test suggested actions include GitHub search."""
        dossier = agent.generate_dossier(sample_program)
        actions = dossier["sections"]["suggested_actions"]
        action_types = [a["action"] for a in actions]
        assert "github_search" in action_types
