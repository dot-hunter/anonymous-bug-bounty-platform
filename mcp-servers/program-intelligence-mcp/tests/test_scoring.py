"""Tests for Priority Engine."""

import pytest
from scoring.priority_engine import PriorityEngine, WEIGHTS, TIER_THRESHOLDS


@pytest.fixture
def engine():
    """Create a PriorityEngine instance."""
    return PriorityEngine()


class TestPriorityEngine:
    """Test the PriorityEngine class."""

    def test_score_program_minimal(self, engine):
        """Test scoring a minimal program."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne"}
        result = engine.score_program(program)
        assert "total_score" in result
        assert "tier" in result
        assert "component_scores" in result
        assert "reasoning" in result
        assert "recommended_next_action" in result

    def test_score_range(self, engine):
        """Test that score is between 0 and 1."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne"}
        result = engine.score_program(program)
        assert 0 <= result["total_score"] <= 1

    def test_score_high_bounty(self, engine):
        """Test that high bounty increases score."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "max_bounty": 50000,
        }
        result = engine.score_program(program)
        assert result["component_scores"]["reward"] == 1.0

    def test_score_wildcards(self, engine):
        """Test that wildcards increase attack surface score."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "wildcards": ["*.test.com", "*.api.test.com"],
        }
        result = engine.score_program(program)
        assert result["component_scores"]["attack_surface"] > 0

    def test_score_graphql(self, engine):
        """Test that GraphQL increases score."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "graphql": ["/graphql"],
        }
        result = engine.score_program(program)
        assert result["component_scores"]["graphql"] == 1.0

    def test_score_apis(self, engine):
        """Test that APIs increase score."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "public_apis": ["https://api.test.com/v1", "https://api.test.com/v2"],
        }
        result = engine.score_program(program)
        assert result["component_scores"]["api_presence"] > 0

    def test_tier_critical(self, engine):
        """Test critical tier for high scores."""
        assert engine._score_to_tier(0.9) == "critical"
        assert engine._score_to_tier(0.85) == "critical"

    def test_tier_high(self, engine):
        """Test high tier."""
        assert engine._score_to_tier(0.70) == "high"
        assert engine._score_to_tier(0.80) == "high"

    def test_tier_medium(self, engine):
        """Test medium tier."""
        assert engine._score_to_tier(0.50) == "medium"
        assert engine._score_to_tier(0.60) == "medium"

    def test_tier_low(self, engine):
        """Test low tier."""
        assert engine._score_to_tier(0.30) == "low"
        assert engine._score_to_tier(0.40) == "low"

    def test_tier_very_low(self, engine):
        """Test very low tier."""
        assert engine._score_to_tier(0.1) == "very_low"
        assert engine._score_to_tier(0.0) == "very_low"

    def test_recommend_next_action_critical(self, engine):
        """Test next action recommendation for critical tier."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne", "wildcards": ["*.test.com"]}
        scores = {"attack_surface": 0.8, "api_presence": 0.2, "graphql": 0.0, "cloud_assets": 0.0, "github": 0.0}
        action = engine._recommend_next_action(program, scores, "critical")
        assert "recon" in action.lower() or "subdomain" in action.lower()

    def test_recommend_next_action_medium(self, engine):
        """Test next action recommendation for medium tier."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne"}
        scores = {"attack_surface": 0.3, "api_presence": 0.3, "graphql": 0.0, "cloud_assets": 0.0, "github": 0.0}
        action = engine._recommend_next_action(program, scores, "medium")
        assert "research" in action.lower()

    def test_recommend_next_action_low(self, engine):
        """Test next action recommendation for low tier."""
        program = {"handle": "test", "name": "Test", "platform": "HackerOne"}
        scores = {"attack_surface": 0.1, "api_presence": 0.1, "graphql": 0.0, "cloud_assets": 0.0, "github": 0.0}
        action = engine._recommend_next_action(program, scores, "low")
        assert "monitor" in action.lower() or "passive" in action.lower()

    def test_rank_programs(self, engine, tmp_path):
        """Test ranking programs."""
        from discovery.engine import DiscoveryEngine

        db_path = tmp_path / "test_rank.db.json"
        disc = DiscoveryEngine(db_path=db_path)
        disc._merge_programs([
            {"handle": "high", "name": "High", "platform": "HackerOne", "max_bounty": 50000, "wildcards": ["*.high.com"]},
            {"handle": "low", "name": "Low", "platform": "HackerOne", "max_bounty": 100},
        ])

        ranked = engine.rank_programs(disc, top_n=10)
        assert len(ranked) == 2
        # High bounty program should rank first
        assert ranked[0]["handle"] == "high"
        assert ranked[0]["score"] > ranked[1]["score"]

    def test_weights_sum_to_one(self):
        """Test that weights sum to approximately 1.0."""
        total = sum(WEIGHTS.values())
        assert abs(total - 1.0) < 0.01

    def test_score_github_repos(self, engine):
        """Test that GitHub repos increase score."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "github": ["org/repo1", "org/repo2", "org/repo3"],
        }
        result = engine.score_program(program)
        assert result["component_scores"]["github"] > 0

    def test_score_confidence(self, engine):
        """Test confidence scoring."""
        program = {
            "handle": "test",
            "name": "Test",
            "platform": "HackerOne",
            "confidence": 0.9,
        }
        result = engine.score_program(program)
        assert result["component_scores"]["confidence"] == 0.9
