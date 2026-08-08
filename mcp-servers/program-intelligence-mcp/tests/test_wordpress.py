"""Tests for the WordPress fingerprinting and ranking modules."""

import pytest

from wordpress import WordPressFingerprinter
from ranker import WordPressRanker


@pytest.fixture
def wp_fingerprint():
    return {
        "is_wordpress": True,
        "authorized": True,
        "url": "https://blog.acme.com",
        "version": "6.5.2",
        "rest_api": "https://blog.acme.com/wp-json/",
        "rest_namespaces": ["wp/v2"],
        "login_page": "https://blog.acme.com/wp-login.php",
        "themes": ["twentytwentyfour"],
        "plugins": ["contact-form-7", "elementor", "woocommerce"],
        "detected_paths": [],
        "errors": [],
    }


@pytest.fixture
def bounty_program():
    return {
        "handle": "acme",
        "name": "Acme",
        "platform": "HackerOne",
        "reward": {"base": 1000, "max": 50000},
        "scope": {
            "domains": ["acme.com"],
            "wildcards": ["*.acme.com"],
            "assets": [],
            "out_of_scope": [],
        },
    }


class TestFingerprinterAuthorization:
    def test_unauthorized_returns_error(self):
        fp = WordPressFingerprinter(authorized=False)
        result = fp.fingerprint("https://example.com", authorized=False)
        assert result["is_wordpress"] is False
        assert result["authorized"] is False

    def test_invalid_url(self):
        fp = WordPressFingerprinter(authorized=True)
        result = fp.fingerprint("", authorized=True)
        assert result["is_wordpress"] is False
        assert "error" in result

    def test_normalize_base_adds_scheme(self):
        assert WordPressFingerprinter._normalize_base("example.com") == "https://example.com"

    def test_normalize_base_keeps_scheme(self):
        assert WordPressFingerprinter._normalize_base("http://example.com") == "http://example.com"

    def test_extract_version(self):
        assert WordPressFingerprinter._extract_version("WordPress 6.5.2") == "6.5.2"
        assert WordPressFingerprinter._extract_version("WordPress 6.7") == "6.7"
        assert WordPressFingerprinter._extract_version("no version here") is None


class TestRanker:
    def test_full_rank(self, wp_fingerprint, bounty_program):
        ranked = WordPressRanker.rank_target(bounty_program, wp_fingerprint)
        assert ranked["is_wordpress"] is True
        # base 30 + plugins 15 (3*5) + theme 5 + rest 10 + login 10 + bounty 15 + wildcard 5
        assert ranked["score"] == 90
        assert ranked["max_score"] == 100

    def test_plugin_cap(self, wp_fingerprint, bounty_program):
        wp_fingerprint["plugins"] = ["a", "b", "c", "d", "e", "f"]  # 6 plugins = 30 -> capped 20
        ranked = WordPressRanker.rank_target(bounty_program, wp_fingerprint)
        plugin_comp = next(c for c in ranked["components"] if c["name"] == "plugins")
        assert plugin_comp["points"] == 20

    def test_not_wordpress_scores_zero(self, bounty_program):
        fp = {"is_wordpress": False, "url": "https://x.acme.com", "authorized": True}
        ranked = WordPressRanker.rank_target(bounty_program, fp)
        assert ranked["score"] == 0
        assert ranked["is_wordpress"] is False

    def test_score_cap_at_100(self, wp_fingerprint, bounty_program):
        wp_fingerprint["plugins"] = ["a", "b", "c", "d", "e"]  # would cap at 20
        ranked = WordPressRanker.rank_target(bounty_program, wp_fingerprint)
        assert ranked["score"] <= 100

    def test_no_bounty_no_wildcard(self, wp_fingerprint):
        program = {
            "handle": "acme",
            "scope": {"domains": ["acme.com"], "wildcards": [], "assets": [], "out_of_scope": []},
        }
        ranked = WordPressRanker.rank_target(program, wp_fingerprint)
        # base 30 + plugins 15 + theme 5 + rest 10 + login 10 = 70
        assert ranked["score"] == 70

    def test_rank_program_targets_sorted(self, wp_fingerprint, bounty_program):
        low = dict(wp_fingerprint)
        low["url"] = "https://low.acme.com"
        low["plugins"] = []
        low["rest_api"] = None
        low["login_page"] = None
        low["themes"] = []
        ranked = WordPressRanker.rank_program_targets(bounty_program, [low, wp_fingerprint])
        assert ranked[0]["url"] == wp_fingerprint["url"]
        assert ranked[0]["score"] >= ranked[1]["score"]
