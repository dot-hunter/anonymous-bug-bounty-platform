"""End-to-end pipeline tests: provider -> normalize -> resolve -> rank.

These tests exercise the full authorized-discovery chain with local
(offline) fixtures, so they are deterministic and require no network.
"""

import json
import pytest

import providers
from normalizer import ScopeNormalizer
from resolver import AuthorizationResolver
from ranker import WordPressRanker
from providers.hackerone import HackerOneProvider
from providers.securitytxt import SecurityTxtProvider


class TestProviderRegistry:
    def test_list_builtin(self):
        assert "hackerone" in providers.BUILTIN_PROVIDERS
        assert "bugcrowd" in providers.BUILTIN_PROVIDERS
        assert "intigriti" in providers.BUILTIN_PROVIDERS
        assert "yeswehack" in providers.BUILTIN_PROVIDERS
        assert "securitytxt" in providers.BUILTIN_PROVIDERS

    def test_get_provider(self):
        prov = providers.get_provider("hackerone")
        assert prov.name == "hackerone"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError):
            providers.get_provider("nope")

    def test_discover_unknown_raises(self):
        with pytest.raises(ValueError):
            providers.discover(provider="bogus")


class TestHackerOneProviderMapping:
    def test_map_row(self):
        prov = HackerOneProvider()
        row = {
            "name": "Acme Security",
            "url": "https://hackerone.com/acme",
            "offers_bounties": True,
            "scope": {
                "in_scope": [
                    {"asset_type": "wildcard", "asset_identifier": "*.acme.com"},
                    {"asset_type": "domain", "asset_identifier": "acme.com"},
                    {"asset_type": "url", "asset_identifier": "https://api.acme.com"},
                ],
                "out_of_scope": [
                    {"asset_type": "url", "asset_identifier": "https://acme.com/admin"}
                ],
            },
        }
        mapped = prov._map_row(row)
        assert mapped["handle"] == "acme"
        assert mapped["platform"] == "HackerOne"
        assert "*.acme.com" in mapped["scope"]["wildcards"]
        assert "acme.com" in mapped["scope"]["domains"]
        assert "https://acme.com/admin" in mapped["scope"]["out_of_scope"]
        assert mapped["tags"] == ["bounty"]

    def test_normalize_program_pipeline(self):
        prov = HackerOneProvider()
        row = {
            "name": "Acme Security",
            "url": "https://hackerone.com/acme",
            "offers_bounties": False,
            "scope": {
                "in_scope": [
                    {"asset_type": "wildcard", "asset_identifier": "*.acme.com"},
                ],
                "out_of_scope": [],
            },
        }
        normalized = prov._normalize(prov._map_row(row))
        assert normalized["platform"] == "HackerOne"
        assert normalized["source"] == "provider:hackerone"
        assert normalized["handle"] == "acme"


class TestSecurityTxtProvider:
    def test_parse_fields(self):
        prov = SecurityTxtProvider()
        body = (
            "Contact: mailto:security@example.com\n"
            "Expires: 2027-01-01T00:00:00.000Z\n"
            "Policy: https://example.com/security-policy\n"
            "# comment line\n"
            "Safe Harbor: We will not pursue legal action\n"
        )
        fields = prov._parse(body)
        assert fields["contact"] == "mailto:security@example.com"
        assert fields["policy"].startswith("https://")
        assert prov._has_safe_harbor(body) is True

    def test_no_safe_harbor(self):
        prov = SecurityTxtProvider()
        assert prov._has_safe_harbor("Contact: mailto:a@b.c") is False


class TestEndToEndPipeline:
    """Full chain: raw provider row -> normalized program -> authorization -> rank."""

    def test_h1_row_to_rank(self):
        prov = HackerOneProvider()
        row = {
            "name": "Acme Security",
            "url": "https://hackerone.com/acme",
            "offers_bounties": True,
            "scope": {
                "in_scope": [
                    {"asset_type": "wildcard", "asset_identifier": "*.acme.com"},
                    {"asset_type": "domain", "asset_identifier": "acme.com"},
                ],
                "out_of_scope": [],
            },
        }
        program = prov._normalize(prov._map_row(row))
        assert program is not None

        # Authorization
        verdict = AuthorizationResolver.resolve_authorization(program, "blog.acme.com")
        assert verdict["verdict"] == "in_scope"
        verdict_oos = AuthorizationResolver.resolve_authorization(program, "evil.com")
        assert verdict_oos["verdict"] == "unknown"

        # Rank a fingerprint for an in-scope asset
        fingerprint = {
            "is_wordpress": True,
            "authorized": True,
            "url": "https://blog.acme.com",
            "version": "6.5.2",
            "rest_api": "https://blog.acme.com/wp-json/",
            "login_page": "https://blog.acme.com/wp-login.php",
            "themes": ["twentytwentyfour"],
            "plugins": ["contact-form-7", "elementor", "woocommerce"],
            "detected_paths": [],
            "errors": [],
        }
        ranked = WordPressRanker.rank_target(program, fingerprint)
        assert ranked["score"] >= 85  # 30+15+5+10+10+15+5 = 90 (bounty + wildcard present)
        assert ranked["is_wordpress"] is True

    def test_program_schema_compat(self):
        """New providers must produce ProgramSchema-compatible programs."""
        from models.program import ProgramSchema
        prov = HackerOneProvider()
        row = {
            "name": "Acme Security",
            "url": "https://hackerone.com/acme",
            "offers_bounties": True,
            "scope": {"in_scope": [], "out_of_scope": []},
        }
        program = prov._normalize(prov._map_row(row))
        valid, errors = ProgramSchema.validate(program)
        assert valid, errors
