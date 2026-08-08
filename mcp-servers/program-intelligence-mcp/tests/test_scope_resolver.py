"""Tests for ScopeNormalizer and AuthorizationResolver."""

import pytest

from normalizer import ScopeNormalizer
from resolver import AuthorizationResolver


@pytest.fixture
def sample_program():
    return {
        "handle": "acme",
        "name": "Acme",
        "platform": "HackerOne",
        "scope": {
            "domains": ["acme.com"],
            "wildcards": ["*.api.acme.com"],
            "assets": ["https://acme.com/portal", "app://mobile"],
            "subdomains": ["old.acme.com"],
            "out_of_scope": ["acme.com/admin", "dev.api.acme.com"],
        },
    }


class TestScopeNormalizer:
    def test_dict_scope(self, sample_program):
        normalized = ScopeNormalizer.normalize_scope(sample_program["scope"])
        assert "acme.com" in normalized["domains"]
        assert "*.api.acme.com" in normalized["wildcards"]
        assert "acme.com/admin" in normalized["out_of_scope"]
        assert "app://mobile" in normalized["assets"]

    def test_flat_list_scope(self):
        normalized = ScopeNormalizer.normalize_scope(
            ["https://example.com", "*.example.org", "admin.example.com"]
        )
        assert "example.org" in normalized["wildcards"] or "*.example.org" in normalized["wildcards"]
        # https://example.com should be classified as domain (host part)
        assert "example.com" in normalized["domains"]

    def test_dataset_rows_scope(self):
        scope = {
            "in_scope": [
                {"asset_type": "wildcard", "asset_identifier": "*.foo.com"},
                {"asset_type": "domain", "asset_identifier": "foo.com"},
                {"asset_type": "url", "asset_identifier": "https://foo.com/api"},
            ],
            "out_of_scope": [{"asset_type": "url", "asset_identifier": "https://foo.com/admin"}],
        }
        normalized = ScopeNormalizer.normalize_scope(scope)
        assert "*.foo.com" in normalized["wildcards"]
        assert "foo.com" in normalized["domains"]
        assert "https://foo.com/admin" in normalized["out_of_scope"]

    def test_scope_from_raw_fallback(self):
        raw = {"domains": ["raw.com"]}
        normalized = ScopeNormalizer.normalize_scope(None, raw)
        assert "raw.com" in normalized["domains"]

    def test_dedupe(self):
        normalized = ScopeNormalizer.normalize_scope(
            {"domains": ["a.com", "a.com", "b.com"]}
        )
        assert normalized["domains"] == ["a.com", "b.com"]


class TestAuthorizationResolver:
    def test_exact_domain_in_scope(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "acme.com")
        assert verdict["verdict"] == "in_scope"
        assert verdict["rule"] == "acme.com"

    def test_subdomain_of_in_scope_domain(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "www.acme.com")
        assert verdict["verdict"] == "in_scope"

    def test_wildcard_match(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "v1.api.acme.com")
        assert verdict["verdict"] == "in_scope"
        assert verdict["rule"] == "*.api.acme.com"

    def test_out_of_scope_exact(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "https://acme.com/admin")
        assert verdict["verdict"] == "out_of_scope"

    def test_out_of_scope_wildcard_child(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "dev.api.acme.com")
        assert verdict["verdict"] == "out_of_scope"

    def test_unknown_target(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "unrelated.net")
        assert verdict["verdict"] == "unknown"

    def test_url_scope_prefix(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "https://acme.com/portal/settings")
        assert verdict["verdict"] == "in_scope"

    def test_url_scope_outside_prefix(self, sample_program):
        # /portal/settings is in scope but /other is not covered by the URL rule
        # (it IS covered by domain acme.com though) — assert not out_of_scope
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "https://acme.com/other")
        assert verdict["verdict"] in ("in_scope", "unknown")

    def test_requires_target(self, sample_program):
        verdict = AuthorizationResolver.resolve_authorization(sample_program, "")
        assert verdict["verdict"] == "unknown"
