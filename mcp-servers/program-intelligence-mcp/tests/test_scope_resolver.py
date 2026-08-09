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


class TestAuthorizationResolverPrecedence:
    """Regression: explicit in-scope entries must beat wildcard out-of-scope
    catch-alls, while unlisted children and carve-outs stay excluded."""

    @pytest.fixture
    def dmp_like_program(self):
        return {
            "handle": "dmp",
            "name": "DMP",
            "scope": {
                "in_scope": [
                    "api.dmp.gouv.fr",
                    "wps-cps.dmp.gouv.fr",
                    "wps-cps.cv.dmp.gouv.fr",
                    "auth.dmp.gouv.fr",
                    "web-mh.dmp.gouv.fr",
                    "lps.dmp.gouv.fr",
                    "lps2.dmp.gouv.fr",
                    "https://www.dmp.fr",
                    "https://www.dmp.gouv.fr",
                    "https://sip2.dmp.gouv.fr",
                ],
                "out_of_scope": [
                    "*.dmp.fr",
                    "*.dmp.gouv.fr",
                    "monespacesante.fr",
                    "monespacesante.gouv.fr",
                ],
            },
        }

    def test_explicit_in_scope_beats_wildcard_oos(self, dmp_like_program):
        # wps-cps.dmp.gouv.fr is explicitly in_scope; *.dmp.gouv.fr wildcard
        # must NOT knock it out of scope.
        verdict = AuthorizationResolver.resolve_authorization(
            dmp_like_program, "wps-cps.dmp.gouv.fr"
        )
        assert verdict["verdict"] == "in_scope"

    def test_other_explicit_in_scope_hosts_allowed(self, dmp_like_program):
        for host in ("api.dmp.gouv.fr", "auth.dmp.gouv.fr", "lps2.dmp.gouv.fr"):
            verdict = AuthorizationResolver.resolve_authorization(dmp_like_program, host)
            assert verdict["verdict"] == "in_scope", host

    def test_unlisted_child_caught_by_wildcard_oos(self, dmp_like_program):
        # evil.dmp.gouv.fr is NOT explicitly listed -> wildcard catch-all blocks it.
        verdict = AuthorizationResolver.resolve_authorization(
            dmp_like_program, "evil.dmp.gouv.fr"
        )
        assert verdict["verdict"] == "out_of_scope"
        assert "*.dmp.gouv.fr" in verdict["rule"]

    def test_explicit_oos_still_wins(self, dmp_like_program):
        verdict = AuthorizationResolver.resolve_authorization(
            dmp_like_program, "monespacesante.gouv.fr"
        )
        assert verdict["verdict"] == "out_of_scope"

    def test_unknown_not_listed(self, dmp_like_program):
        verdict = AuthorizationResolver.resolve_authorization(
            dmp_like_program, "unrelated.gov"
        )
        assert verdict["verdict"] == "unknown"

    def test_wildcard_oos_carveout_beats_wildcard_inscope(self):
        # "*.dev.api.acme.com" carved out of "*.api.acme.com" -> out_of_scope
        prog = {
            "scope": {
                "wildcards": ["*.api.acme.com"],
                "out_of_scope": ["*.dev.api.acme.com"],
            }
        }
        verdict = AuthorizationResolver.resolve_authorization(
            prog, "x.dev.api.acme.com"
        )
        assert verdict["verdict"] == "out_of_scope"
        # sibling still in scope
        verdict2 = AuthorizationResolver.resolve_authorization(
            prog, "x.prod.api.acme.com"
        )
        assert verdict2["verdict"] == "in_scope"
