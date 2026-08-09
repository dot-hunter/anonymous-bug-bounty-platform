"""
Authorization Resolver — deterministic in-scope/out-of-scope decisions.

Given a program's normalized scope and a target (hostname or URL),
resolve_authorization() returns a verdict with full provenance:

    verdict: in_scope | out_of_scope | unknown
    rule:    which scope entry matched ("*.example.com" wildcard)
    target:  the normalized target
    reason:  human-readable explanation

Rules (in priority order):
  1. Explicit (non-wildcard) out-of-scope entry  -> out_of_scope
     (deliberate per-host/path exclusions always win)
  2. Exact in-scope domain match                 -> in_scope
     (authoritative allowlist: beats wildcard OOS catch-alls)
  3. URL prefix match against in-scope URL       -> in_scope
  4. Out-of-scope wildcard parent match          -> out_of_scope
     (catch-all "everything else" exclusions + carve-outs)
  5. In-scope wildcard parent match              -> in_scope
  6. Subdomain of in-scope domain                -> in_scope
  7. Otherwise                                   -> unknown (not covered)

The resolver is pure: it makes no network requests and performs no
testing. It answers "is this target covered by this program's scope?"
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from normalizer import ScopeNormalizer

logger = logging.getLogger("program-intelligence.resolver")


class AuthorizationResolver:
    """Deterministic scope authorization resolution."""

    @classmethod
    def resolve_authorization(
        cls,
        program: dict,
        target: str,
    ) -> dict:
        """Resolve whether `target` is authorized by `program`'s scope.

        Args:
            program: program dict with normalized scope (or raw scope — will normalize).
            target:  hostname or URL, e.g. "sub.example.com" or "https://api.example.com/v1".

        Returns:
            dict with verdict, rule, target, reason, program.
        """
        scope = program.get("scope")
        if not isinstance(scope, dict) or not scope.get("domains") and not scope.get("wildcards"):
            scope = ScopeNormalizer.normalize_scope(scope, program)

        host = cls._extract_host(target)
        if not host:
            return cls._verdict("unknown", None, target, "Could not parse target as hostname/URL")

        # 1. EXPLICIT (non-wildcard) out-of-scope entries — deliberate
        #    per-host/path exclusions win over everything.
        explicit_oos = [
            e for e in scope.get("out_of_scope", [])
            if not e.strip().lower().startswith("*.")
        ]
        oos_hits = cls._match_scope(explicit_oos, host, target)
        if oos_hits:
            return cls._verdict("out_of_scope", oos_hits[0], target,
                                f"Target matches explicit out-of-scope entry: {oos_hits[0]}")

        # 2. Exact in-scope domain match — the authoritative allowlist.
        #    An explicitly listed host stays in scope even when a wildcard
        #    out-of-scope entry (e.g. "*.dmp.gouv.fr") would also match it.
        if host in scope.get("domains", []):
            return cls._verdict("in_scope", host, target,
                                f"Exact in-scope domain match: {host}")

        # 3. URL prefix match against in-scope URL assets
        for asset in scope.get("assets", []):
            if cls._url_matches(asset, target):
                return cls._verdict("in_scope", asset, target,
                                    f"URL scope entry {asset} matches target")

        # 4. Out-of-scope wildcard parents — catch-all exclusions
        #    ("everything else under this parent") and carve-outs like
        #    "*.dev.api.acme.com" out of "*.api.acme.com".
        wildcard_oos = [
            e for e in scope.get("out_of_scope", [])
            if e.strip().lower().startswith("*.")
        ]
        oos_hits = cls._match_scope(wildcard_oos, host, target)
        if oos_hits:
            return cls._verdict("out_of_scope", oos_hits[0], target,
                                f"Target matches out-of-scope wildcard: {oos_hits[0]}")

        # 5. In-scope wildcard parent covers target
        for wc in scope.get("wildcards", []):
            wc_host = cls._strip_wildcard(wc)
            if cls._is_subdomain_of(host, wc_host):
                return cls._verdict("in_scope", wc, target,
                                    f"In-scope wildcard {wc} covers {host}")

        # 6. Subdomain of an in-scope domain (domains imply subdomains)
        for dom in scope.get("domains", []):
            if cls._is_subdomain_of(host, dom):
                return cls._verdict("in_scope", dom, target,
                                    f"Subdomain of in-scope domain: {host} ⊂ {dom}")

        return cls._verdict("unknown", None, target,
                            "Target is not covered by this program's scope")

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _verdict(verdict: str, rule: str | None, target: str, reason: str) -> dict:
        return {
            "verdict": verdict,
            "rule": rule,
            "target": target,
            "reason": reason,
        }

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract hostname from a target string (hostname or URL)."""
        target = (target or "").strip().lower()
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            return (parsed.hostname or "").rstrip(".")
        # Strip path, port, userinfo
        if "/" in target:
            target = target.split("/")[0]
        if "@" in target:
            target = target.rsplit("@", 1)[-1]
        if ":" in target and not target.startswith("["):
            # port (avoid IPv6 bracket handling for simplicity)
            host_part = target.split(":", 1)[0]
            return host_part.rstrip(".")
        return target.rstrip(".")

    @staticmethod
    def _strip_wildcard(wc: str) -> str:
        wc = wc.strip().lower()
        if wc.startswith("*."):
            return wc[2:]
        return wc

    @classmethod
    def _is_subdomain_of(cls, host: str, parent: str) -> bool:
        parent = parent.strip().lower().rstrip(".")
        host = host.rstrip(".")
        if not parent:
            return False
        return host == parent or host.endswith("." + parent)

    @classmethod
    def _match_scope(cls, entries: list[str], host: str, target: str) -> list[str]:
        """Return scope entries that match the target."""
        hits: list[str] = []
        for entry in entries:
            e = entry.strip().lower()
            if not e:
                continue
            if "://" in e:
                if cls._url_matches(e, target):
                    hits.append(entry)
                continue
            if "/" in e:
                # Path-bearing entry without scheme, e.g. "acme.com/admin"
                if cls._host_path_matches(e, target):
                    hits.append(entry)
                continue
            if e.startswith("*."):
                if cls._is_subdomain_of(host, cls._strip_wildcard(e)):
                    hits.append(entry)
            elif e == host or cls._is_subdomain_of(host, e):
                hits.append(entry)
        return hits

    @classmethod
    def _host_path_matches(cls, entry: str, target: str) -> bool:
        """Match a bare 'host/path' entry against a URL target."""
        entry = entry.strip().lower()
        entry_host, _, entry_path = entry.partition("/")
        entry_path = "/" + entry_path
        try:
            t = urlparse(target if "://" in target else f"https://{target}")
            if not t.hostname:
                return False
            if entry_host.rstrip(".") != t.hostname.rstrip("."):
                return False
            t_path = t.path or "/"
            return t_path == entry_path or t_path.startswith(entry_path.rstrip("/") + "/") or t_path.startswith(entry_path)
        except Exception:
            return False

    @staticmethod
    def _url_matches(scope_url: str, target: str) -> bool:
        """True if target URL falls under scope_url prefix."""
        try:
            s = urlparse(scope_url)
            t = urlparse(target if "://" in target else f"https://{target}")
            if not s.hostname or not t.hostname:
                return False
            if s.hostname != t.hostname:
                return False
            s_path = s.path.rstrip("/") or ""
            t_path = t.path.rstrip("/") or ""
            if not s_path:
                return True  # scope is the whole origin
            return t_path == s_path or t_path.startswith(s_path + "/")
        except Exception:
            return False
