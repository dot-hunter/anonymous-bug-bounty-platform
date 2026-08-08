"""
WordPress Fingerprinter — detect WordPress and enumerate plugins/themes.

IMPORTANT: This module only fingerprints assets that are *authorized*.
Every fingerprint_asset() call must be preceded by an authorization
check (resolver.resolve_authorization -> verdict == "in_scope"), or the
caller must pass authorized=True explicitly after verifying scope.

Fingerprinting is passive/lightweight:
  - GET / (generator meta tag, /wp-content/ references)
  - GET /wp-json/ (REST API root: namespaces, version)
  - GET /wp-login.php (login page present?)
  - GET /feed/ or /?feed=rss2 (generator meta)
  - Known plugin/theme probe paths (light, non-intrusive)

No payloads, no exploitation, no auth bypass attempts.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("program-intelligence.wordpress")

USER_AGENT = "ProgramIntelligenceFingerprinter/1.0 (bug bounty scope analysis)"
TIMEOUT = 10.0

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']*wordpress[^"\']*)["\']',
    re.IGNORECASE,
)
WP_CONTENT_RE = re.compile(r"""wp-content/(?:themes|plugins)/([^/"'\s]+)""", re.IGNORECASE)
WP_JSON_RE = re.compile(r'["\']/(?:index\.php\?rest_route=|wp-json/)', re.IGNORECASE)
VERSION_RE = re.compile(r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)

# Lightweight plugin slug probes (top-500 by install count, curated subset).
COMMON_PLUGINS = [
    "contact-form-7", "elementor", "woocommerce", "akismet", "yoast-seo",
    "wordfence", "jetpack", "wpforms-lite", "classic-editor", "all-in-one-seo-pack",
    "google-analytics-for-wordpress", "duplicate-post", "wp-super-cache", "w3-total-cache",
    "updraftplus", "really-simple-ssl", "redirection", "cookie-notice", "wp-mail-smtp",
    "litespeed-cache", "rank-math-seo", "astra-sites", "insert-headers-and-footers",
    "custom-post-type-ui", "regenerate-thumbnails", "better-wp-security", "limit-login-attempts-reloaded",
    "duplicator", "wp-optimize", "smush", "shortcodes-ultimate", "advanced-custom-fields",
    "tablepress", "autoptimize", "svg-support", "easy-digital-downloads", "the-events-calendar",
    "wp-file-manager", "user-role-editor", "disable-comments", "nextgen-gallery",
]

COMMON_THEMES = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo", "twentytwentyone",
    "twentytwenty", "twentynineteen", "astra", "generatepress", "kadence",
    "oceanwp", "hello-elementor", "storefront", "flavor", "blocksy",
]


class WordPressFingerprinter:
    """Fingerprints WordPress installations on authorized targets."""

    def __init__(self, authorized: bool = True, probe_plugins: bool = True):
        self.authorized = authorized
        self.probe_plugins = probe_plugins
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})
        # Honor the authorized_discovery policy knobs (graceful if absent).
        try:
            from config import fingerprinting_config
            cfg = fingerprinting_config()
            if not cfg.get("enabled", True):
                self.probe_plugins = False
                logger.info("Fingerprinting disabled by authorized_discovery policy")
            self.max_plugin_probes = int(cfg.get("max_plugin_probes", 10))
            self.max_theme_probes = int(cfg.get("max_theme_probes", 5))
        except Exception as exc:
            logger.debug("authorized_discovery policy not applied: %s", exc)
            self.max_plugin_probes = 10
            self.max_theme_probes = 5

    def fingerprint(self, url: str, authorized: bool | None = None) -> dict:
        """Fingerprint a single target URL.

        Args:
            url:        base URL of the target (scheme + host, optional path).
            authorized: override the authorized flag (default: constructor value).

        Returns:
            dict with is_wordpress, version, rest_api, login_page, themes,
            plugins, detected_paths, errors.
        """
        allowed = self.authorized if authorized is None else authorized
        if not allowed:
            return {
                "is_wordpress": False,
                "authorized": False,
                "error": "Target not authorized for fingerprinting. Resolve scope first.",
            }

        url = self._normalize_base(url)
        if not url:
            return {"is_wordpress": False, "authorized": True, "error": "Invalid URL"}

        result: dict[str, Any] = {
            "is_wordpress": False,
            "authorized": True,
            "url": url,
            "version": None,
            "rest_api": None,
            "rest_namespaces": [],
            "login_page": None,
            "themes": [],
            "plugins": [],
            "detected_paths": [],
            "errors": [],
        }

        # 1. Homepage: generator meta + wp-content refs
        home = self._get(url + "/")
        if home is not None:
            if home.status_code == 200:
                text = home.text[:200000]
                gen = GENERATOR_RE.search(text)
                if gen:
                    result["is_wordpress"] = True
                    result["version"] = self._extract_version(gen.group(1))
                    result["detected_paths"].append(url + "/")
                found = set(WP_CONTENT_RE.findall(text))
                if found:
                    result["is_wordpress"] = True
                    result["detected_paths"].append(url + "/wp-content/")
                    for slug in found:
                        if slug not in result["themes"] and slug not in result["plugins"]:
                            # wp-content/themes/<slug> vs wp-content/plugins/<slug>
                            if f"/wp-content/themes/{slug}/" in text:
                                result["themes"].append(slug)
                            else:
                                result["plugins"].append(slug)
            else:
                result["errors"].append(f"homepage HTTP {home.status_code}")

        # 2. REST API root
        rest = self._get(url + "/wp-json/")
        if rest is not None and rest.status_code == 200:
            result["rest_api"] = url + "/wp-json/"
            result["is_wordpress"] = True
            result["detected_paths"].append(url + "/wp-json/")
            try:
                data = rest.json()
                if isinstance(data, dict):
                    namespaces = data.get("namespaces", [])
                    result["rest_namespaces"] = [n for n in namespaces if isinstance(n, str)][:30]
                    if data.get("name") or data.get("description"):
                        result["is_wordpress"] = True
            except (ValueError, json.JSONDecodeError):
                pass

        # 3. Login page
        login = self._get(url + "/wp-login.php", allow_redirects=False)
        if login is not None and login.status_code in (200, 302):
            result["login_page"] = url + "/wp-login.php"
            result["is_wordpress"] = True
            result["detected_paths"].append(url + "/wp-login.php")
        elif login is not None and login.status_code == 404:
            result["errors"].append("wp-login.php 404")

        # 4. Feed generator
        if not result["is_wordpress"]:
            feed = self._get(url + "/feed/")
            if feed is not None and feed.status_code == 200:
                if GENERATOR_RE.search(feed.text[:100000]) or WP_JSON_RE.search(feed.text[:100000]):
                    result["is_wordpress"] = True
                    result["detected_paths"].append(url + "/feed/")

        # 5. Plugin/theme probes (only if is_wordpress and authorized)
        if self.probe_plugins and result["is_wordpress"]:
            for slug in COMMON_PLUGINS:
                probe = self._get(url + f"/wp-content/plugins/{slug}/readme.txt")
                if probe is not None and probe.status_code == 200 and "Plugin Name" in probe.text[:2000]:
                    result["plugins"].append(slug)
                if len(result["plugins"]) >= self.max_plugin_probes:
                    break
            for slug in COMMON_THEMES:
                probe = self._get(url + f"/wp-content/themes/{slug}/style.css")
                if probe is not None and probe.status_code == 200 and "Theme Name" in probe.text[:2000]:
                    result["themes"].append(slug)
                if len(result["themes"]) >= self.max_theme_probes:
                    break

        # Dedupe
        result["plugins"] = list(dict.fromkeys(result["plugins"]))
        result["themes"] = list(dict.fromkeys(result["themes"]))
        return result

    # ── helpers ──────────────────────────────────────────────────────────────
    def _get(self, url: str, allow_redirects: bool = True) -> requests.Response | None:
        try:
            return self._session.get(url, timeout=TIMEOUT, allow_redirects=allow_redirects)
        except requests.RequestException as exc:
            logger.debug("GET %s failed: %s", url, exc)
            return None

    @staticmethod
    def _normalize_base(url: str) -> str:
        url = (url or "").strip()
        if not url:
            return ""
        if "://" not in url:
            url = "https://" + url
        parsed = urlparse(url)
        if not parsed.hostname:
            return ""
        scheme = parsed.scheme or "https"
        host = parsed.netloc
        # Drop path for base probing (target is the origin)
        return f"{scheme}://{host}".rstrip("/")

    @staticmethod
    def _extract_version(gen_content: str) -> str | None:
        m = VERSION_RE.search(gen_content)
        return m.group(1) if m else None
