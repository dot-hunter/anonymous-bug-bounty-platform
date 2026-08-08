"""
Provider Registry — authorized program-discovery providers.

Every provider outputs one normalized program schema (ProgramSchema).
Providers are *authorized discovery* sources: they only read publicly
published program scope data (program pages, security.txt, public
datasets). They never perform active testing.

Providers:
  - hackerone    (HackerOne public programs)
  - bugcrowd     (Bugcrowd public programs)
  - intigriti    (Intigriti public programs)
  - yeswehack    (YesWeHack public programs)
  - securitytxt  (security.txt / VDP policy discovery)

Provider interface:
  name        -> str
  discover()  -> list[dict]   # normalized programs (ProgramSchema)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("program-intelligence.providers")

BUILTIN_PROVIDERS = [
    "hackerone",
    "bugcrowd",
    "intigriti",
    "yeswehack",
    "securitytxt",
]


def get_provider(name: str) -> Any:
    """Get a provider instance by name. Raises ValueError for unknown providers."""
    if name not in BUILTIN_PROVIDERS:
        raise ValueError(
            f"Unknown provider: {name}. Available: {BUILTIN_PROVIDERS}"
        )
    if name == "hackerone":
        from providers.hackerone import HackerOneProvider
        return HackerOneProvider()
    if name == "bugcrowd":
        from providers.bugcrowd import BugcrowdProvider
        return BugcrowdProvider()
    if name == "intigriti":
        from providers.intigriti import IntigritiProvider
        return IntigritiProvider()
    if name == "yeswehack":
        from providers.yeswehack import YesWeHackProvider
        return YesWeHackProvider()
    if name == "securitytxt":
        from providers.securitytxt import SecurityTxtProvider
        return SecurityTxtProvider()
    raise ValueError(f"Provider not implemented: {name}")


def discover(provider: str = "all", max_results: int = 50) -> list[dict]:
    """Run discovery across providers. provider='all' runs every provider."""
    if provider == "all":
        names = BUILTIN_PROVIDERS
    elif provider in BUILTIN_PROVIDERS:
        names = [provider]
    else:
        # Allow comma-separated lists
        names = [p.strip() for p in provider.split(",") if p.strip()]
        unknown = [n for n in names if n not in BUILTIN_PROVIDERS]
        if unknown:
            raise ValueError(f"Unknown providers: {unknown}. Available: {BUILTIN_PROVIDERS}")

    # Honor the authorized_discovery policy: skip disabled providers.
    try:
        from config import provider_enabled
        names = [n for n in names if provider_enabled(n)]
    except Exception as exc:
        logger.warning("provider_enabled check failed (%s) — running all", exc)

    all_programs: list[dict] = []
    errors: dict[str, str] = {}
    for name in names:
        try:
            prov = get_provider(name)
            found = prov.discover()
            if found:
                all_programs.extend(found)
                logger.info("Provider %s returned %d programs", name, len(found))
            else:
                logger.info("Provider %s returned no programs", name)
        except Exception as exc:
            logger.error("Provider %s failed: %s", name, exc)
            errors[name] = str(exc)

    return all_programs[:max_results] if max_results else all_programs
