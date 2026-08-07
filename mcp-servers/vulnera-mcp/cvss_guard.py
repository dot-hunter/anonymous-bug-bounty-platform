#!/usr/bin/env python3
"""CVSS Version Guard — Ensures reports use the correct CVSS version per platform."""

from __future__ import annotations

PLATFORM_CVSS = {
    "hackerone": "3.1",
    "bugcrowd": "4.0",
    "intigriti": "4.0",
    "immunefi": "4.0",
    "yeswehack": "4.0",
    "independent": "4.0",
}

def validate_cvss_version(platform: str, report: dict) -> dict:
    """Ensure report uses the correct CVSS version for the platform.
    
    Args:
        platform: Bug bounty platform name (e.g., "hackerone", "bugcrowd")
        report: Report dict containing 'cvss_version' field
    
    Returns:
        Dict with 'valid' boolean and error details if invalid
    """
    required = PLATFORM_CVSS.get(platform.lower(), "4.0")
    used = report.get("cvss_version", "3.1")
    if used != required:
        return {
            "valid": False,
            "error": f"Platform {platform} requires CVSS {required}, report uses {used}",
            "fix": f"Recalculate CVSS using version {required}",
            "required_version": required,
            "used_version": used,
        }
    return {"valid": True, "cvss_version": required}


def get_supported_platforms() -> dict:
    """Return dict of supported platforms and their required CVSS versions."""
    return PLATFORM_CVSS.copy()
