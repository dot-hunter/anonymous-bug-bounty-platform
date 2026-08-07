#!/usr/bin/env python3
"""Advanced JWT attacks — KID injection, JKU exploitation."""

from __future__ import annotations
import json
import base64
import logging

logger = logging.getLogger("jwt-advanced")


def test_jwt_advanced(target: str, token: str) -> dict:
    """Test advanced JWT attacks — KID injection, JKU, algorithm confusion."""
    findings = []

    if not token:
        return {"type": "jwt_advanced", "vulnerable": False, "findings": []}

    parts = token.split(".")
    if len(parts) != 3:
        return {"type": "jwt_advanced", "vulnerable": False, "findings": []}

    try:
        # Decode header
        header_padding = "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(parts[0] + header_padding))

        # KID injection check
        if "kid" in header:
            kid = header["kid"]
            if ".." in kid or "/" in kid:
                findings.append({"type": "jwt_kid_path_traversal", "kid": kid, "severity": "critical"})
            if kid in ["", "0", "1", "default"]:
                findings.append({"type": "jwt_weak_kid", "kid": kid, "severity": "medium"})

        # JKU exploitation
        if "jku" in header:
            findings.append({"type": "jwt_jku_present", "jku": header["jku"], "severity": "high"})

        # Algorithm confusion
        alg = header.get("alg", "")
        if alg == "RS256":
            findings.append({"type": "jwt_rs256_to_hs256", "severity": "high",
                           "note": "Test if public key can be used as HMAC secret"})
        elif alg.lower() == "none":
            findings.append({"type": "jwt_alg_none", "severity": "critical"})

    except Exception:
        pass

    return {"type": "jwt_advanced", "vulnerable": len(findings) > 0, "findings": findings}
