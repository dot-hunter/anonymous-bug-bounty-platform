#!/usr/bin/env python3
"""GraphQL advanced attacks — batching, depth, introspection."""

from __future__ import annotations
import json
import logging
import subprocess

logger = logging.getLogger("graphql-advanced")


def _run(cmd, timeout=60, input=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input)
        return proc.returncode, proc.stdout, proc.stderr
    except Exception as exc:
        return -1, "", str(exc)


def test_graphql_advanced(target: str, endpoint: str) -> dict:
    """Test GraphQL advanced attacks — batching, depth, introspection."""
    findings = []

    # Batching test
    batch_query = json.dumps([{"query": "{__typename}"}] * 5)
    rc, stdout, _ = _run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", batch_query, "--max-time", "10", endpoint],
        timeout=15,
    )
    if rc == 0 and stdout:
        try:
            data = json.loads(stdout)
            if isinstance(data, list) and len(data) == 5:
                findings.append({"type": "graphql_batching", "severity": "medium"})
        except json.JSONDecodeError:
            pass

    # Depth limit test
    nested = "{" * 10 + "a" + "}" * 10
    rc, stdout, _ = _run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", json.dumps({"query": nested}), "--max-time", "10", endpoint],
        timeout=15,
    )
    if rc == 0 and stdout and "data" in stdout and "errors" not in stdout:
        findings.append({"type": "graphql_depth_limit", "severity": "medium"})

    # Introspection test
    rc, stdout, _ = _run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", json.dumps({"query": "{__schema{queryType{name}}}"}),
         "--max-time", "10", endpoint],
        timeout=15,
    )
    if rc == 0 and stdout and "__schema" in stdout:
        findings.append({"type": "graphql_introspection", "severity": "medium"})

    return {"type": "graphql_advanced", "vulnerable": len(findings) > 0, "findings": findings}
