"""
SUPERSEDED (2026-08-08): opencode 1.18+ removed the `hooks` config key.
Use /home/bb/.config/opencode/plugin/security-hooks.js instead (registered via
"plugin" array in opencode.jsonc). This file is kept as reference only.
"""
#!/usr/bin/env python3
"""PreToolUse hook — blocks out-of-scope Bash tool calls before execution.
Reads scope.yaml for allowlist. Blocks any Bash command containing an OOS domain.
"""
import json
import sys
import re
from pathlib import Path

SCOPE_FILE = Path.home() / ".config" / "vulnera-mcp" / "scope.yaml"


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"allow": True}))
        return

    if data.get("tool_name") not in ("Bash", "bash"):
        print(json.dumps({"allow": True}))
        return

    cmd = data.get("tool_input", {}).get("command", "")

    if not SCOPE_FILE.exists():
        print(json.dumps({"allow": True}))
        return

    try:
        import yaml
        scope = yaml.safe_load(SCOPE_FILE.read_text())
    except Exception:
        # yaml unavailable or parse failure — fail open for bash, blocked for non-parse
        print(json.dumps({"allow": True}))
        return

    in_scope = scope.get("in_scope", []) or []
    out_scope = scope.get("out_of_scope", []) or []

    # Normalize wildcard domains to regex
    def domain_regex(d: str) -> str:
        d = d.strip().lower()
        if d.startswith("*."):
            return r"(?:^|[.\s'\"/])(?:" + re.escape(d[2:]) + r")"
        return r"(?:^|[.\s'\"/])" + re.escape(d)

    # Block if any OOS domain appears in the command
    for oos in out_scope:
        if not oos:
            continue
        try:
            if re.search(domain_regex(oos), cmd, re.IGNORECASE):
                print(json.dumps({
                    "allow": False,
                    "reason": f"Out-of-scope target detected: {oos} in command",
                }))
                return
        except re.error:
            continue

    # Allow if no in_scope configured
    if not in_scope:
        print(json.dumps({"allow": True}))
        return

    # Optionally block commands that reference bare domains not in scope
    # (heuristic only — commands like `cd`, `ls` have no domains)
    bare_domains = re.findall(r"[\w\-]+(?:\.[\w\-]+){1,}(?::\d+)?", cmd)
    relevant = [d for d in bare_domains if "localhost" not in d and not d.endswith(".local") and not d.endswith(".internal")]
    if relevant:
        for d in relevant:
            in_scope_ok = any(
                (d == s.strip().lstrip("*.")) or d.endswith("." + s.strip().lstrip("*."))
                for s in in_scope if s.strip()
            )
            if not in_scope_ok:
                print(json.dumps({
                    "allow": False,
                    "reason": f"Domain {d} not in scope. In-scope: {in_scope}",
                }))
                return

    print(json.dumps({"allow": True}))


if __name__ == "__main__":
    main()
