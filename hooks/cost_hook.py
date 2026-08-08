#!/usr/bin/env python3
"""SubagentStop hook — logs agent name + token cost to cost-tracking.jsonl.
Called by OpenCode after each subagent completes.
"""
import json
import sys
import datetime
from pathlib import Path

COST_LOG = Path.home() / ".config" / "vulnera-mcp" / "cost-tracking.jsonl"


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        # Not JSON input — treat as no-op
        print(json.dumps({"ok": True}))
        return

    agent = data.get("agent_name", "unknown")
    tokens = data.get("total_tokens", 0) or 0
    # Blended cost estimate: claude-opus-4-7 class ~$0.015/1K input, $0.075/1K output
    cost_usd = (float(tokens) / 1000.0) * 0.045  # blended estimate
    entry = {
        "ts": datetime.datetime.utcnow().isoformat(),
        "agent": agent,
        "tokens": tokens,
        "cost_usd": round(cost_usd, 4),
        "session": data.get("session_id", ""),
    }
    COST_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(COST_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(json.dumps({"ok": True}))


if __name__ == "__main__":
    main()
