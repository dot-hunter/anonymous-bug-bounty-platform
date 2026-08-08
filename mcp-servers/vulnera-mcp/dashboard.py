#!/usr/bin/env python3
"""Real-time hunt dashboard — curses-based. Launch: python3 dashboard.py --watch"""
import argparse
import curses
import json
import time
from datetime import datetime
from pathlib import Path

AUDIT_LOG = Path.home() / ".config" / "vulnera-mcp" / "audit.jsonl"
COST_LOG = Path.home() / ".config" / "vulnera-mcp" / "cost-tracking.jsonl"
STATE_FILE = Path.home() / ".config" / "vulnera-mcp" / "autopilot-state.json"
KG_FILE = Path.home() / ".config" / "platform" / "memory" / "knowledge_graph.json"


def load_last_n(path, n=10):
    if not path.exists():
        return []
    try:
        lines = path.read_text().strip().split("\n")
        entries = []
        for l in lines[-n:]:
            if l.strip():
                try:
                    entries.append(json.loads(l))
                except Exception:
                    continue
        return entries
    except Exception:
        return []


def session_cost():
    entries = load_last_n(COST_LOG, 100)
    return sum(e.get("cost_usd", 0) for e in entries)


def kg_stats():
    if not KG_FILE.exists():
        return {"nodes": 0, "edges": 0}
    try:
        data = json.loads(KG_FILE.read_text())
        return {
            "nodes": len(data.get("nodes", {})),
            "edges": len(data.get("edges", [])),
        }
    except Exception:
        return {"nodes": 0, "edges": 0}


def autopilot_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def draw(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        state = autopilot_state()
        audit = load_last_n(AUDIT_LOG, 8)
        kg = kg_stats()
        cost = session_cost()

        lines = [
            f"╔═══ ANONYMOUS BUG BOUNTY HUNTER — {now} ═══",
            f"║  Target: {state.get('current_target', 'none')}",
            f"║  Phase:  {state.get('current_phase', 'idle')}",
            f"║  Cycle:  {state.get('cycle', 0)} / {state.get('max_cycles', 50)}",
            f"║  KG:     {kg['nodes']} nodes · {kg['edges']} edges",
            f"║  Cost:   ${cost:.3f} this session",
            f"╠═══ RECENT AUDIT LOG ═══",
        ]
        for entry in audit[-6:]:
            ts = entry.get("ts", "")[-8:]
            tool = entry.get("tool", entry.get("action", "?"))[:30]
            lines.append(f"║  {ts}  {tool}")
        lines.append("╚" + "═" * (max(w - 2, 1)))

        for i, line in enumerate(lines[: h - 1]):
            try:
                stdscr.addstr(i, 0, line[: w - 1])
            except curses.error:
                pass

        stdscr.refresh()
        key = stdscr.getch()
        if key == ord("q"):
            break
        time.sleep(2)


def main():
    parser = argparse.ArgumentParser(description="Bug bounty hunt dashboard")
    parser.add_argument("--watch", action="store_true", help="curses live view")
    args = parser.parse_args()
    if args.watch:
        curses.wrapper(draw)
    else:
        state = autopilot_state()
        kg = kg_stats()
        cost = session_cost()
        print(
            f"Target: {state.get('current_target','none')} | "
            f"Phase: {state.get('current_phase','idle')} | "
            f"KG: {kg['nodes']}N/{kg['edges']}E | "
            f"Cost: ${cost:.3f}"
        )


if __name__ == "__main__":
    main()
