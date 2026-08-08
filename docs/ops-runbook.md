# Ops Runbook — Operator Manual for Anonymous Autopilot Hunter

**Version:** 2026.08
**Purpose:** Operator-side procedures for running, monitoring, and closing the loop on autonomous hunts. The autopilot NEVER auto-submits reports — a human performs all submission actions from this runbook.

---

## 1. Starting a Hunt

```bash
# One-shot against a target (scope-checked)
opencode "autopilot-hunter: start hunt on <program-handle>"

# Full autonomous loop (max 50 cycles, 60s pause)
opencode "autopilot-hunter: run full cycle"
```

Pre-flight checklist:
- [ ] `scope.yaml` populated at `~/.config/vulnera-mcp/scope.yaml` (copy from `scope.yaml.example`)
- [ ] **Plugin installed**: `opencode.jsonc` registers `"plugin": [".../plugin/security-hooks.js"]` — this supplies `tool.execute.before` (scope enforcement) and `session.idle` (cost tracking). The legacy Python hooks in `./hooks/` (cost_hook.py, scope_hook.py) remain as reference; they are NOT wired into the config since opencode 1.18+ dropped the `hooks` key. The plugin reads `~/.config/vulnera-mcp/scope.yaml` — create it from `hooks/scope.yaml.example` or the hooks silently no-op.
- [ ] VPN active + rotated (30-min rotation confirmed)
- [ ] `~/.config/vulnera-mcp/STOP` does NOT exist (remove if a previous halt signal is present)
- [ ] Session state clean: `cat ~/.config/vulnera-mcp/autopilot-state.json`

## 2. Monitoring

```bash
# Live terminal dashboard (curses)
python3 ~/.opencode/mcp/servers/vulnera-mcp/dashboard.py --watch

# One-shot status
python3 ~/.opencode/mcp/servers/vulnera-mcp/dashboard.py

# Cost summary
cat ~/.config/vulnera-mcp/cost-tracking.jsonl | python3 -c "import json,sys; d=[json.loads(l) for l in sys.stdin]; print(f'Total: \${sum(x.get(\"cost_usd\",0) for x in d):.3f}')"

# Session state
cat ~/.config/vulnera-mcp/autopilot-state.json | python3 -m json.tool | head -30

# Audit trail
tail -20 ~/.config/vulnera-mcp/audit.jsonl
```

## 3. Emergency Stop

```bash
touch ~/.config/vulnera-mcp/STOP          # graceful stop after current stage
# For immediate halt: Ctrl-C in the opencode session
```

## 4. Reviewing Findings

Findings accumulate at:

```
~/.opencode/data/reports/{program}/{timestamp}/
├── DRAFT.md              # platform-formatted draft report
├── poc/                  # Docker-based PoCs
├── evidence/             # HTTP captures + screenshots (zip bundle)
└── killed/{finding_id}.json  # findings that failed validation (never silently discarded)
```

Review gate (human):
1. Read `DRAFT.md` — confirm impact-first framing, working PoC, correct CVSS version
2. Reproduce the PoC yourself in a fresh environment
3. Verify scope compliance against the program policy page

## 5. Submitting and Closing the Loop (record_outcome)

After the platform/human receives the submission verdict, record the outcome so the feedback loop can update technique weights. This is the ONLY manual step that changes future autonomous behavior.

```bash
# Via MCP tool (e.g. inside opencode):
#   record_outcome(
#     vuln_class="idor",
#     technique="direct_id_increment",
#     platform="hackerone",
#     outcome="bounty" | "duplicate" | "informational" | "n/a",
#     payout=2500,
#     payload="<the exact payload that worked>",
#     target="target.example.com",
#     notes="<free text for future planning>"
#   )
```

### Outcome values and effect on weights

| outcome | weight effect | meaning |
|---------|--------------|---------|
| `bounty` | weight × 1.5 | technique paid — boost future priority |
| `duplicate` | weight × 0.9 | known issue — slight decrease |
| `informational` | weight × 0.5 | low value — strong decrease |
| `n/a` | weight × 0.3 | rejected/out-of-scope — strong decrease |

Weights are read by `GoalDrivenPlanner.generate_goals()` at every planning pass. A technique with a history of bounties on the same platform + vuln class is prioritized automatically.

### When to call record_outcome

- Immediately after the program triages your submission (bounty/duplicate/informational)
- For informational-only findings, still record (teaches the planner what NOT to prioritize)
- For N/A (rejected) findings, record with notes on why (scope confusion, missing impact)

## 6. Rotating Targets

Rotation is automatic (max 3 cycles per target, 300s cooldown). To force manual rotation:

```bash
opencode "autopilot-hunter: force rotate target now"
```

To permanently ban a target: add its domains to `out_of_scope` in `scope.yaml`.

## 7. Maintenance

| Task | Command | Frequency |
|------|---------|-----------|
| Verify servers compile | `python3 -m py_compile <server>.py` | after any edit |
| Check tool count | import server; count tools | after any edit |
| Re-seed writeup index | delete `~/.config/platform/writeups.db`, restart server | when index empty |
| Verify hooks fire | run `node --check plugin/security-hooks.js`; feed JSON to `hooks/*.py` manually | after config change |
| Purge stale state | remove `~/.config/vulnera-mcp/autopilot-state.json` | when starting fresh campaign |
| Update payload library | edit `~/.config/opencode/payloads.md` | continuous |

## 8. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Scope violation` in audit log | Check `scope.yaml`; the PreToolUse hook (plugin `tool.execute.before`) blocked the command — expected behavior |
| Dashboard shows 0 KG nodes | `platform_knowledge_graph_query` hasn't run yet; run a recon stage first |
| `Cost: $0` | `session.idle` plugin event not fired yet (no completed session) or log path mismatch |
| Autopilot stuck on same target | check `autopilot-state.json` `cycle`; force rotate |
| Hooks not blocking | verify `"plugin"` array in `opencode.jsonc` points at `plugin/security-hooks.js` and `~/.config/vulnera-mcp/scope.yaml` exists |
| Writeup index 0 entries | auto-seed runs at server startup; if DB was deleted mid-run, restart the server |
| `Unrecognized key: hooks` on start | opencode 1.18+ dropped the `hooks` config key; hooks live in `plugin/security-hooks.js` (see `config/opencode.jsonc`) |
