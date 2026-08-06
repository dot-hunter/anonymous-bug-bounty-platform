# TODO — Prioritized Action Items

**Date:** 2026-08-06  
**Generated from:** Complete ecosystem audit  
**Total items:** 42  
**Total estimated effort:** ~120 hours

---

## P0 — CRITICAL (Must fix before autonomous operation)

| # | Task | Difficulty | Time | Impact | Token Cost | Expected Bounty |
|---|------|-----------|------|--------|------------|-----------------|
| 1 | Replace vulnera-mcp XSS stub with dalfox integration | Medium | 3h | Critical | 0 | $100-1,000/find |
| 2 | Replace vulnera-mcp SQLi stub with sqlmap integration | Medium | 3h | Critical | 0 | $500-5,000/find |
| 3 | Replace vulnera-mcp IDOR stub with parameter variation | Medium | 3h | Critical | 0 | $500-3,000/find |
| 4 | Replace vulnera-mcp CSP stub with header analysis | Low | 1h | High | 0 | $200-1,000/find |
| 5 | Replace vulnera-mcp JWT stub with algorithm confusion | Medium | 2h | High | 0 | $300-2,000/find |
| 6 | Replace vulnera-mcp OAuth stub with flow testing | Medium | 2h | High | 0 | $1,000-5,000/find |
| 7 | Replace vulnera-mcp GraphQL stub with introspection | Medium | 2h | High | 0 | $500-3,000/find |
| 8 | Replace vulnera-mcp scan_secrets with trufflehog | Medium | 2h | High | 0 | $500-50,000/find |
| 9 | Replace vulnera-mcp scan_s3 with s3scanner | Low | 1h | Medium | 0 | $100-1,000/find |
| 10 | Replace vulnera-mcp js_analyze with LinkFinder+SecretFinder | Medium | 3h | High | 0 | $500-5,000/find |
| 11 | Fix bounty-directory f-string syntax error | Trivial | 0.25h | Critical | 0 | Enables selection |
| 12 | Add HackerOne API to bounty-directory | Medium | 2h | High | 0 | Better targeting |
| 13 | Add Bugcrowd API to bounty-directory | Medium | 2h | High | 0 | Better targeting |
| 14 | Convert nuclei-mcp to real FastMCP server | Medium | 2h | High | 0 | Enables nuclei MCP |
| 15 | Convert interactsh-mcp to real FastMCP server | Medium | 2h | High | 0 | Enables OOB testing |
| 16 | Convert shodan-mcp to real FastMCP server | Medium | 2h | Medium | 0 | Enables Shodan MCP |
| 17 | Add scope validation to vulnera-mcp | Medium | 3h | Critical | 0 | Legal protection |
| 18 | Add adaptive rate limiting to vulnera-mcp | Low | 2h | Critical | 0 | Prevents bans |
| 19 | Clean CodeQL temp databases after runs | Low | 0.5h | Medium | 0 | Disk cleanup |
| 20 | End-to-end test of fixed pipeline | Medium | 4h | Critical | 50,000 | Validation |
| **P0 Total** | | | **40.75h** | | **50,000** | **Unlocks all hunting** |

---

## P1 — HIGH (Should fix within 2 weeks)

| # | Task | Difficulty | Time | Impact | Token Cost | Expected Bounty |
|---|------|-----------|------|--------|------------|-----------------|
| 21 | Register 8 unregistered agents in opencode.jsonc | Trivial | 0.5h | High | 0 | Usability |
| 22 | Fix 3 duplicate skill manifests (make unique) | Trivial | 0.25h | Medium | 0 | Clarity |
| 23 | Implement SSTI detection skill | Medium | 6h | Very High | 2,000 | $2,000-15,000/find |
| 24 | Implement XXE testing skill | Medium | 4h | High | 1,500 | $1,000-8,000/find |
| 25 | Implement IDOR automation (multi-account) | Medium | 6h | High | 2,000 | $500-3,000/find |
| 26 | Implement file upload security testing | Medium | 4h | High | 1,800 | $1,000-10,000/find |
| 27 | Implement path traversal testing | Low | 3h | High | 1,500 | $500-5,000/find |
| 28 | Implement JWT attack tool (full) | Medium | 3h | Medium | 1,200 | $300-2,000/find |
| 29 | Expand autopilot-hunter pipeline to 24 steps | Medium | 2h | High | 0 | Coverage |
| 30 | Add SSTI/XXE/IDOR to master prompt sections | Low | 1h | High | 0 | Guidance |
| 31 | Test pipeline with vulnerable target (DVWA) | Medium | 4h | Critical | 30,000 | Validation |
| **P1 Total** | | | **34.75h** | | **40,000** | **$5,300-53,000/find** |

---

## P2 — MEDIUM (Should fix within 1 month)

| # | Task | Difficulty | Time | Impact | Token Cost | Expected Bounty |
|---|------|-----------|------|--------|------------|-----------------|
| 32 | Add bbot integration for recon aggregation | Medium | 4h | High | 0 | Better recon |
| 33 | Add cloud security scanning (cloudfox/s3scanner) | Medium | 6h | High | 0 | $1,000-10,000/find |
| 34 | Add container security scanning (trivy/grype) | Medium | 4h | Medium | 0 | Compliance |
| 35 | Add GraphQL fuzzing depth | Medium | 5h | Medium | 2,500 | $500-5,000/find |
| 36 | Add WebSocket security testing | Medium | 4h | Medium | 2,000 | $1,000-5,000/find |
| 37 | Add gRPC security testing | Medium | 5h | Medium | 2,500 | $500-3,000/find |
| 38 | Add OAuth/OIDC flow testing | Medium | 5h | High | 2,000 | $1,000-5,000/find |
| 39 | Add proxy support to agent-reach | Low | 2h | High | 0 | OPSEC |
| 40 | Add integrity hashes to all MCP servers | Trivial | 0.5h | Medium | 0 | Security |
| **P2 Total** | | | **35.5h** | | **9,000** | **$4,000-28,000/find** |

---

## P3 — LOW (Nice to have)

| # | Task | Difficulty | Time | Impact | Token Cost | Expected Bounty |
|---|------|-----------|------|--------|------------|-----------------|
| 41 | Implement VPN rotation (WireGuard) | Medium | 4h | High | 0 | OPSEC |
| 42 | Implement ephemeral Docker containers | Medium | 6h | Medium | 0 | Isolation |
| 43 | Add Tor routing integration | Medium | 4h | Medium | 0 | OPSEC |
| 44 | Add traffic shaping (request randomization) | Low | 3h | Medium | 0 | Stealth |
| 45 | Add PDF export for reports | Low | 3h | Medium | 0 | Quality |
| 46 | Add screenshot evidence capture (Playwright) | Medium | 4h | Medium | 0 | Proof quality |
| **P3 Total** | | | **24h** | | **0** | **OPSEC/Quality** |

---

## Quick Wins (< 1 hour each)

| # | Task | Time | Impact |
|---|------|------|--------|
| Q1 | Fix bounty-directory f-string | 5 min | Fixes crash |
| Q2 | Register 8 agents in config | 15 min | Unlocks agents |
| Q3 | Fix duplicate skill manifests | 15 min | Reduces confusion |
| Q4 | Add integrity hashes to MCP configs | 15 min | Security |
| Q5 | Clean CodeQL temp DB after runs | 30 min | Disk space |
| Q6 | Add scope checking to race_condition_test | 30 min | Safety |
| **Quick Wins Total** | | **2h** | **Immediate improvement** |

---

## Dependency Graph

```
P0-1 through P0-10 (fix stubs) ──┐
P0-11 through P0-13 (bounty-dir) ├─▶ P0-17 (scope guard) ──▶ P0-18 (rate limit) ──▶ P0-20 (test)
P0-14 through P0-16 (MCP convert) ┘

P0 complete ──▶ P1-21 (register agents) ──▶ P1-23 through P1-28 (new skills) ──▶ P1-29 (pipeline expand) ──▶ P1-31 (test)

P1 complete ──▶ P2-32 (bbot) ──▶ P2-33 (cloud) ──▶ P2-35 through P2-38 (API deep) 

P2 complete ──▶ P3-41 (VPN) ──▶ P3-42 (containers) ──▶ P3-44 (traffic) ──▶ P3-45 (PDF)
```

---

## Progress Tracking

| Priority | Items | Hours | Completed | Remaining |
|----------|-------|-------|-----------|-----------|
| P0 | 20 | 40.75 | 0 | 20 |
| P1 | 11 | 34.75 | 0 | 11 |
| P2 | 9 | 35.5 | 0 | 9 |
| P3 | 6 | 24 | 0 | 6 |
| Quick Wins | 6 | 2 | 0 | 6 |
| **Total** | **52** | **137h** | **0** | **52** |

---

## Notes

- **Token costs** are estimated per-cycle inference costs (not implementation costs)
- **Expected bounty** ranges are based on HackerOne/Bugcrowd public data for 2025-2026
- **Difficulty** is relative to a security engineer familiar with Python and bug bounty tools
- **Impact** measures how much the item contributes to successful vulnerability discovery
- All P0 items must be complete before autonomous hunting begins
- P1 items should be complete before hunting production targets
- P2/P3 items improve quality and safety but are not blockers
