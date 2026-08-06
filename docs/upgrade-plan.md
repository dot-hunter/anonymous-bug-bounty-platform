# Upgrade Plan — From Audit to Production

**Date:** 2026-08-06  
**Based on:** Complete audit findings from Phases 1-9

---

## Week 1: Critical Fixes (P0)

### Day 1-2: Fix vulnera-mcp Stubs

**File:** `~/.opencode/mcp/servers/vulnera-mcp/server.py`

Replace all stub test methods with real implementations:

```python
# BEFORE (current):
def test_xss(self, target, param, url):
    return {"target": target, "param": param, "url": url, "type": "xss", "vulnerable": False, "payloads_tested": []}

# AFTER (target):
def test_xss(self, target, param, url):
    """Real XSS testing via dalfox with payload rotation."""
    dalfox = _which("dalfox")
    if not dalfox:
        return {"target": target, "param": param, "url": url, "type": "xss", "vulnerable": False, "error": "dalfox not installed"}
    
    # Run dalfox with safe parameters
    rc, stdout, stderr = _run([
        dalfox, "url", url, 
        "--param", param,
        "--silence",
        "--no-spinner",
        "--format", "json"
    ], timeout=120)
    
    findings = []
    if rc == 0 and stdout:
        for line in stdout.strip().split("\n"):
            try:
                result = json.loads(line)
                if result.get("type") == "V":
                    findings.append(result)
            except json.JSONDecodeError:
                continue
    
    return {
        "target": target, "param": param, "url": url,
        "type": "xss", "vulnerable": len(findings) > 0,
        "findings": findings, "payloads_tested": len(findings)
    }
```

**Estimated time:** 2 hours per tool × 10 tools = 16 hours

### Day 3: Fix bounty-directory + Register Agents

**File:** `~/.opencode/mcp/servers/bounty-directory/server.py`
- Fix f-string on line 150: `f"report_{target.replace(':', '_')}_{int(time.time())}.md"`
- Add HackerOne/Bugcrowd API integration

**File:** `~/.config/opencode/opencode.jsonc`
- Register 8 unregistered agents with proper permissions

**Estimated time:** 4 hours

### Day 4: Convert CLI MCP Servers + Add Scope/Rate Limiting

**Files:**
- `~/tools/claude-bug-bounty/mcp/nuclei-mcp/server.py` → FastMCP
- `~/tools/claude-bug-bounty/mcp/interactsh-mcp/server.py` → FastMCP
- `~/tools/claude-bug-bounty/mcp/shodan-mcp/server.py` → FastMCP
- Add scope_guard to vulnera-mcp
- Add rate_limiter to vulnera-mcp

**Estimated time:** 8 hours

### Day 5: Testing + Integration

- Test all fixed MCP servers under stdio transport
- Verify scope guard blocks out-of-scope requests
- Verify rate limiter adapts on 429
- Run autopilot-hunter against test target
- Validate full pipeline end-to-end

**Estimated time:** 6 hours

---

## Week 2: High-Value Skills (P1)

### Day 6-7: SSTI + XXE + IDOR

Create three new vulnerability testing skills:

1. **SSTI Detector** (`~/.opencode/skills/ssti-detect.skill.json` + tool)
   - Payload library for 8 template engines
   - Differential testing (render detection)
   - fenjing integration for WAF bypass

2. **XXE Tester** (`~/.opencode/skills/xxe-test.skill.json` + tool)
   - Basic/OOB/blind XXE payloads
   - interactsh integration for OOB callbacks

3. **IDOR Automator** (extend existing test_idor in vulnera-mcp)
   - Parameter discovery integration
   - Multi-account testing
   - Response diffing

**Estimated time:** 8 hours

### Day 8: File Upload + Path Traversal + JWT

4. **File Upload Tester**
   - Polyglot generation
   - Extension bypass library

5. **Path Traversal Tester**
   - Encoding bypass library
   - Null byte injection

6. **JWT Attack Tool** (extend test_jwt in vulnera-mcp)
   - Algorithm confusion
   - None bypass
   - Key brute force

**Estimated time:** 6 hours

### Day 9-10: Pipeline Integration + Validation

- Add all new skills to autopilot-hunter pipeline
- Update pipeline steps (expand from 18 to 24 steps)
- Add SSTI, XXE, IDOR as new testing phases
- Validate full pipeline with test target
- Update documentation

**Estimated time:** 8 hours

---

## Week 3: Medium Skills + OPSEC (P2)

### Day 11-12: bbot + Cloud + Container

1. Install and integrate bbot for recon
2. Add cloudfox/s3scanner for cloud scanning
3. Add trivy/grype for container scanning

**Estimated time:** 8 hours

### Day 13-14: API Deep Testing

4. GraphQL fuzzing depth
5. WebSocket security testing
6. gRPC security testing

**Estimated time:** 8 hours

### Day 15: OAuth + JWT Deep Testing

7. OAuth/OIDC flow testing
8. JWT comprehensive attack suite

**Estimated time:** 6 hours

---

## Week 4: OPSEC + Polish (P3)

### Day 16-17: VPN Rotation + Ephemeral Containers

1. vpn_manager.py with WireGuard
2. Docker ephemeral workspace per target
3. Auto-destroy and cleanup

**Estimated time:** 8 hours

### Day 18: Tor + Traffic Shaping

4. tor_controller.py
5. Request randomization and shaping

**Estimated time:** 6 hours

### Day 19: Report Quality

6. PDF export (pandoc/weasyprint)
7. Platform-specific templates
8. Screenshot evidence capture (Playwright)

**Estimated time:** 6 hours

### Day 20: Final Integration + Documentation

- Full end-to-end test
- Update all documentation
- Performance benchmarking
- Token usage optimization

**Estimated time:** 6 hours

---

## Specific File Changes

### Files to Modify:

| File | Change | Priority |
|------|--------|----------|
| `vulnera-mcp/server.py` | Replace 10 stub methods with real implementations | P0 |
| `bounty-directory/server.py` | Fix f-string, add live API | P0 |
| `opencode.jsonc` | Register 8 agents | P0 |
| `nuclei-mcp/server.py` | Convert to FastMCP | P0 |
| `interactsh-mcp/server.py` | Convert to FastMCP | P0 |
| `shodan-mcp/server.py` | Convert to FastMCP | P0 |
| `autopilot-hunter.agent.json` | Expand pipeline to 24 steps | P1 |
| `master-prompt.md` | Add SSTI/XXE/JWT sections | P1 |
| `agent-reach/server.py` | Add proxy support | P2 |
| `security-research/server.py` | Clean CodeQL temp files | P2 |

### Files to Create:

| File | Purpose | Priority |
|------|---------|----------|
| `vulnera-mcp/scope_guard.py` | Scope validation | P0 |
| `vulnera-mcp/rate_limiter.py` | Adaptive rate limiting | P0 |
| `vulnera-mcp/ssti_detector.py` | SSTI testing | P1 |
| `vulnera-mcp/xxe_tester.py` | XXE testing | P1 |
| `vulnera-mcp/file_upload_tester.py` | Upload testing | P1 |
| `vulnera-mcp/path_traversal_tester.py` | Path traversal testing | P1 |
| `skills/ssti-detect.skill.json` | SSTI skill manifest | P1 |
| `skills/xxe-test.skill.json` | XXE skill manifest | P1 |
| `opsec/vpn_manager.py` | VPN rotation | P3 |
| `opsec/tor_controller.py` | Tor routing | P3 |
| `opsec/container_orchestrator.py` | Ephemeral containers | P3 |
| `opsec/traffic_shaper.py` | Traffic randomization | P3 |
| `report/pdf_exporter.py` | PDF generation | P3 |
| `report/screenshot_capture.py` | Evidence screenshots | P3 |

---

## Testing Strategy

### Unit Tests (per component):
- Each MCP tool: input validation, output format, error handling
- Each skill manifest: JSON schema validation
- Each agent: frontmatter validation, permission check

### Integration Tests:
- MCP server stdio transport: start, call tool, verify output
- Full pipeline: program selection → recon → testing → validation → report
- Scope guard: verify blocks out-of-scope, allows in-scope
- Rate limiter: verify adapts on 429

### End-to-End Tests:
- Run full autopilot-hunter against deliberately vulnerable target (DVWA, WebGoat)
- Verify: findings generated, PoC created, report formatted
- Verify: no out-of-scope requests, rate limits respected

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Tool not installed | Graceful degradation + install prompt |
| Target blocks testing | VPN rotation + adaptive rate limiting |
| False positives | 7-question gate + manual review requirement |
| Scope violation | Hard block via scope_guard.py |
| Token limit exceeded | Checkpoint state + resume |
| MCP server crash | Auto-restart with exponential backoff |
| Legal exposure | Scope validation + audit logging + human review for submission |

---

## Definition of Done

- [ ] All P0 items complete and tested
- [ ] At least 80% of P1 items complete
- [ ] autopilot-hunter runs end-to-end against test target
- [ ] At least 3 real vulnerability classes detected in test target
- [ ] Scope guard prevents 100% of out-of-scope requests
- [ ] Rate limiter prevents IP bans during sustained testing
- [ ] Report output includes CVSS, PoC, and remediation
- [ ] All documentation updated
- [ ] 409 existing tests still passing
- [ ] New tests for all new components passing
