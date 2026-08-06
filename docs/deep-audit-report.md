# Deep Code Audit — Anonymous Autopilot Bug Bounty Hunter

**Date:** 2026-08-06  
**Auditor:** Principal Security Architect  
**Scope:** Complete OpenCode bug bounty ecosystem  
**Total Code:** 10,172 lines (MCP servers) + 7,895 lines (vulnera-mcp modules) = **18,067 lines**

---

## 1. Architecture Overview

### 1.1 System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        OPENCODE HARNESS                              │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ autopilot    │  │ autopilot-   │  │ program-intelligence-     │  │
│  │ agent        │  │ hunter agent │  │ agent                     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────────┬──────────────┘  │
│         │                 │                        │                 │
│  ┌──────┴─────────────────┴────────────────────────┴──────────────┐  │
│  │                    MASTER PROMPT (221 lines)                    │  │
│  │  Attack Surface Mapping | Trust Boundaries | Sink-to-Source     │  │
│  └──────────────────────────────┬─────────────────────────────────┘  │
│                                 │                                    │
│  ┌──────────────────────────────┴─────────────────────────────────┐  │
│  │                    MCP SERVER LAYER (9 servers)                 │  │
│  │                                                                │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │ vulnera-mcp (94 tools, 3,590 lines)                      │  │  │
│  │  │  server.py + advanced_ssrf.py + advanced_p2.py           │  │  │
│  │  │  + llm_security.py + owasp_complete.py                   │  │  │
│  │  │  + scope_guard.py + rate_limiter.py + opsec_toolkit.py   │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │                                                                │  │
│  │  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐     │  │
│  │  │ security-      │ │ bounty-        │ │ agent-reach    │     │  │
│  │  │ research (11)  │ │ directory (6)  │ │ (8)            │     │  │
│  │  └────────────────┘ └────────────────┘ └────────────────┘     │  │
│  │                                                                │  │
│  │  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐     │  │
│  │  │ nuclei-mcp (5) │ │ shodan-mcp (6) │ │ hackerone (5)  │     │  │
│  │  └────────────────┘ └────────────────┘ └────────────────┘     │  │
│  │                                                                │  │
│  │  ┌────────────────┐ ┌────────────────┐                        │  │
│  │  │ interactsh (4) │ │ program-       │                        │  │
│  │  └────────────────┘ │ intelligence   │                        │  │
│  │                     │ (21)           │                        │  │
│  │                     └────────────────┘                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    DATA LAYER                                 │  │
│  │  ~/.config/vulnera-mcp/                                      │  │
│  │  ├── findings/          # JSONL findings                      │  │
│  │  ├── graph.json         # Knowledge graph                     │  │
│  │  ├── audit.jsonl        # Audit trail                        │  │
│  │  ├── scope.json         # Authorized scope                    │  │
│  │  └── autopilot-state.json # Hunt state                        │  │
│  │                                                              │  │
│  │  ~/.config/program-intelligence/                             │  │
│  │  ├── programs_db.json   # Program database                    │  │
│  │  ├── knowledge_graph.json # Tech relationships               │  │
│  │  ├── research/          # Cached dossiers                    │  │
│  │  ├── memory/            # Cross-target memory                │  │
│  │  └── snapshots/         # Change detection                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Inventory

| Component | Files | Lines | Tools | Purpose |
|-----------|-------|-------|-------|---------|
| vulnera-mcp/server.py | 1 | 3,590 | orchestrator | Main vulnerability engine |
| advanced_ssrf.py | 1 | 645 | 9 | Advanced SSRF bypasses |
| advanced_p2.py | 1 | 1,290 | 19 | Supply chain, race, cloud, API, deserialization, business logic |
| llm_security.py | 1 | 651 | 11 | OWASP LLM Top 10 2026 |
| owasp_complete.py | 1 | 1,359 | 12 | TLS, logging, CORS, DNS, email, headers, subdomain takeover |
| scope_guard.py | 1 | 86 | — | Scope validation |
| rate_limiter.py | 1 | 95 | — | Adaptive rate limiting |
| opsec_toolkit.py | 1 | 179 | — | VPN, traffic shaping, identity |
| security-research | 1 | 807 | 11 | Semgrep, CodeQL, race, PoC |
| agent-reach | 1 | 276 | 8 | OSINT (Twitter, Reddit, GitHub, YouTube) |
| bounty-directory | 1 | 193 | 6 | Program database + live API |
| program-intelligence | ~15 | ~732 | 21 | Discovery, enrichment, scoring, knowledge graph |
| nuclei-mcp | 1 | 210 | 5 | Template scanning |
| shodan-mcp | 1 | 193 | 6 | Internet intelligence |
| hackerone-mcp | 1 | 204 | 5 | HackerOne reports |
| interactsh-mcp | 1 | 153 | 4 | OOB callbacks |

**Total MCP Tools: 160**

---

## 2. Component Dependency Map

```
server.py (orchestrator)
  ├── KnowledgeGraph (graph.json)
  ├── ReconPipeline
  │   ├── subfinder, amass, httpx, gau, ffuf, sn0int, katana, naabu, bbot
  ├── ActiveTester
  │   ├── dalfox, xsstrike, sqlmap, wafw00f
  ├── APITester
  │   ├── graphql-cop, gqlmap
  ├── AuthTester
  │   ├── jwt_tool
  ├── CloudScanner
  │   ├── s3scanner, trufflehog, gitleaks
  ├── JSAnalyzer
  ├── SwarmPentester
  ├── AISecurityTester
  ├── CTEMManager
  ├── ScannerOrchestrator (main entry point)
  │   ├── RateLimiter (adaptive)
  │   ├── ScopeGuard (scope validation)
  │   ├── AuditLogger (audit.jsonl)
  │   ├── AdvancedSSRF (advanced_ssrf.py)
  │   ├── SSTITester
  │   ├── XXETester
  │   ├── FileUploadTester
  │   ├── PathTraversalTester
  │   ├── SSRFTester (basic)
  │   ├── CommandInjectionTester
  │   ├── NoSQLInjectionTester
  │   ├── LDAPInjectionTester
  │   ├── CORSTester
  │   ├── DNSSecurityTester
  │   ├── EmailSecurityTester
  │   ├── BusinessLogicTester
  │   ├── DeserializationTester
  │   ├── TLSSecurityTester
  │   ├── SecurityLoggingTester
  │   ├── SecurityHeadersTester
  │   ├── SubdomainTakeoverTester
  │   ├── BBotIntegration
  │   ├── WebSocketTester
  │   ├── GRPCTester
  │   ├── OIDCTester
  │   ├── GraphQLDeepTester
  │   ├── SupplyChainTester
  │   ├── RaceConditionTester
  │   ├── CloudSecurityTester
  │   ├── APISecurityDeepTester
  │   └── LLMSecuritySuite
```

---

## 3. Data Flow Analysis

### 3.1 Recon Flow
```
Target → ScopeGuard.check() → RateLimiter.wait()
  → subfinder/amass → httpx (live probe)
  → gau/waybackurls (URL discovery)
  → katana (JS crawling)
  → JSAnalyzer (endpoint extraction)
  → KnowledgeGraph.add_node()
  → Findings stored in graph.json
```

### 3.2 Vulnerability Testing Flow
```
Endpoint → ScopeGuard.check() → RateLimiter.wait()
  → ActiveTester.test_xss/test_sqli/...
  → Response analysis (status, content, timing)
  → If vulnerable: KnowledgeGraph.add_finding()
  → AuditLogger.log()
```

### 3.3 Memory/Knowledge Flow
```
Discovery → program-intelligence/discovery/engine.py
  → DiscoveryEngine.discover() → programs_db.json
  → ProgramEnricher.enrich() → tech stack inference
  → PriorityEngine.score() → ranked programs
  → ChangeDetector.detect() → scope/policy changes
  → MemoryStore.save() → cross-target learning
```

---

## 4. Strengths

### 4.1 Architecture
- **Modular design**: Each tool class is independent and testable
- **Layered security**: Scope guard → rate limiter → audit logger at every entry
- **Knowledge persistence**: JSONL/JSON-based storage enables crash recovery
- **Multi-cloud coverage**: AWS, GCP, Azure, DigitalOcean metadata endpoints
- **Stealth-first**: Adaptive rate limiting, human-like pacing

### 4.2 Tool Coverage
- **160 MCP tools** covering full OWASP Top 10 (2021 + 2025) and LLM Top 10 (2026)
- **Advanced SSRF**: DNS rebinding, IP encoding (decimal/hex/octal/IPv6), redirect chains, gopher abuse
- **Business logic**: Payment bypass, coupon abuse, workflow manipulation
- **Supply chain**: CI/CD injection, dependency confusion, typosquatting, SBOM
- **AI/LLM security**: Full OWASP LLM Top 10 2026 coverage

### 4.3 OPSEC
- Scope guard validates every outbound request
- Rate limiter adapts per-target with auto-backoff
- Audit trail logs all actions (sanitized)
- VPN/Tor/proxy toolkit ready
- Identity rotation support

### 4.4 Extensibility
- New tools added via simple class + `@server.tool()` decorator
- New MCP servers independent of main system
- Skills system for prompt-based knowledge

---

## 5. Weaknesses & Bottlenecks

### 5.1 Architecture Weaknesses

| Issue | Impact | Severity |
|-------|--------|----------|
| **Single-threaded scanning** | All tests run sequentially | High |
| **File-based storage only** | No concurrent write support | Medium |
| **No message queue** | Can't distribute work across agents | Medium |
| **No checkpoint/resume** | Crash loses in-progress scan state | High |
| **KnowledgeGraph writes on every add** | Disk I/O bottleneck | Medium |
| **No browser automation** | Can't test JS-heavy SPAs | High |
| **No real AI integration** | Tools exist but no LLM-driven reasoning | Critical |

### 5.2 Tool Weaknesses

| Issue | Impact | Severity |
|-------|--------|----------|
| **No async/concurrent requests** | Race condition tests are limited | Medium |
| **No headless browser** | Can't render JS or test DOM XSS | High |
| **No WebSocket client** | Basic WebSocket testing only | Medium |
| **No gRPC client** | Limited to grpcurl availability | Low |
| **No SQLMap tamper scripts** | Limited WAF bypass for SQLi | Medium |
| **No blind SSRF automation** | Collaborator integration is manual | High |
| **No mutation fuzzing** | Limited input mutation capability | Medium |
| **No certificate pinning bypass** | Mobile testing limited | Low |

### 5.3 Reliability Issues

| Issue | Impact | Severity |
|-------|--------|----------|
| **No retry with exponential backoff** | Transient failures kill scan | Medium |
| **No timeout per-tool** | Hung tools block pipeline | Medium |
| **No circuit breaker** | Repeated failures waste resources | High |
| **No health checks** | Dead MCP servers not detected | Medium |

### 5.4 Missing Capabilities

| Missing | Impact | Severity |
|---------|--------|----------|
| **AI-driven reasoning** | No intelligent decision making | Critical |
| **Parallel execution** | Slow scan times | High |
| **Continuous monitoring** | No re-scan scheduling | Medium |
| **Report auto-generation** | Manual report assembly | Medium |
| **Screenshot evidence** | No visual proof collection | Medium |
| **Chain builder automation** | No automatic exploit chaining | High |
| **WAF fingerprint/evasion** | No WAF-specific bypass selection | Medium |
| **Mobile app testing** | No APK/iOS analysis | Medium |
| **Container image scanning** | No Docker/K8s image analysis | Medium |

---

## 6. Missing Capabilities (Prioritized)

### P0 — Critical
1. **AI-driven autonomous reasoning** — LLM decides next action based on context
2. **Checkpoint/resume** — Save scan state, resume after crash
3. **Parallel execution** — Run independent tests concurrently
4. **Browser automation** — Headless Chrome for JS rendering

### P1 — High
5. **Blind SSRF automation** — Interactsh/burp collaborator integration
6. **Exploit chain builder** — Automatically chain low-severity findings
7. **WAF fingerprint + evasion** — Detect WAF, select bypass technique
8. **Continuous monitoring** — Re-scan schedule for scope changes
9. **Health monitoring** — Detect and recover from MCP server failures
10. **Report auto-generation** — Structured findings → submission-ready report

### P2 — Medium
11. **Mobile app analysis** — APK decompilation, iOS plist analysis
12. **Container image scanning** — Trivy/Grype integration
13. **Mutation fuzzing** — Radamsa/LibFuzzer integration
14. **Certificate analysis** — Full chain validation, CT log monitoring
15. **Email security deep** — SMTP relay testing, DMARC validation

---

## 7. Prioritized Improvement Roadmap

### Phase 1: Reliability (Week 1)
1. Add checkpoint/resume to ScannerOrchestrator
2. Add retry with exponential backoff to _run()
3. Add per-tool timeout configuration
4. Add circuit breaker pattern
5. Add health check endpoint

### Phase 2: Intelligence (Week 2)
6. Add AI-driven planner module
7. Add exploit chain builder
8. Add WAF fingerprint + evasion selector
9. Add evidence collector (screenshots, HTTP archives)

### Phase 3: Performance (Week 3)
10. Add parallel test execution (asyncio)
11. Add batch processing for recon tools
12. Add intelligent caching for repeated queries

### Phase 4: Coverage (Week 4)
13. Add browser automation (Playwright)
14. Add blind SSRF automation
15. Add mobile app analysis
16. Add container security scanning

---

## 8. Security Review

### 8.1 Scope Enforcement
- ✅ Scope guard validates before every request
- ✅ Rate limiter prevents flooding
- ✅ Audit trail logs all actions
- ⚠️ No automatic scope update from program pages

### 8.2 Anonymity
- ✅ VPN/Tor/proxy toolkit
- ✅ Identity rotation
- ✅ Traffic shaping
- ⚠️ No automatic proxy health checking

### 8.3 Destructive Action Prevention
- ✅ No data modification tools
- ✅ No account takeover tools
- ✅ No destructive payloads
- ⚠️ No explicit "read-only" mode flag

---

## 9. Scalability Review

| Aspect | Current | Target |
|--------|---------|--------|
| Concurrent tests | 1 (sequential) | 10+ |
| Scan targets | 1 | 5+ parallel |
| Data storage | File-based | Database |
| Memory usage | ~100MB | ~500MB |
| Scan speed | ~30 min/target | ~10 min/target |

---

## 10. Concrete Implementation Plan

### Enhancement 1: Checkpoint/Resume
**File:** `vulnera-mcp/server.py`  
**Change:** Add `save_state()` and `load_state()` to ScannerOrchestrator  
**Effort:** 2 hours  
**Impact:** High — crash recovery

### Enhancement 2: Parallel Execution
**File:** `vulnera-mcp/server.py`  
**Change:** Add `asyncio.gather()` for independent tool calls  
**Effort:** 4 hours  
**Impact:** High — 3x speed improvement

### Enhancement 3: AI-Driven Planner
**File:** New file `vulnera-mcp/ai_planner.py`  
**Change:** LLM-based decision engine for next-action selection  
**Effort:** 8 hours  
**Impact:** Critical — autonomous operation

### Enhancement 4: Browser Automation
**File:** New file `vulnera-mcp/browser_agent.py`  
**Change:** Playwright-based headless browser for JS rendering  
**Effort:** 6 hours  
**Impact:** High — DOM XSS, SPA testing

### Enhancement 5: WAF Fingerprint + Evasion
**File:** `vulnera-mcp/server.py`  
**Change:** Add WAF detection → technique mapping  
**Effort:** 3 hours  
**Impact:** Medium — better bypass success

---

## 11. Summary

| Category | Score | Notes |
|----------|-------|-------|
| Tool Coverage | 95% | 160 tools, OWASP 2021+2025+LLM 2026 |
| Architecture | 75% | Modular but single-threaded |
| Reliability | 65% | No checkpoint/retry/circuit breaker |
| Intelligence | 40% | No AI-driven reasoning |
| OPSEC | 85% | Scope guard, rate limiter, audit trail |
| Scalability | 50% | Sequential only, file-based storage |
| **Overall** | **68%** | **Solid foundation, needs intelligence layer** |

**Recommendation:** Implement Phase 1 (Reliability) and Phase 3 (Performance) first, then Phase 2 (Intelligence) for maximum impact.
