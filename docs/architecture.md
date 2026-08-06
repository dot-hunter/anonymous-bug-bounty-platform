# Architecture — Ultimate Bug Bounty Hunter 2026

**Date:** 2026-08-06  
**Version:** 2026.08-ULTIMATE  
**Status:** Audit-derived target architecture

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OPENCODE BUG BOUNTY ECOSYSTEM                     │
│                     Ultimate Hunter 2026 Architecture                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────┐       │
│  │   USER       │───▶│  OPENCODE    │───▶│  DEFAULT AGENT    │       │
│  │  INTERFACE   │    │  HARNESS     │    │  autopilot-hunter │       │
│  └─────────────┘    └──────────────┘    └─────────┬─────────┘       │
│                                                      │                │
│                    ┌─────────────────────────────────┼────────┐      │
│                    │         ORCHESTRATION LAYER      │        │      │
│                    │  ┌─────────────────────────────┐ │        │      │
│                    │  │   Master Prompt (221 lines) │ │        │      │
│                    │  │   - Attack surface mapping  │ │        │      │
│                    │  │   - Trust boundary analysis │ │        │      │
│                    │  │   - Sink-to-source doctrine  │ │        │      │
│                    │  │   - 20-min rotation rule     │ │        │      │
│                    │  │   - Session protocol         │ │        │      │
│                    │  └─────────────────────────────┘ │        │      │
│                    └──────────────────────────────────┼────────┘      │
│                                                       │               │
│  ┌────────────────────────────────────────────────────┼───────────┐  │
│  │                    MCP SERVER LAYER                 │           │  │
│  │                                                    ▼           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │  │
│  │  │ vulnera-mcp  │  │ security-   │  │ program-     │        │  │
│  │  │ (27 tools)   │  │ research    │  │ intelligence │        │  │
│  │  │              │  │ (11 tools)  │  │ (22 tools)   │        │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │  │
│  │  │ agent-reach  │  │ bounty-      │  │ hackerone    │        │  │
│  │  │ (9 tools)    │  │ directory    │  │ (5 tools)    │        │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │  │
│  │  │ nuclei-mcp   │  │ interactsh   │  │ shodan-mcp   │        │  │
│  │  │ (3 tools)    │  │ (3 tools)    │  │ (4 tools)    │        │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     AGENT LAYER                                │  │
│  │                                                               │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │  │
│  │  │ autopilot-       │  │ program-        │  │ deep-        │  │  │
│  │  │ hunter           │  │ intelligence    │  │ validator    │  │  │
│  │  │ (18-step pipe)  │  │ -agent          │  │ (7-gate)     │  │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘  │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │  │
│  │  │ exploit-        │  │ secret-hunter   │  │ recon-ranker │  │  │
│  │  │ chainer         │  │ -agent          │  │              │  │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘  │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │  │
│  │  │ llm-security    │  │ cloud-security  │  │ mobile-      │  │  │
│  │  │ -agent          │  │ -agent          │  │ pentest      │  │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘  │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │  │
│  │  │ cicd-security   │  │ crypto-auditor  │  │ web3-auditor │  │  │
│  │  │ -agent          │  │ -agent          │  │              │   │  │
│  │  └─────────────────┘  └─────────────────┘  └──────────────┘  │  │
│  │  ┌─────────────────┐  ┌─────────────────┐                    │  │
│  │  │ zero-day-       │  │ report-writer   │                    │  │
│  │  │ hunter          │  │                 │                    │  │
│  │  └─────────────────┘  └─────────────────┘                    │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     SKILL LAYER (81 skills)                    │  │
│  │                                                               │  │
│  │  Reverse Engineering (40+)  │  Web Security (15+)            │  │
│  │  - apk-reverse               │  - api-security                │  │
│  │  - dotnet-reverse            │  - llm-security                │  │
│  │  - ida-reverse               │  - identity-federation         │  │
│  │  - js-reverse                │  - database-security           │  │
│  │  - ghidra-reverse            │  - email-security              │  │
│  │  - firmware-pentest          │  - supply-chain-security       │  │
│  │  - malware-analysis          │  - code-audit                  │  │
│  │  - ... (30+ more)            │  - ... (5+ more)               │  │
│  │                                                               │  │
│  │  Cloud/Infra (8)            │  Specialized (18)              │  │
│  │  - cloud-k8s                │  - pentest-tools               │  │
│  │  - windows-ad               │  - attack-chain                │  │
│  │  - ot-ics                   │  - threat-hunting              │  │
│  │  - wifi-wireless            │  - digital-forensics           │  │
│  │  - hardware-security        │  - radio-sdr                   │  │
│  │  - ... (3 more)             │  - ... (13 more)               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     DATA LAYER                                 │  │
│  │                                                               │  │
│  │  ~/.config/vulnera-mcp/     │  ~/.config/program-intelligence/│  │
│  │  ├── findings/              │  ├── programs_db.json           │  │
│  │  ├── graph.json             │  ├── knowledge_graph.json       │  │
│  │  ├── autopilot-state.json   │  ├── research/                  │  │
│  │  ├── visited.jsonl          │  ├── memory/                    │  │
│  │  └── autopilot.log          │  ├── snapshots/                 │  │
│  │                             │  └── changes.jsonl              │  │
│  │  ~/.config/agent-reach/     │  ~/.config/opencode/            │  │
│  │  ├── cookies/               │  ├── session-logs/              │  │
│  │  ├── osint_cache.json       │  └── weird-inventory/           │  │
│  │  └── recon_cache.json       │                                 │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                     OPSEC LAYER                                │  │
│  │                                                               │  │
│  │  VPN Rotation │ Tor Egress │ Proxy Chains │ Rate Limiting    │  │
│  │  Browser Isol │ Container  │ DNS Isol     │ Cookie Sep       │  │
│  │  Identity Rot │ Traffic Sh │ Workspace Enc│ Audit Sanitize   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow — One Complete Hunt Cycle

```
PHASE 0: PROGRAM SELECTION
  program-intelligence.rank_programs()
  → bounty-directory.get_program(handle)
  → Output: selected_target + scope + bounty_info
  │
  ▼
PHASE 1: INTELLIGENCE GATHERING
  agent-reach.osint_intel(target)
  → agent-reach.search_twitter(target)
  → agent-reach.read_reddit("bugbounties" + "hacking")
  → program-intelligence.generate_research_dossier(handle)
  → Output: osint_data + research_dossier
  │
  ▼
PHASE 2: SCOPE EXTRACTION
  Parse program scope page
  → Extract: domains, IP ranges, ASNs, exclusions
  → scope_guard.validate(target) for all subsequent requests
  → Output: validated_scope
  │
  ▼
PHASE 3: TECHNOLOGY FINGERPRINTING
  vulnera-mcp.recon(target, quick=false)
  → subfinder → amass → sn0int
  → httpx (live probe)
  → wafw00f (WAF fingerprint)
  → Output: tech_stack + live_hosts + waf_type
  │
  ▼
PHASE 4: ASSET INVENTORY
  → subdomain_enum → live_probe
  → naabu (port scan, exclude CDN)
  → gau + waybackurls (historical URLs)
  → katana (JS-aware crawl)
  → Output: asset_graph
  │
  ▼
PHASE 5: ENDPOINT EXTRACTION
  → js_analyze (download + beautify + extract)
  → ParamMiner / Arjun (parameter discovery)
  → GraphQL introspection (if detected)
  → WebSocket endpoint detection
  → Output: endpoint_list + parameter_map
  │
  ▼
PHASE 6: API DISCOVERY
  → test_swagger (OpenAPI collection)
  → GraphQL schema analysis
  → gRPC service detection (if applicable)
  → Output: api_surface
  │
  ▼
PHASE 7: SECRET MINING
  → scan_secrets (trufflehog/gitleaks)
  → JS bundle analysis for API keys
  → GitHub code search for target
  → Output: leaked_secrets
  │
  ▼
PHASE 8: CLOUD ENUMERATION
  → scan_s3 (bucket enumeration)
  → scan_k8s (Kubernetes exposure)
  → scan_terraform (state exposure)
  → Output: cloud_attack_surface
  │
  ▼
PHASE 9: ATTACK SURFACE GRAPH
  → graph_paths (correlate all findings)
  → KnowledgeGraph.add_finding() for each
  → Output: prioritized_attack_graph
  │
  ▼
PHASE 10: VULNERABILITY TESTING
  → test_xss (dalfox integration)
  → test_sqli (sqlmap integration)
  → test_idor (parameter variation)
  → test_csp (CSP bypass)
  → test_jwt (algorithm confusion)
  → test_oauth (flow manipulation)
  → test_graphql (introspection + batching)
  → test_rate_limit (adaptive)
  → test_bola (object-level auth)
  → test_prompt_injection (if AI surface)
  → test_waf_bypass_ml (differential fuzzing)
  → Output: raw_findings
  │
  ▼
PHASE 11: STATIC ANALYSIS (if source available)
  → run_semgrep (custom + bundled rules)
  → run_codeql (taint tracking)
  → check_dependency_confusion
  → Output: static_findings
  │
  ▼
PHASE 12: RACE CONDITION TESTING
  → race_condition_test (parallel requests)
  → Target: single-use tokens, credits, permissions
  → Output: race_findings
  │
  ▼
PHASE 13: VALIDATION
  → deep-validator (7-question gate)
  → Cross-reference always-rejected table
  → CVSS 3.1 calculation
  → Output: validated_findings
  │
  ▼
PHASE 14: VARIANT ANALYSIS
  → variant_analysis (Semgrep rule + GitHub search)
  → Scale 1 finding → 2-5 variants
  → Output: variant_findings
  │
  ▼
PHASE 15: IMPACT SCORING
  → Score by: exploitability, sensitivity, scope
  → Chain analysis: A→B→C compound severity
  → Output: scored_findings
  │
  ▼
PHASE 16: REPORT GENERATION
  → generate_poc_scaffold (Docker + script)
  → report-writer (impact-first, <600 words)
  → Export: markdown + JSON
  → Output: submission_package
  │
  ▼
PHASE 17: TARGET ROTATION
  → mark_visited(target)
  → persist_state()
  → select_next_target()
  → Output: next_target
```

---

## Component Interaction Matrix

| Component | Calls | Called By | Data Produced |
|-----------|-------|-----------|---------------|
| program-intelligence | — | autopilot-hunter | ranked_targets, dossiers |
| bounty-directory | program-intelligence | autopilot-hunter | program_details |
| agent-reach | — | autopilot-hunter | osint_data |
| vulnera-mcp | subfinder, amass, httpx, nuclei, dalfox, sqlmap | autopilot-hunter | recon_results, findings |
| security-research | semgrep, codeql | autopilot-hunter | static_findings, poc_scaffolds |
| deep-validator | — | autopilot-hunter | validated_findings |
| report-writer | — | autopilot-hunter | submission_package |

---

## Token Budget Allocation

| Phase | Est. Tokens | % of Total |
|-------|------------|------------|
| Master prompt load | 3,000 | 3.75% |
| Program selection | 1,500 | 1.875% |
| Intelligence gathering | 4,000 | 5% |
| Recon + fingerprinting | 6,000 | 7.5% |
| Endpoint extraction | 5,000 | 6.25% |
| Vulnerability testing | 25,000 | 31.25% |
| Static analysis | 8,000 | 10% |
| Validation | 4,000 | 5% |
| Variant analysis | 6,000 | 7.5% |
| Report generation | 8,000 | 10% |
| Overhead (retries, context) | 9,500 | 11.875% |
| **Total per cycle** | **80,000** | **100%** |

---

## Failure Modes & Mitigations

| Failure | Impact | Mitigation |
|---------|--------|------------|
| MCP server crash | Pipeline halt | Auto-restart with exponential backoff |
| Tool not installed | Empty results | Graceful degradation + install prompt |
| Rate limit (429) | Testing halt | Adaptive delay + VPN rotation |
| Scope violation | Legal risk | scope_guard hard block on every request |
| False positive | Wasted time | 7-question gate before reporting |
| Token limit exceeded | Incomplete cycle | Checkpoint state + resume |
| Target down | Pipeline stall | Skip + rotate to next target |
| WAF block | Missed vulns | ML-based WAF bypass (differential fuzzing) |

---

## Scaling Strategy

### Current: Single-target sequential
- One target at a time
- 18 sequential steps
- ~80k tokens per cycle

### Target: Multi-target parallel
- 3-5 targets in parallel (different phases)
- Shared recon cache
- ~200k tokens per cycle (2.5x throughput)

### Future: Swarm architecture
- Recon agents: parallel subdomain enum
- Testing agents: parallel vuln class testing
- Validation agents: parallel finding validation
- Report agents: parallel report drafting
- Coordinator: correlation + deduplication
