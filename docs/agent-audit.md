# Agent Audit — OpenCode Bug Bounty Ecosystem 2026

**Date:** 2026-08-06  
**Scope:** 22 agent definitions across `~/.config/opencode/agents/`, `~/.opencode/agents/`, and `~/bounty-hunter/agents/`

---

## Agent Inventory

| Agent | Registered | File | Role | Token Cost | Score |
|-------|-----------|------|------|-----------|-------|
| autopilot | ✅ | `agents/autopilot.md` | Autonomous hunt loop | Medium | 72 |
| autopilot-hunter | ✅ | `agents/autopilot-hunter.agent.json` | 18-step elite pipeline | Very High | 74 |
| program-intelligence-agent | ✅ | `agents/program-intelligence-agent.md` | Program discovery/scoring | High | 68 |
| ai-recon-agent | ✅ | `agents/ai-recon-agent.md` | AI-powered recon | Medium | 70 |
| exploit-chainer | ✅ | `agents/exploit-chainer.md` | Chain builder | Medium | 75 |
| deep-validator | ✅ | `agents/deep-validator.md` | 7-question gate validation | Low | 82 |
| secret-hunter-agent | ✅ | `agents/secret-hunter-agent.md` | Credential scanning | Medium | 76 |
| mobile-pentest-agent | ✅ | `agents/mobile-pentest-agent.md` | APK/iOS testing | Medium | 71 |
| cloud-security-agent | ✅ | `agents/cloud-security-agent.md` | AWS/GCP/Azure | Medium | 73 |
| cicd-security-agent | ✅ | `agents/cicd-security-agent.md` | CI/CD pipeline review | Medium | 70 |
| llm-security-agent | ✅ | `agents/llm-security-agent.md` | LLM/AI app testing | Medium | 77 |
| crypto-auditor-agent | ✅ | `agents/crypto-auditor-agent.md` | Smart contract audit | Medium | 74 |
| zero-day-hunter | ✅ | `agents/zero-day-hunter.md` | Zero-day discovery | High | 69 |
| chain-builder | ❌ | `agents/chain-builder.md` | Chain builder (dup) | Medium | 60 |
| credential-hunter | ❌ | `agents/credential-hunter.md` | Credential attacks | High | 65 |
| recon-agent | ❌ | `agents/recon-agent.md` | Subdomain/recon | Medium | 67 |
| recon-ranker | ❌ | `agents/recon-ranker.md` | Attack surface ranking | Low | 71 |
| report-writer | ❌ | `agents/report-writer.md` | Report generation | Low | 78 |
| token-auditor | ❌ | `agents/token-auditor.md` | Token security | Low | 66 |
| validator | ❌ | `agents/validator.md` | Finding validation | Low | 80 |
| web3-auditor | ❌ | `agents/web3-auditor.md` | Web3/DeFi audit | Medium | 72 |
| bounty-hunter | ❌ | `~/bounty-hunter/agents/bounty-hunter.md` | Legacy 10-phase agent | High | 70 |
| fleet-hunter | ❌ | `~/bounty-hunter/agents/fleet-hunter.md` | Fleet orchestrator | High | 65 |

---

## Detailed Ratings

### Recon — Score: 68/100

**Strengths:**
- Multiple recon agents cover different angles (subdomain, cloud, AI-powered)
- Recon-ranker provides prioritization layer
- Integration with subfinder, amass, httpx via vulnera-mcp

**Weaknesses:**
- Recon-agent NOT registered in config despite being defined
- No dedicated gRPC/protobuf recon agent
- No WebSocket-specific recon
- JS crawling delegated to vulnera-mcp stub (not implemented)
- Recon-pipeline has no dedicated OAuth/OIDC flow discovery

**Hallucination Risks:** Medium — recon agents may report findings from tools that return empty results (vulnera-mcp stubs)

---

### Fuzzing — Score: 45/100

**Strengths:**
- Nuclei integration via nuclei-mcp (CLI wrapper)
- ffuf available in go bin
- Custom nuclei templates library (200+ workflows, 18 profiles)
- Radamsa fuzzing helper script exists

**Weaknesses:**
- No dedicated fuzzing agent
- No boofuzz/protocol fuzzing integration
- No AFL++/LibFuzzer orchestration
- No structure-aware fuzzing for GraphQL/gRPC
- Nuclei MCP server is CLI-only (no MCP protocol)
- No custom fuzzing grammar for JSON APIs
- Dalfox exists but not integrated into any automated pipeline

---

### Source Review — Score: 78/100

**Strengths:**
- Security-research MCP with semgrep + codeql
- 10 custom Semgrep rules for 2026 techniques
- 2 CodeQL taint-tracking queries
- Code-audit skill in reverse-skill pack
- Sink-to-source methodology in master prompt

**Weaknesses:**
- CodeQL requires separate installation (graceful no-op if absent)
- No Joern integration for advanced C/C++ analysis
- No automated decompilation for closed-source binaries
- Semgrep rules only cover JavaScript/Python — no Go/Rust rules

---

### Exploit Generation — Score: 55/100

**Strengths:**
- Exploit-chainer agent for A→B→C chains
- generate_poc_scaffold MCP tool (Docker + script + report draft)
- 6 variant analysis templates
- pwn-chain skill for binary exploitation

**Weaknesses:**
- PoC scaffold generator produces TODOs — requires manual fill
- No automated exploit development (no angr/Qiling integration)
- No Metasploit/Meteor integration
- No browser exploit automation
- Chain builder not integrated with finding validation

---

### Report Writing — Score: 72/100

**Strengths:**
- Report-writer agent (not registered but defined)
- generate_report in bounty-directory MCP
- generate_bug_report MCP tool
- CVSS 3.1 calculation guidance
- Multiple export formats (markdown, JSON)
- References: report-formatting.md, cvss-guide.md, judging.md

**Weaknesses:**
- Report-writer agent NOT registered in config
- No HackerOne-specific export format
- No Bugcrowd-specific export format
- No Intigriti-specific export format
- No PDF export capability
- No screenshot evidence integration

---

### Prioritization — Score: 70/100

**Strengths:**
- program-intelligence MCP with weighted scoring engine
- rank_programs tool with tier classification
- Technology knowledge graph for cross-target patterns
- Change detection for re-prioritization

**Weaknesses:**
- Priority scoring relies on local data (stale)
- No real-time bounty amount tracking
- No competition density estimation
- No skill-match scoring against personal success history

---

### Triage — Score: 75/100

**Strengths:**
- Deep-validator agent with 7-question gate
- Validator agent with 4-gate checklist
- Weird inventory logging for cross-session correlation
- Refutation.py in bounty-hunter tools
- Judging.md reference (4-gate validation)

**Weaknesses:**
- No automated false-positive detection
- No duplicate submission checking against HackerOne/Bugcrowd
- No confidence scoring per finding
- Cross-references always-rejected table missing

---

## Overlap Analysis

### Duplicate/Redundant Agents:
1. **chain-builder ↔ exploit-chainer** — Near-identical chain builders, only exploit-chainer registered
2. **autopilot ↔ autopilot-hunter ↔ bounty-hunter** — Three autonomous hunt agents with significant overlap
3. **recon-agent ↔ ai-recon-agent** — Overlapping recon roles
4. **validator ↔ deep-validator** — Overlapping validation roles

### Recommended Consolidation:
- Merge chain-builder INTO exploit-chainer
- Merge autopilot INTO autopilot-hunter (superset)
- Merge recon-agent INTO ai-recon-agent
- Merge validator INTO deep-validator (superset)
- Archive bounty-hunter (legacy)

---

## Token Efficiency Analysis

| Agent | Est. Tokens/Invocation | Efficiency |
|-------|----------------------|------------|
| autopilot-hunter | ~8,500 | Low (18-step pipeline) |
| program-intelligence-agent | ~3,200 | Medium |
| deep-validator | ~1,800 | High |
| report-writer | ~2,400 | High |
| recon-ranker | ~1,500 | High |
| exploit-chainer | ~4,200 | Medium |
| zero-day-hunter | ~6,800 | Low |

**Token Waste Sources:**
1. autopilot-hunter loads full master-prompt (~3000 tokens) for every cycle
2. program-intelligence-agent rebuilds knowledge graph from disk each call
3. Multiple agents repeat the same MCP tool calls (no shared cache)

---

## Orchestration Quality: 62/100

**Issues:**
- No formal orchestration protocol between agents
- autopilot-hunter pipeline is sequential — no parallel execution
- No dynamic agent selection based on target type
- No retry logic with exponential backoff
- No circuit breaker pattern
- State persistence is file-based only (race conditions possible)

---

## Final Agent Scores

| Category | Score | Grade |
|----------|-------|-------|
| Recon | 68 | B- |
| Fuzzing | 45 | F |
| Source Review | 78 | B+ |
| Exploit Generation | 55 | D+ |
| Report Writing | 72 | B- |
| Prioritization | 70 | B- |
| Triage | 75 | B |
| **Overall Agent Stack** | **66** | **C+** |
