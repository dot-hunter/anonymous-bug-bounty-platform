# 🐛 Anonymous Bug Bounty Platform 2026

**Autonomous AI-powered bug bounty hunting platform with 221 MCP tools, multi-agent architecture, full OWASP coverage, and advanced research capabilities.**

![Platform](https://img.shields.io/badge/Platform-OpenCode-blue)
![MCP Tools](https://img.shields.io/badge/MCP%20Tools-221-green)
![OWASP](https://img.shields.io/badge/OWASP%202021%2B2025%20%2B%20LLM%202026-covered)
![Agents](https://img.shields.io/badge/Agents-21-orange)
![Code](https://img.shields.io/badge/Lines-150K%2B-brightgreen)

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/dot-hunter/anonymous-bug-bounty-platform.git
cd anonymous-bug-bounty-platform

# Install dependencies
pip install mcp fastmcp

# Configure OpenCode
cp config/opencode.jsonc ~/.config/opencode/

# Start hunting
opencode
```

---

## 📊 Platform Overview

| Component | Count | Description |
|-----------|-------|-------------|
| **MCP Tools** | 221 | Across 9 servers |
| **MCP Servers** | 9 | Specialized security tools |
| **Agents** | 21 | Multi-role autonomous agents |
| **Commands** | 27 | Slash commands |
| **Skills** | 13 | JSON skill manifests |
| **Code** | 150K+ | Lines of Python |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    OPENCODE HARNESS                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              AGENT LAYER (21 agents)                  │   │
│  │  autopilot │ recon │ validator │ chain-builder │ ... │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────┴───────────────────────────────┐   │
│  │              MASTER PROMPT (221 lines)                │   │
│  │  Attack Surface │ Trust Boundaries │ Sink-to-Source   │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────┴───────────────────────────────┐   │
│  │              MCP SERVER LAYER (9 servers)             │   │
│  │  vulnera-mcp (128) │ security-research (11)          │   │
│  │  program-intelligence (21) │ agent-reach (8)           │   │
│  │  shodan (6) │ nuclei (5) │ hackerone (5) │ interactsh  │   │
│  └──────────────────────┬───────────────────────────────┘   │
│                         │                                    │
│  ┌──────────────────────┴───────────────────────────────┐   │
│  │              DATA LAYER                               │   │
│  │  Knowledge Graph │ Memory │ Evidence │ Audit Trail     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 MCP Servers

### vulnera-mcp (155 tools)
Full vulnerability assessment engine:
- **OWASP Top 10 (2021+2025)**: Complete coverage
- **SSRF Advanced**: DNS rebinding, IP encoding, redirect chains, gopher
- **BOLA 10 Patterns**: All IDOR patterns from 2026 research
- **LLM Security**: OWASP LLM Top 10 2026
- **API Security**: BFLA, mass assignment, pagination attacks
- **Business Logic**: Payment bypass, coupon abuse, workflow manipulation
- **Supply Chain**: CI/CD analysis, dependency confusion, typosquatting
- **Deserialization**: Java/Python/PHP/.NET gadget chains
- **HTTP Smuggling**: CL.TE, TE.CL, H2.CL
- **Advanced JWT**: KID injection, JKU, algorithm confusion
- **GraphQL Advanced**: Batching, depth, introspection attacks
- **WebSocket Deep**: CSWSH, message injection
- **Prototype Pollution**: Server-side + exploitation chains
- **gf Patterns**: URL filtering for idor/ssrf/xss/sqli/lfi/rce
- **LinkFinder**: JS endpoint + secret extraction
- **VHost Enum**: Host header fuzzing + poisoning checks
- **Auth Recon**: Session-based authenticated testing, BOLA/BFLA primer
- **Platform Core**: Planner, memory, knowledge graph, hypothesis engine

### security-research (11 tools)
- Semgrep static analysis
- CodeQL taint tracking
- Race condition exploitation
- Dependency confusion detection
- PoC scaffold generation
- Variant analysis

### program-intelligence (21 tools)
- Program discovery and scoring
- Research dossier generation
- Technology knowledge graph
- Change detection
- Cross-target memory

### agent-reach (8 tools)
- Twitter/X OSINT
- Reddit thread analysis
- GitHub repo scraping
- YouTube transcript fetching
- Bilibili/XiaoHongShu support

### shodan-mcp (6 tools)
- Host search and discovery
- DNS resolution/reverse
- Account information

### nuclei-mcp (5 tools)
- Template-based scanning
- Profile-based scanning
- Template management

### hackerone-mcp (5 tools)
- Disclosed report search
- Program information
- Report details

### interactsh-mcp (4 tools)
- OOB callback generation
- Interaction tracking
- Payload generation

---

## 🤖 Agents (21)

| Agent | Role |
|-------|------|
| autopilot | Autonomous hunt loop |
| autopilot-hunter | Elite 18-step pipeline |
| program-intelligence | Program discovery/scoring |
| recon-agent | Subdomain enumeration |
| recon-ranker | Attack surface ranking |
| deep-validator | 7-question gate validation |
| exploit-chainer | A→B→C chain building |
| cloud-security | AWS/GCP/Azure assessment |
| cicd-security | Pipeline security review |
| llm-security | AI/LLM app testing |
| mobile-pentest | APK/iOS analysis |
| crypto-auditor | Smart contract audit |
| web3-auditor | DeFi protocol testing |
| zero-day-hunter | Proactive discovery |
| secret-hunter | Credential scanning |
| ai-recon | AI-powered recon |
| chain-builder | Exploit chain builder |
| report-writer | Report generation |
| validator | Finding validation |
| token-auditor | Token security |
| credential-hunter | Credential attacks |

---

## 📋 Commands (27)

| Command | Description |
|---------|-------------|
| `/hunt <target>` | Full autonomous hunt |
| `/recon <target>` | Reconnaissance only |
| `/scan <target>` | Vulnerability scan |
| `/validate` | Validate a finding |
| `/report` | Generate report |
| `/chain <finding>` | Build exploit chain |
| `/scope <target>` | Set scope configuration |
| `/surface` | Map attack surface |
| `/triage` | Triage findings |
| `/intel <target>` | Gather OSINT |
| `/takeover <domain>` | Check subdomain takeover |
| `/cloud-recon <target>` | Cloud asset enumeration |
| `/param-discover <url>` | Parameter discovery |
| `/secrets-hunt <url>` | Secret scanning |
| `/bypass-403 <url>` | 403 bypass attempts |
| `/autopilot` | Autonomous loop |
| `/arsenal` | Tool arsenal |
| `/breach-check` | Breach data check |
| `/chain` | Chain builder |
| `/cloud-recon` | Cloud recon |
| `/memory-gc` | Memory garbage collection |
| `/osint-employees` | Employee OSINT |
| `/param-discover` | Parameter discovery |
| `/pickup` | Pickup findings |
| `/remember` | Remember context |
| `/scan-cves` | CVE scanning |
| `/scope-aggregate` | Scope aggregation |
| `/spray` | Credential spraying |
| `/surface` | Surface mapping |
| `/token-scan` | Token scanning |
| `/triage` | Triage |
| `/validate` | Validate |
| `/web3-audit` | Web3 audit |
| `/wordlist-gen` | Wordlist generation |

---

## 🛡️ OWASP Coverage

### OWASP Top 10 (2021 + 2025)
- ✅ A01: Broken Access Control (BOLA, BFLA, IDOR 10 patterns)
- ✅ A02: Security Misconfiguration (headers, CORS, DNS, email)
- ✅ A03: Software Supply Chain (CI/CD, dependencies, typosquatting)
- ✅ A04: Cryptographic Failures (TLS, ciphers, certificates)
- ✅ A05: Injection (SQLi, XSS, SSTI, XXE, command, NoSQL, LDAP)
- ✅ A06: Insecure Design (business logic, workflow manipulation)
- ✅ A07: SSRF (cloud metadata, internal services, all bypasses)
- ✅ A08: Data Integrity (deserialization gadget chains)
- ✅ A09: Logging Failures (debug endpoints, error analysis)
- ✅ A10: Exception Handling (integer overflow, resource exhaustion)

### OWASP LLM Top 10 (2026)
- ✅ L01: Prompt Injection (direct, indirect, tool abuse)
- ✅ L02: Sensitive Info Disclosure (prompt leak, training data)
- ✅ L03: Supply Chain (AI model integrity)
- ✅ L04: Insecure Output Handling (XSS, injection via LLM)
- ✅ L05: Excessive Agency (permission escalation)
- ✅ L06: System Prompt Leakage (encoding bypasses)
- ✅ L07: Misinformation (hallucination detection)
- ✅ L08: Unbounded Consumption (resource exhaustion)
- ✅ L09: Data/Model Poisoning
- ✅ L10: Agentic Security

---

## 🔬 Advanced Features

### 🧰 Offensive Toolbox (`tools/`)

Readymade offensive tooling, zero external deps required:

| tool | purpose |
|------|---------|
| `tools/xss2shell/` | XSS → interactive browser shell: payload generator + long-poll beacon listener (cookies, keylog, same-origin HTTP, JS eval, redirect) — stdlib only |
| `tools/github-keys/` | One-liner server access from `github.com/<user>.keys` + team onboarding that auto-pulls keys for an entire GitHub org |
| `tools/ssh-playground/` | Public SSH server that greets you by GitHub username — captures offered pubkey fingerprints (never accepts), whoami.filippo.io style (paramiko) |
| `tools/key-trends/` | Key-type trend visualizer — RSA vs Ed25519 over years from GitHub public keys (`created_at`), SVG/ASCII output, no matplotlib |
| `tools/pair-tunnel/` | Instant pair-programming tunnels without sharing keys manually — access derived from GitHub-published keys, ephemeral authorized_keys |

### BOLA — 10 IDOR Patterns
1. Direct ID manipulation (sequential/UUID)
2. Body parameter IDOR
3. File/path reference IDOR
4. GraphQL IDOR
5. Indirect reference IDOR
6. Batch/bulk endpoint IDOR
7. State-changing IDOR (write/delete)
8. Webhook/callback IDOR
9. API versioning IDOR
10. Export/report function IDOR

### SSRF Advanced Bypasses
- DNS rebinding (rbndr.us, nip.io, sslip.io)
- IP encoding (decimal, hex, octal, IPv6)
- URL parser confusion (credentials, backslash, fragment)
- Redirect bypass (open redirect chaining)
- Protocol smuggling (gopher, file, dict, ftp)
- IMDSv2 bypass testing

### Business Logic
- Payment bypass (negative amounts, zero price)
- Coupon abuse (20 common codes)
- Workflow manipulation (skip steps, state transitions)
- Integer overflow (int32 max, infinity, NaN)

### Supply Chain
- CI/CD pipeline analysis (GitHub Actions, GitLab CI, Jenkins)
- Dependency confusion detection
- Typosquatting detection (14 mutation patterns)
- SBOM generation

---

## 📁 Repository Structure

```
anonymous-bug-bounty-platform/
├── mcp-servers/                  # Core MCP servers
│   ├── vulnera-mcp/             # 155 tools — main engine
│   ├── security-research/       # 11 tools — SAST/CodeQL
│   ├── agent-reach/             # 8 tools — OSINT
│   ├── bounty-directory/        # 6 tools — program DB
│   └── program-intelligence/    # 21 tools — discovery
├── mcp-servers-external/        # External MCP servers
│   ├── nuclei-mcp/              # 5 tools — template scanning
│   ├── interactsh-mcp/          # 4 tools — OOB callbacks
│   ├── shodan-mcp/              # 6 tools — internet intel
│   └── hackerone-mcp/           # 5 tools — H1 reports
├── config/                      # OpenCode configuration
│   ├── opencode.jsonc           # Main config
│   ├── master-prompt.md         # Agent system prompt
│   ├── enterprise-attack-2026.json
│   └── waf-bypass-2026.json
├── agents/                      # 21 agent definitions
├── commands/                    # 27 slash commands
├── skills/                      # 13 skill manifests
├── tools/                       # Offensive toolbox
│   ├── xss2shell/              # XSS -> interactive browser shell
│   ├── github-keys/            # 1-liner SSH access + org onboarding
│   ├── ssh-playground/         # SSH server that greets by GitHub user
│   ├── key-trends/              # RSA vs Ed25519 trend visualizer
│   └── pair-tunnel/             # pair-programming tunnels, no key sharing
├── docs/                        # Audit reports
│   ├── deep-audit-report.md
│   ├── phase-a-architecture-audit.md
│   ├── inventory.json
│   ├── agent-audit.md
│   ├── comparison.md
│   ├── skill-gap-analysis.md
│   ├── mcp-audit.md
│   ├── opsec-plan.md
│   ├── research.md
│   ├── roadmap.md
│   ├── upgrade-plan.md
│   └── todo.md
└── README.md                    # This file
```

---

## 🔐 OPSEC Features

- **Scope Guard**: Validates every outbound request against authorized scope
- **Rate Limiter**: Adaptive per-target rate limiting with auto-backoff
- **Audit Trail**: Complete JSONL audit log of all actions
- **VPN/Tor Toolkit**: Anonymous routing infrastructure
- **Identity Rotation**: Burner identity management
- **Traffic Shaping**: Human-like request patterns

---

## 📈 Platform Phases (All Complete)

| Phase | Component | Status |
|-------|-----------|--------|
| A | Architecture Audit | ✅ |
| B | Goal-Driven Planner | ✅ |
| C | Long-Term Memory | ✅ |
| D | Knowledge Graph | ✅ |
| E | Hypothesis Engine | ✅ |
| F | Evidence-Based Reasoning | ✅ |
| G | Continuous Learning | ✅ |
| H | Multi-Agent Event System | ✅ |
| I | Observability | ✅ |
| J | Reliability (checkpoint/retry/circuit) | ✅ |
| K | Research Workflow | ✅ |
| L | Human Review Gates | ✅ |

---

## ⚠️ Legal Disclaimer

This platform is designed for **authorized security testing only**. Always:

1. Obtain explicit written permission before testing any target
2. Respect program scope and rules of engagement
3. Follow responsible disclosure practices
4. Never test systems you don't own or have authorization to test

Unauthorized access to computer systems is illegal.

---

## 📄 License

MIT License — See LICENSE file for details.

---

## 👤 Author

**dot-hunter** — Autonomous Security Research Platform

---

*Built with ❤️ for the bug bounty community. Happy hunting! 🐛*
