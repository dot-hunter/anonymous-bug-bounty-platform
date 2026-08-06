# MCP Server Audit — OpenCode Bug Bounty Ecosystem 2026

**Date:** 2026-08-06  
**Scope:** 9 MCP servers across `~/.opencode/mcp/servers/` and `~/tools/claude-bug-bounty/mcp/`

---

## Server Inventory

| MCP Server | Type | Transport | Tools | Real MCP? | Status |
|-----------|------|-----------|-------|-----------|--------|
| vulnera-mcp | local | stdio | 27 | ✅ Yes | Active (but stubs) |
| security-research | local | stdio | 11 | ✅ Yes | Active (functional) |
| agent-reach | local | stdio | 9 | ✅ Yes | Active (degraded) |
| bounty-directory | local | stdio | 6 | ✅ Yes | Active (limited) |
| program-intelligence | local | stdio | 22 | ✅ Yes | Active (modular) |
| hackerone | local | stdio | ~5 | ✅ Yes (FastMCP) | Venv-only |
| nuclei | local | stdio | ~3 | ❌ CLI wrapper | CLI-only |
| interactsh | local | stdio | ~3 | ❌ CLI wrapper | CLI-only |
| shodan | local | stdio | ~4 | ❌ CLI wrapper | CLI-only |

---

## Per-Server Security Assessment

### vulnera-mcp — Score: 45/100 (Security: 50, Usefulness: 40, Speed: 60, Token Cost: 70)

**Permissions:**
- Bash: unrestricted (called by autopilot)
- Filesystem: writes to `~/.config/vulnera-mcp/`
- Network: unlimited outbound via subprocess calls to external tools

**Security Findings:**
- ⚠️ **CRITICAL: No scope validation** — accepts any target string and runs tools against it
- ⚠️ **No rate limiting** — can flood targets with requests
- ⚠️ **Command injection risk** — `_run()` uses `subprocess.run(cmd, ...)` with list args (safe) but passes user-controlled target strings directly to CLI tools without sanitization
- ⚠️ **Unrestricted filesystem** — KnowledgeGraph writes to `~/.config/vulnera-mcp/graph.json` (no size limit)
- ⚠️ **No audit trail** — does not log which targets were tested
- ✅ **Sandboxed** — runs as local user, no escalation

**Secrets Exposure:** None (no API keys required)

**API Scopes:** N/A (CLI tool wrapper)

**Command Injection Risk:** Medium — target strings passed directly to subfinder, amass, etc. If target contains shell metacharacters in some paths (e.g., via f-string formatting), injection is possible.

**Context Leaks:** Low — returns structured JSON, no session data exposed.

**Privilege Escalation:** None.

**Filesystem Abuse:** Medium — unbounded graph.json growth, no rotation.

**Performance:** KnowledgeGraph._save() called on every add_node/add_edge — disk I/O bottleneck.

---

### security-research — Score: 82/100 (Security: 85, Usefulness: 90, Speed: 75, Token Cost: 70)

**Permissions:**
- Filesystem: reads target code paths, writes to `~/.config/opencode/session-logs/` and `~/.config/opencode/weird-inventory/`
- Network: only for dependency confusion check (npmjs registry)

**Security Findings:**
- ✅ **No shell execution** — only semgrep/codeql subprocess with controlled args
- ✅ **Temporary file cleanup** — semgrep rules cleaned up after run
- ✅ **Input validation** — session_id sanitized with regex for weird inventory paths
- ⚠️ **CodeQL temp DB not cleaned** — `_run_codeql_impl` creates temp dirs but doesn't remove them after runs
- ⚠️ **Race condition test opens arbitrary URLs** — `_race_attack` uses urllib without proxy support, sends requests to user-controlled URL
- ⚠️ **No scope checking on target_path** — semgrep/codeql can scan any path the user provides
- ✅ **Dependency confusion uses timeout** — 10s per package check

**Secrets Exposure:** None.

**Command Injection Risk:** Low — all subprocess calls use list args.

**Sandbox Escapes:** None.

**Context Leaks:** None — session logs are local.

---

### agent-reach — Score: 58/100 (Security: 60, Usefulness: 55, Speed: 50, Token Cost: 65)

**Permissions:**
- Network: unlimited outbound (Twitter, Reddit, GitHub, YouTube, Bilibili, XiaoHongShu)
- Filesystem: writes cookies to `~/.config/agent-reach/cookies/`

**Security Findings:**
- ⚠️ **Cookie storage** — cookies stored in plaintext locally
- ⚠️ **No request signing** — requests to platforms may be traceable
- ⚠️ **No proxy support** — all requests originate from host IP (OPSEC risk)
- ⚠️ **Regex parsing of HTML** — fragile, may expose to injection if HTML contains crafted patterns
- ⚠️ **No rate limiting** — can trigger platform bans
- ✅ **Privacy-first** — instructions say "data never uploaded"
- ⚠️ **GitHub API unauthenticated** — rate limited to 60 req/hr

**Secrets Exposure:** Cookies stored locally (medium risk).

**SSRF Risk:** Low — URLs are platform-specific, not user-arbitrary.

**Browser Abuse:** N/A.

---

### bounty-directory — Score: 35/100 (Security: 70, Usefulness: 25, Speed: 90, Token Cost: 95)

**Permissions:**
- Filesystem: reads/writes `~/.config/vulnera-mcp/programs.json`

**Security Findings:**
- ⚠️ **F-string syntax error** — line 150 has nested quotes that will cause runtime error
- ⚠️ **Only 10 hardcoded programs** — no live data source
- ⚠️ **No API integration** — HackerOne/Bugcrowd APIs not used
- ✅ **No network exposure** — purely local
- ✅ **Read-only operations** (except report generation)

**Secrets Exposure:** None.

---

### program-intelligence — Score: 68/100 (Security: 75, Usefulness: 70, Speed: 55, Token Cost: 60)

**Permissions:**
- Filesystem: reads/writes `~/.config/program-intelligence/` (multiple files)
- Network: potentially for research dossier generation

**Security Findings:**
- ⚠️ **No size limits on memory store** — unbounded growth
- ⚠️ **Knowledge graph linear scan** — O(n) queries, slow with scale
- ✅ **Additive-only memory** — never deletes (audit trail preserved)
- ✅ **No shell execution** — pure Python
- ⚠️ **Research dossier may fetch external URLs** — SSRF potential if not validated

**Secrets Exposure:** None (local file storage only).

---

### hackerone (claude-bug-bounty) — Score: 75/100 (Security: 80, Usefulness: 85, Speed: 70, Token Cost: 65)

**Permissions:**
- Network: HackerOne API (read-only for disclosed reports)
- Filesystem: none

**Security Findings:**
- ✅ **Read-only API access** — only fetches disclosed reports
- ✅ **Integrity hash** — SHA-256 verification for server.py
- ⚠️ **Requires venv** — only works under `.venv-mcp/bin/python`
- ⚠️ **No API key needed** — uses anonymous access (limited data)
- ✅ **Graceful degradation** — handles network errors

**Secrets Exposure:** None (anonymous access).

**API Scopes:** Read-only, disclosed reports only.

---

### nuclei (claude-bug-bounty) — Score: 50/100 (Security: 60, Usefulness: 65, Speed: 80, Token Cost: 55)

**Type:** CLI wrapper, NOT a real MCP server.

**Security Findings:**
- ⚠️ **Not an MCP server** — despite the `-mcp` name, has no FastMCP/MCP protocol implementation
- ✅ **CLI-only** — runs nuclei as subprocess
- ⚠️ **Full nuclei capability** — can scan any target with any template
- ⚠️ **No scope checking** — passes targets directly to nuclei

**Command Injection Risk:** Low — uses subprocess list args.

---

### interactsh (claude-bug-bounty) — Score: 40/100 (Security: 65, Usefulness: 30, Speed: 70, Token Cost: 60)

**Type:** CLI wrapper, NOT a real MCP server.

**Security Findings:**
- ⚠️ **Not an MCP server** — CLI-only history/serve commands
- ✅ **OOB interaction tracking** — useful for blind SSRF/XXE
- ⚠️ **Requires interactsh-client binary** — external dependency

---

### shodan (claude-bug-bounty) — Score: 45/100 (Security: 70, Usefulness: 40, Speed: 65, Token Cost: 50)

**Type:** CLI wrapper, NOT a real MCP server.

**Security Findings:**
- ⚠️ **Not an MCP server** — CLI-only search/info commands
- ⚠️ **Requires SHODAN_API_KEY** — gracefully degrades if missing
- ✅ **No key = no data** — safe failure mode
- ⚠️ **API key in environment** — potential exposure via env inspection

---

## Aggregate MCP Security Scorecard

| Criterion | Score | Notes |
|-----------|-------|-------|
| Permission Granularity | 40 | All-or-nothing bash allow |
| Secret Protection | 75 | API keys via env vars |
| Command Injection Resistance | 80 | Most use list args |
| Scope Enforcement | 25 | Almost no scope checking |
| Rate Limiting | 10 | No rate limits anywhere |
| Audit Logging | 20 | No centralized audit log |
| Sandbox Isolation | 60 | Local execution, no containerization |
| SSRF Protection | 50 | Some tools validate URLs |
| Context Leak Prevention | 80 | Minimal context escaping |
| **Overall MCP Security** | **49** | **F** |

---

## Recommendations

### P0 — Critical
1. **Implement scope checking in vulnera-mcp** — add scope_guard integration
2. **Fix bounty-directory f-string syntax error** — runtime crash
3. **Add rate limiting to vulnera-mcp** — prevent target flooding
4. **Clean CodeQL temp databases** — disk leak

### P1 — High
5. **Convert nuclei/interactsh/shodan to real MCP servers** or remove `-mcp` naming
6. **Add proxy support to agent-reach** — OPSEC requirement
7. **Implement audit logging** — every outbound request logged
8. **Add scope validation to race_condition_test** — prevents testing out-of-scope URLs
9. **Add input sanitization for target parameters** — prevent command injection via tool args

### P2 — Medium
10. **Add integrity hashes for all MCP servers** — not just hackerone
11. **Implement memory store TTL** — prevent unbounded growth
12. **Add proxy support to security-research** — for race condition tests
13. **Implement disk usage limits** — graph.json, memory store, session logs
