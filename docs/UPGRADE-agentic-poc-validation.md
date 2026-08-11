# UPGRADE PLAN — Agentic PoC Validation Layer ("VALIDATOR")

## 1. Why (research summary)

Online research (giveen/late-sast, dshochat/Argus_Scanner, backspace-shmackspace/deep-code-security,
ksgsslee/vulnhunt-agent, iamngoni/heimdall, securelayer7/sandyaa, nandrzej/vlnr, Hacktron AI SAST)
converges on one pattern: **pattern-matching SAST floods; agentic validation proves.**

Common architecture of every serious tool:
```
Static candidates → deterministic triage → sandbox execution → bounded-PoC retry loop
→ verdict classification (CONFIRMED/BLOCKED/UNREACHABLE/NEEDS_CONTEXT) → report only proofs
→ retest mode (FIXED/STILL_PRESENT)
```
Key shared rules:
- "If it cannot prove it, it does not report it" (Hacktron)
- Sandbox constraints: no network, CPU/RAM/time caps, non-root, read-only repo (heimdall: 1 CPU / 512MB / 30s)
- Bounded retry with refinement from failure logs (vlnr: 2 attempts Tier1→Tier2)
- False positives kept as VEX/audit trail, not deleted (vlnr, Argus SUPPRESSED)
- Adversarial review stage tries to DISPROVE findings before report (heimdall Vidarr)
- Retest against patched code (late-sast)

## 2. Current state vs target (deep-dive gaps)

| Capability | Current project | Target |
|---|---|---|
| Static candidates | ✅ semgrep/codeql/gitleaks, RAG payload corpus | keep |
| PoC scaffold generation | ✅ generate_poc_scaffold (Dockerfile+script+draft) | keep |
| PoC EXECUTION | ❌ never runs | sandbox runner |
| Verdict classification | ❌ no | CONFIRMED/BLOCKED/UNREACHABLE/NEEDS_CONTEXT/INCONCLUSIVE |
| Noise filter/triage | ❌ all findings forwarded | POC_CANDIDATE/STATIC_ONLY/IGNORE/HUMAN_REVIEW |
| Bounded retry/refine | ❌ single shot | ≤3 attempts, corpus+encoder variants |
| Evidence/audit per finding | ❌ | per-finding evidence dir (cmd,out,err,verdict) |
| Retest mode | ❌ | FIXED/STILL_PRESENT/CANNOT_VERIFY |
| FP ledger (VEX) | ❌ | vex.json |
| Sandbox availability | ❌ no docker/podman/bwrap/firejail on this box | layered backends + honest jail fallback |

## 3. Architecture

```
agentic_audit.py --target-dir <repo> [--retest <report.json>] [--sandbox auto|docker|jail]

  HUNT      semgrep (custom rules + OWASP) + gitleaks secrets scan
     │      → raw findings (file, line, vuln_class, severity, snippet)
     ▼
  TRIAGE    noise_filter.py (deterministic rules)
     │      R1 test/vendor/generated → IGNORE
     │      R2 sink line + source-token reachability → POC_CANDIDATE | HUMAN_REVIEW
     │      R3 sanitizer tokens present → mark sanitized (auditor will try to disprove)
     │      R4 dedupe (class+file+sink), R5 LOW/INFO → STATIC_ONLY
     ▼
  AUDIT     poc_validator.py — bounded retry loop (≤3 attempts)
     │      attempt0: payload from RAG corpus (by vuln_class)
     │      attempt1: encoder variants (waf_encoder.py)
     │      attempt2: alternate sinks/inputs
     │      each attempt runs INSIDE sandbox via sandbox_runner.py
     ▼
  VERDICT   differential (payload vs benign) + class-specific signal (marker/file/OOB)
     │      CONFIRMED | BLOCKED | UNREACHABLE | NEEDS_CONTEXT | INCONCLUSIVE
     ▼
  REPORT    findings/audit/<ts>/report.md + findings.json + vex.json
            evidence/<id>/{poc.py, out.txt, err.txt, verdict.json}
            ONLY CONFIRMED reach the headline; LIKELY flagged; FPs → VEX
  RETEST    re-scan + re-validate prior report findings → FIXED/STILL_PRESENT/CANNOT_VERIFY
```

## 4. Sandbox backends (layered, honest)

1. `docker` → `podman` → `bwrap` → `firejail` (full isolation, no net, caps) — auto-detected
2. **jail** (always available, no privileges): tmp dir cwd, empty env, `-I -E` python,
   `resource` caps (RLIMIT_CPU/AS/NOFILE/NPROC), process-group timeout kill,
   **LD_PRELOAD sockblock.so** (tiny C shim compiled with gcc at first run — sockets
   return ENONET ⇒ network isolation without root)
3. If nothing can isolate network, honest `NO_ISOLATION` warning in report header.

## 5. Files

| File | Purpose |
|---|---|
| tools/agentic/noise_filter.py | deterministic triage classifier + unit tests |
| tools/agentic/sandbox_runner.py | layered backends incl. sockblock jail + tests |
| tools/agentic/sockblock.c | network-block shim (gcc -shared) |
| tools/agentic/poc_validator.py | bounded retry PoC loop + verdicts |
| tools/agentic/agentic_audit.py | orchestrator CLI + report/retest/VEX |
| tools/agentic/agentic_audit.sh | hunter.sh-compatible wrapper |
| tools/agentic/tests/ | unit + integration tests (fixtures incl. vuln app) |
| docs/UPGRADE-agentic-poc-validation.md | this plan |
| tools/hunter.sh | new `--audit` mode |
| agents/autopilot-hunter.md | Stage 12.5 Agentic PoC Gate |
| mcp-servers/security-research/server.py | `agentic_audit` + `poctester_run` tools |

## 6. Test plan

- Unit: noise filter decisions, sandbox verdicts, retest transitions
- Fixture `tests/fixtures/app_vuln/`: cmd-injection fn, path-traversal fn, sanitized fn, clean fn
- Integration: full run ⇒ CONFIRMED×2, BLOCKED×1; fixed copy ⇒ retest FIXED
- Existing 168 tests stay green; new suite added to platform tests

## 7. Security boundaries (of the validator itself)

- Never runs code outside sandbox backend; jail mode explicitly logged as logical-only isolation
- No network in any sandbox mode; OOB confirmation only via interactsh for remote targets (separate path)
- Bounded time/CPU/memory per attempt; bounded attempts; cleanup between runs
- Only targets the operator puts in --target-dir (authorized code)