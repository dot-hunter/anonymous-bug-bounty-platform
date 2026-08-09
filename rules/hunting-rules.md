# Hunting Rules — 30 Rules of Engagement (read at session start)

Operational rules that govern every hunt session. Violating a rule kills the session or the finding.

## Scope & Authorization (1-6)

1. **Scope is law.** Only test assets that resolve `in_scope` via `resolve_authorization`. Never "check anyway" — a single out-of-scope request invalidates the session.
2. **Policy beats instinct.** Read program policy before testing: some programs exclude XSS, limit to `*.site.com`, exclude `.env`/leaked-secret reports, require no automated scanning.
3. **Permission levels.** Passive recon (headers, DNS, robots, certificates) is always allowed on in-scope hosts. Active testing requires the asset be listed in scope + not excluded.
4. **Rate limit default 30 req/min**, recon 10 req/min. Back off on any 429/503. If rate limit observed, wait 60s and reduce by half.
5. **No destructive testing.** Never delete, modify, or exfiltrate real user data. PoC with self-created objects only. Test accounts / test data only.
6. **Stop on critical.** RCE / full DB / ATO confirmed → stop active exploitation of that path immediately, checkpoint state, notify.

## Never-Submit Filter (7-12) — kill these before writing a report

7. **Self-XSS without a chain.** XSS that only fires in your own browser with no impact path (CSRF→stored, admin consumer) = kill.
8. **Missing security headers.** X-Frame-Options, CSP, HSTS missing = informational, not a finding, unless you have a working CSP bypass PoC + sensitive action.
9. **Rate limiting alone.** Brute force on login not limited — needs an ATO-capable PoC (credential stuffing against real account).
10. **Username enumeration** — needs a credential-stuffing or ATO path, not just "different error messages."
11. **Clickjacking** — needs a sensitive action target (account deletion, money transfer) with a working overlay PoC.
12. **"Could potentially"** — any finding that requires hedging language is not ready. Reword with evidence or kill it.

## Finding Quality (13-18)

13. **Reproduce first.** A finding without a working repro is a hypothesis. Re-run the exact request twice; capture both responses.
14. **Prove impact, not just injection.** Payload that reflects is NOT impact. Show: data read, cookie exfil, state change, or OOB callback.
15. **Evidence bundle.** Every finding ships with: request (raw), response (raw), screenshot (if UI), timestamp, and the exact payload.
16. **CVSS version per platform.** H1 = CVSS 3.1; Bugcrowd/Intigriti/Immunefi/YesWeHack = CVSS 4.0. Wrong version = instant block.
17. **Duplicate check before writing.** Search hacktivity + memory for the same vuln on the same asset. Never submit known dupes.
18. **One finding = one root cause.** Don't bundle 5 unrelated issues in one report. Chain-related findings document the chain, then report the highest-impact node.

## Process (19-24)

19. **Hypothesis before hammering.** Test a named hypothesis (class + param + expected behavior). Generic endpoint scanning without hypothesis = noise.
20. **Confirm sink first** (sink-first workflow). Find the execution sink, trace back to user data. Only then run payloads.
21. **Sibling check.** If you find a bug in endpoint A, check sibling endpoints B/C (same pattern) — report as variants, not separate reports.
22. **Detection-token rotation.** Use a fresh marker (canary id/payload) per test to avoid cross-test confusion; rotate when re-testing.
23. **Checkpoint after every stage.** State saved after each pipeline stage. Never lose progress to a crash.
24. **Mutation matrix.** When a payload is filtered, apply the mutation matrix (encoding → casing → comments → whitespace → unicode) before concluding "filtered."

## Tooling (25-30)

25. **Scanner output is a lead, not a finding.** dalfox/nuclei hits require manual confirmation with the context-specific payload.
26. **OOB for blind.** Blind injection (SSRF/XSS/SQLi) confirmed only via interactsh/DNS callback evidence, saved with session ID.
27. **Never store raw secrets.** Cookies/tokens in memory only; log session_id hash (12 chars) to audit.jsonl.
28. **Noise budget.** Prefer targeted requests over scans. 429 = target awareness = fail. When scanning, stay under 30 req/min.
29. **PoC self-contained.** Single command, reproducible, safe (read-only or self-created object). Docker PoC preferred.
30. **Session hygiene.** New session = fresh identity + fresh tokens + fresh scope check. Never carry tokens across sessions.