# Top 10 Submission Mistakes (read before reporting)

Distilled from N/A and informational closures across public bug bounty programs. Each mistake costs you review time and reputation.

## 1. Submitting without a reproduction
No exact URL, no raw request, no replayable payload. Triage closes as "Needs more info" or N/A.
**Fix:** Reproduce once more, paste raw request (with headers) + response, screenshot.

## 2. Impact language that hedges**
"May allow an attacker to...", "could potentially result in..." — triggers auto-rejection templates.
**Fix:** Replace with the observed behavior: "Attacker-supplied value rendered unsanitized in victim browser (repro attached)."

## 3. Reporting informational as vulnerability
Missing headers, self-XSS, clickjacking with no target, banner disclosure. Flagged N/A.
**Fix:** Check `rules/never-submit.md` before writing. If it matches Always-Rejected, kill it or build a chain.

## 4. Out-of-scope assets
Testing `staging.target.com` listed as out-of-scope, or third-party CDN — immediate N/A + possible ban.
**Fix:** Run scope check (`resolve_authorization`) BEFORE the test, not after. One request outside scope = session contaminated.

## 5. Duplicate submission
Same vuln class on same asset, week-old hacktivity post, you never checked.
**Fix:** Hacktivity + memory search before report (rule 17). If unclear dupe, contact the Triage with your evidence first.

## 6. Wrong CVSS version
H1 wants 3.1, others 4.0 — auto-blocked at the platform layer.
**Fix:** `validate_cvss(platform, report)` in the pipeline; re-calculate with the platform's official calculator.

## 7. Over-reporting a scanner hit
Nuclei/dalfox output pasted as a bug without manual confirmation. Scanner noise = poor reputation.
**Fix:** Manual confirmation — reproduce with a context-specific payload, prove impact.

## 8. Skipping rate limits / heavy scans
DoS-ish automation sets off WAF/IDS, gets the session IP banned, and kills your other findings.
**Fix:** Default 30 req/min, hypothesis-driven targeted requests; over 429 → slow down.

## 9. Verbose report walls of text
Long preamble, 5 unrelated issues in one report, no reproduction steps. Triage dislikes walls.
**Fix:** One finding per report, steps to reproduce numbered, evidence collected, severity computed.

10. **No chain documentation**
Open redirect submitted alone at Low; 5 minutes of chaining would have made it High (OAuth).
**Fix:** Always run chain-table.md when closing out a session: which gadget can escalate?

## Session close checklist

- [ ] Did I kill the obvious N/A findings myself?
- [ ] Is the PoC reproducible by a triager in <10 minutes?
- [ ] Are all assets in scope verified?
- [ ] Is the CVSS version correct for the platform?
- [ ] Did I document the chain (if any)?
- [ ] Did I log a lesson to memory for the next run?