# Never-Submit — Findings that get KILLED at the gate

Read before writing ANY report. If your finding matches a row here, kill or chain it before spending time on a report.

## Always-Rejected (kill immediately, no report)

| # | Finding | Why rejected |
|---|---------|--------------|
| 1 | Self-XSS with no impact chain | No other victim; no demonstrated impact |
| 2 | Missing security headers (CSP, HSTS, X-Frame-Options) | Informational; requires working bypass PoC + sensitive action to be valid |
| 3 | Clickjacking without sensitive action target | No demonstrated harm; most programs mark N/A |
| 4 | Rate limit missing on login | Requires ATO-capable PoC (credential stuffing to real account) |
| 5 | Username/email enumeration | Informational unless credential-stuffing path exists |
| 6 | OPTIONS enabled / CORS wildcard with no data exposure | No impact demonstrated |
| 7 | Password complexity or policy findings | Out of security-control scope for most bug bounties |
| 8 | Response headers version disclosure (server banner, X-Powered-By) | Informational; no direct exploit |
| 9 | TLS/SSL config (old cipher, missing HSTS preload) | Informational; tool-time, rarely accepted |
| 10 | CDN/DNS propagated info (SPF/DKIM/DMARC weak) | Informational; no direct impact |
| 11 | Mobile app uses HTTP instead of HTTPS | Accepted only on iOS/Android strict policies; needs interceptor demo |
| 12 | "Potential" / "theoretical" / "could allow" | Not a finding — no repro, no impact |

## Conditionally Valid (report only WITH demonstrated chain)

| # | Finding | Valid chain |
|---|---------|-------------|
| 1 | Self-XSS | + CSRF→store in DB → fires for other users (becomes stored XSS) |
| 2 | Open redirect | + OAuth token theft / + phishing credential capture with tool |
| 3 | CORS misconfig | + sensitive authenticated endpoint with credentials mode to prove read |
| 4 | Cache poisoning | + unkeyed header is attacker-controlled + victim cache = stored XSS |
| 5 | Username enumeration | + credential stuffing against real user (must not do!) → chained ATO |
| 6 | PUT/DELETE without authz on low-sensitivity endpoint | + show write impact to real data |
| 7 | SSRF without response reflection | + OOB DNS callback (interactsh) proves outbound request |
| 8 | Clickjacking | + sensitive action (account deletion, payment) with overlay demo |
| 9 | IDOR informational (empty body / count leak) | + chained to real read (via related endpoint) |
| 10 | Verbose error/stack trace | + contains secrets/keys usable in chain |

## Gate Rules

- If a finding matches an Always-Rejected row: **KILL** — do not write a report.
- If it matches Conditionally Valid: **CHAIN or DOWNGRADE** — build the chain first, or downgrade to low/informational and only report if the program explicitly wants it.
- If you cannot remove hedging language from the summary within one rewrite: **KILL**.
- Gate verdicts: PASS / KILL / DOWNGRADE / CHAIN_REQUIRED — no other outcomes.