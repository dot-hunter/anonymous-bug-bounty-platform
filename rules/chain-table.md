# Chain Table — capability → next bug → payout

Use this table when you hold a single low/medium finding ("gadget") and want to escalate to a reportable severity. Chains documented with the DEEP CHAINS section are proven compound attacks.

## Capability → Next-Bug Map

| You have | Capability | Next bug to hunt | Final severity |
|----------|-----------|------------------|----------------|
| Open redirect | Any URL on trusted domain redirects | OAuth `redirect_uri` bypass, token in referrer, cache poisoning | High (ATO) |
| Reflected XSS | Script exec in own session | Find stored sink (profile, comment) or admin consumer scan | Medium→High |
| Stored XSS (user) | Script exec for users | Admin panel consumption = blind XSS → ATO | Critical |
| DOM XSS | Client-side exec | postMessage → sink on sensitive page (payment) | High |
| SSRF | Internal fetch | Cloud metadata → IAM creds, Redis gopher → RCE | Critical |
| SSRF (blind) | Outbound to anything | Internal service port scan → admin panel → known CVE | High |
| IDOR (read) | Object read | Password-reset token / email change → ATO | Critical |
| IDOR (count leak) | Meta info only | Data leak via export/batch endpoint | Medium |
| Open CORS | Exfil API reads | Auth'd sensitive endpoint with credentials mode | Medium+ |
| Cache poisoning | Unkeyed header | XSS on victim cached pages | High |
| Subdomain takeover | DNS dangling | OAuth redirect_uri accept → token steal | High |
| LFI | File read | Log poisoning → RCE; secrets → further access | Critical |
| SQLi (bool) | Data extraction | DB creds → host RCE; admin creds → ATO | Critical |
| Cloud bucket read | Object read | IAM keys in objects → account takeover | Critical |
| Prototype pollution | Object merge | → XSS (browser) / → RCE (Node settings) | High |
| JWT alg gymnastics | Token forge | → admin token / ATO | High |
| Race (single-use) | Token reuse | Coupon/payment double-spend | High |
| SSTI (math) | Template exec probe | → engine RCE chain | Critical |
| Dependency confusion | Package name takeover | → CI/CD RCE (read installed package) | Critical |
| LLM tool abuse | Fetch/code tool | → SSRF metadata / RCE in sandbox | High |
| Captcha/nonce bypass | Flow control | → brute / spam / coupon | Medium |

## Deep Chains (documented 4)

### Chain 1: XSS → ATO
1. Reflected or stored XSS on any page
2. Sink must reach `document.cookie` (HttpOnly? no → direct; yes → same-origin fetch to `/api/me` or CSRF token steal)
3. Trigger victim visit (share link, admin consumer, report reading)
4. Result: session hijack / ATO — **CVSS 9.0+ if admin or sensitive scope**

### Chain 2: SSRF → Metadata → Cloud Takeover
1. URL fetcher callable with arbitrary URL
2. `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` returns JSON keys
3. Use keys → `aws s3 ls`, `ec2 describe`, console login as role
4. Result: full cloud account takeover — **CVSS 10.0 class**

### Chain 3: IDOR → Password Reset → ATO
1. User B object accessible (user_id in body/url)
2. `POST /api/reset {user_id: B}` → reset ticket created for B
3. Read reset link via IDOR on reset request / email oracle response
4. Or: change profile email of B to attacker email → request normal reset
5. Result: **ATO — CVSS 9.0+**

### Chain 4: Subdomain Takeover → OAuth
1. Dangling CNAME to expired third party → register, host content
2. If `redirect_uri` in OAuth allows `https://stale.target.com/dropped` (some do), or `login.microsoft` style
3. Capture victim authorization code
4. Result: ATO via code capture — **High/Critical**

## Rules for reporting chains

Rule 1: report the **highest-severity node** with the full chain documented; don't spread separate reports for chain hops (flagged as duplicate).
Rule 2: every hop must be `in_scope` — out-of-scope hop → kill the chain.
Rule 3: do NOT execute destructive last steps (deleting victim data, password resets on real accounts); show capability with self-created objects + screenshots.