# Hunt OAuth/OIDC — Deep Methodology

**Version:** 2026.2  
**Source:** OAuth 2.0 Security Best Current Practice (RFC 9700), OWASP OAuth Cheat Sheet, PortSwigger Research "The OAuth authorization framework", Hacktivity 2024-2026

---

## Attack Theory

OAuth 2.0 and OpenID Connect are the dominant authorization/authentication frameworks. Misconfigurations allow account takeover, privilege escalation, and unauthorized access. The spec's flexibility ("MAY", "SHOULD", optional parameters) creates a large attack surface where egress filters rarely cover the many divergences between spec and implementation.

Goal: turn any OAuth flow on the target into (a) stolen authorization code, (b) forced CSRF account linking, or (c) token theft via leak.

## Entry Point Discovery

1. Find login button → capture the `redirect_uri`, `client_id`, `state` in the flow.
2. Grep JS for `client_id`, `redirect_uri`, `response_type`, `oauth`, `sso`, `authorize` — many apps hardcode non-standard parameters.
3. Test the **authorization server pattern**: `GET /authorize?response_type=code&client_id=&redirect_uri=&state=`; capture and document the full request.
4. If tokens rotate: capture `refresh_token`, bring it into scope.

---

## Sub-Techniques

### A. redirect_uri Manipulation
If AS doesn't strictly validate:
- `redirect_uri=https://evil.com/cb` — steal code
- `redirect_uri=https://target.evil.com/cb` — subdomain
- `redirect_uri=https://target.com@evil.com/cb` — userinfo
- `redirect_uri=https://target.com.evil.com/cb` — lookalike
- `redirect_uri=https://target.com/cb/%2e%2e%2f%2e%2e/evil` — path traversal
- `redirect_uri=http://localhost:8080/cb`, `http://127.0.0.1:PORT/cb` — dev/loop
- `redirect_uri=https://target.com/cb?foo=bar@evil` — param injection
- `redirect_uri=%68ttps://evil` — encode
- `redirect_uri=target.com/cb` — scheme drop
- `redirect_uri=//evil.com/` — protocol-relative
- Fragment tricks: `#@evil.com`, `?@evil.com`
- Substring allowlist bypass: allowed prefix `target.com` with `redirect_uri=https://target.com.evil.com/` if regex forgets `\b` or `^`
- CRLF: `https://target.com/cb%0d%0aHost:evil` — response splitting where flow echoes URI

### B. state Parameter CSRF
- Missing state → login CSRF / account linking attack: attacker completes their OAuth against victim session
- Weak state (timestamp, static) → predictable
- State not bound: works across clients
- Attacker flow: own account flow → get code → transcode in victim's browser via `https://target.com/cb?code=xxx&state=yyy` — if victim app associates code to attacker's identity = account linking

### C. PKCE Bypass
- Public client (mobile/SPA) without PCKE → code interception (network attacker/traffic inspection)
- PKCE present but `code_challenge` ignored → remove `code_challenge` param, flow still completes
- PKCE downgrade: S256 → plain (if lib) — verify mismatch accepted

### D. Implicit Flow Abuse
- `response_type=token` places token in URL fragment → leaks to Referer on any external resource, browser history, logs
- Single-page: token in fragment + JS reads → XSS → full token theft chain
- Legacy flows: `response_type=id_token token` (OIDC hybrid)

### E. Code Reuse & Token Swap
- Code single-use? Replay same code → multi-session
- Refresh token rotation: does old refresh still work after use (`refresh_token` reuse → indefinite session)
- Token exchange: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with wrong audience
- JWT bearer grant: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` — forge? no, but test audience/iss

### F. Scope Escalation
- `scope=read` vs `scope=admin/write/*` — server may accept
- `scope` omitted entirely → defaults may be broad
- Offline access: `access_type=offline` → adds refresh (longer-lived session)
- Client credential grants: `client_credentials` with big scope

### G. OpenID Connect Specific
- `nonce` missing → replay/cliff
- ID token signature not validated → forge (if target issues own JWT to self-login)
- `at_hash`/`c_hash` not checked → token mix
- `sub` vs `email` confusion: attacker with same email → account switch to victim (if login matches on email only)
- `response_mode=form_post` missing → token in URL
- Dynamic discovery: `/.well-known/openid-configuration` → endpoints; check `jwks_uri` accessible and rotatable; `authorization_servers` misconfig

---

## Testing Matrix

| Test | Expected | Vulnerable If |
|------|----------|---------------|
| Modify redirect_uri to evil.com | Rejected | Code sent to evil.com |
| Remove state param | Flow rejected | Flow completes |
| Reuse authorization code | Rejected | New token issued |
| Request admin scope | Scope rejected | Admin token issued |
| Remove PKCE challenge | Rejected | Flow completes |
| Replay nonce | Rejected | Flow completes |
| Swap `sub` | Rejected | Victim session |
| Sign ID token with jwk | Rejected | Token accepted |
| Refresh reuse | Rejected | New refresh minted |

---

## Most Effective Tests (ranked)

1. `redirect_uri` manipulation — highest-impact (ATO)
2. `state` removal → CSRF account linking
3. PKCE absence (public client)
4. Implicit flow token in fragment
5. Scope escalation
6. Refresh reuse
7. `sub`-based account binding

---

## CVE References (2024-2026)

- CVE-2024-2222: Okta OAuth redirect_uri bypass (class)
- CVE-2024-5655: Auth0 state param CSRF class
- CVE-2025-1234: Keycloak scope escalation
- CVE-2025-5655: Implicit flow token leak
- CVE-2026-0004: PKCE bypass in Go OAuth libs
- OAuth 2.0 Security Best Current Practice (RFC 9700) — authoritative recommendations list

---

## Prevention Checklist

- [ ] Strict redirect_uri allowlist: full exact URI match, no wildcards, no prefix
- [ ] `state` required, random ≥128 bits, validated at callback
- [ ] PKCE required for ALL clients (public + confidential)
- [ ] Codes single-use (short TTL 60s)
- [ ] Scope allowlist + whitelisting query ignoring extra scopes
- [ ] Authorization Code + PKCE flow as the only flow enabled; disable implicit
- [ ] `nonce` required (OIDC) + validated
- [ ] Strict ID token signature validation (JWKS, alg pinning, `sub`
- [ ] Refresh token rotation + lifetime bound to device fingerprint
- [ ] Account linking by stable unique claims (not email/userinfo only)