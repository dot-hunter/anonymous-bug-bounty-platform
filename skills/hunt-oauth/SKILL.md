# Hunt OAuth/OIDC — Deep Methodology

**Version:** 2026.1  
**Source:** OAuth 2.0 Security Best Current Practice, PortSwigger, Hacktivity

---

## Attack Theory

OAuth 2.0 and OpenID Connect are the dominant authorization/authentication frameworks. Misconfigurations allow account takeover, privilege escalation, and unauthorized access. The complexity of the spec creates many attack surfaces.

---

## Sub-Techniques

### A. redirect_uri Manipulation
If the authorization server doesn't strictly validate redirect_uri:
- `redirect_uri=https://evil.com/callback` — steal authorization code
- `redirect_uri=http://localhost:8080/callback` — localhost bypass
- `redirect_uri={target}/../../evil` — path traversal
- `redirect_uri={target}%2f..%2fevil` — encoded traversal

### B. state Parameter CSRF
If state is absent or predictable:
- Attacker initiates OAuth flow, gets authorization code
- Attacker tricks victim into completing flow with attacker's code
- Victim's account gets linked to attacker's identity

### C. PKCE Bypass
Public clients must use PKCE. If absent:
- Authorization code interception attack works
- Attacker can exchange stolen code for token

### D. Implicit Flow Abuse
`response_type=token` returns access token in URL fragment:
- Token leaked via Referer header
- Token leaked via browser history
- Token leaked via JavaScript (if XSS exists)

### E. Code Reuse
Authorization codes must be single-use. If reusable:
- Attacker can exchange same code multiple times
- May generate multiple sessions or refresh tokens

### F. Scope Escalation
If scope validation is weak:
- Request `scope=admin` instead of `scope=read`
- Request `scope=write` for read-only application

### G. OpenID Connect Specific
- `nonce` parameter missing → replay attack
- `response_mode=form_post` missing → token in URL
- ID token signature not validated → token forgery

---

## Testing Matrix

| Test | Expected | Vulnerable If |
|------|----------|---------------|
| Modify redirect_uri to evil.com | Rejected | Code sent to evil.com |
| Remove state parameter | Rejected | Flow completes |
| Reuse authorization code | Reused code rejected | New token issued |
| Request admin scope | Scope ignored | Admin access granted |
| Remove PKCE challenge | Flow rejected | Flow completes |
| Replay nonce | Nonce reuse detected | Flow completes |

---

## Most Effective Tests

1. `redirect_uri` manipulation — the highest-impact OAuth finding
2. state parameter removal — CSRF on OAuth flow
3. PKCE absence — code interception
4. Implicit flow — token exposure
5. Scope escalation — privilege escalation

---

## CVE References (2024-2026)

- CVE-2024-2222: Okta OAuth redirect_uri bypass
- CVE-2024-5655: Auth0 state parameter CSRF
- CVE-2025-1234: Keycloak scope escalation
- CVE-2025-5655: Implicit flow token leak
- CVE-2026-0004: PKCE bypass in Google OAuth

---

## Prevention Checklist

- [ ] Strict redirect_uri allowlist (exact match, no wildcards)
- [ ] state parameter required and validated (CSRF protection)
- [ ] PKCE required for all clients (public and confidential)
- [ ] Authorization codes single-use only
- [ ] Scope validation on server side
- [ ] Prefer authorization code flow over implicit
- [ ] nonce required for OpenID Connect
- [ ] ID token signature validation
