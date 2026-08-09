# Hunt IDOR/BOLA — Deep Methodology

**Version:** 2026.2  
**Lines:** ~650  
**Source:** 1,000+ public HackerOne reports, OWASP API Security Top 10 2023, PortSwigger

---

## Attack Theory

IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization) are the same vulnerability class. The user is authenticated and authorized to call the endpoint, but the API fails to verify that the specific object being requested belongs to that user. OWASP API1:2023. Horizontal privilege escalation: same role, wrong object.

### The Core Problem
Authentication ≠ Authorization. The server verifies "who are you" but not "are you allowed to access THIS resource." A successful attack produces a normal 200 OK response with valid data, making it invisible to traditional scanners — only comparison of two sessions reveals it.

### Business Impact
- Unauthorized data access (PII, financial, medical)
- Data modification or deletion
- Full account takeover (via password reset IDOR, etc.)
- GDPR/regulatory multiplier on EU/health targets

### Kill signals (skip)
- No authenticated object-identifying endpoints (all reads are public; no user-scoped data)
- Every endpoint derives object from session token server-side (no client-supplied object id anywhere)

---

## Attack Surface Discovery (authenticated)

1. `session_recon`: load authenticated session, probe dashboard pages → extract `/api/*` patterns
2. `linkfinder_extract` on each JS bundle → endpoints + object ids in code
3. `auth_bola_primer` on session file → plan of authenticated endpoints
4. Focus on: `/users/{id}`, `/orders/{id}`, `/tickets/{id}`, `/messages/{thread}`, `/documents/{id}`, `/export/{id}`, `/invoices/{id}`, `/webhooks/{id}`, `/projects/{id}`, `/orgs/{orgid}/…`
5. Record two accounts (A and B) and one shared admin session — compare authorizations across accounts.

## Sub-Techniques

### A. Direct ID Manipulation (Classic)
Sequential integers in URL path or query params.
- `GET /api/users/123` → `GET /api/users/124`
- `GET /orders?id=500` → `GET /orders?id=501`
- Test: increment/decrement by 1, `0`, `-1`, `999999`, `2147483647`
- Also: string ids like `/orders/A123` → `/orders/A124`

### B. UUID "Defense" Bypass
UUIDs make enumeration harder but don't provide authorization — they are NOT random-enough to be security.
UUIDs leak through: API responses (user lists, search results), email webhook APKs (password reset, invitation), HTML source (data-attributes, JS vars), WebSocket messages, GraphQL introspection, browser local storage.
Then reuse them against object endpoints.

### C. Body Parameter IDOR
Developers protect URL params but forget JSON body.
- `POST /api/transfer {"user_id": 1}` → `{"user_id": 2}`
- `{"id": 100}` → `{"id": 101}` in POST/PUT bodies
Also query-vs-body double params: send id both in query and body — server may use one for authz, other for execution.

### D. HTTP Method Switching
Authz may exist on GET but not on PUT/DELETE/POST.
Test matrix: same object ID with every method, including `OPTIONS`, `PATCH`.
- `GET /api/users/other_id` → 403
- `PATCH /api/users/other_id` → 200 (vuln)

### E. Mass Assignment / Parameter Pollution (API3)
Try adding privileged fields: `role`, `isAdmin`, `verified`, `tenant`, `account_type`, `organization_id`, `billing_plan`, `owner`.
Also `_method=DELETE` override, `X-HTTP-Method-Override`.

### F. Batch/Bulk Endpoints (API6/API1 combo)
- `{"ids": [1,2,3]}` → `{"ids": [9999...]}`  — exfiltrate N objects in one request
- If bulk not allowed: send many single requests (HTTP/2 multiplex can bypass rate limit)

### G. Indirect Reference Leak
- Search API returns object IDs → feed them into profile/export endpoints
- Email addresses as user keys (`/api/user?email=victim@x.com`)
- Phone number as key
- Username as key

### H. GraphQL IDOR
- `query { user(id: "2") { email } }`
- Aliasing: multiple `user(id:..)` in one query (introspection disabled → enumerate by guessing ids)
- Batching 100 queries/request may trip rate-limit-less IDOR en masse

### I. API Versioning
- `/api/v2/users/0` → 403; `/api/v1/users/0` → 200
- `/api/beta/`, `/api/labs/`, `/internal/`, `/debug/` → often no auth
- Headers: `X-Api-Version: 1`, `v: 1` query

### J. State-Changing IDOR (Most Dangerous)
- Cancel others' orders: `POST /api/orders/{other_id}/cancel`
- Modify others' settings: `PUT /api/users/{other_id}/settings`
- Reset others' password via `POST /api/reset {user_id: other}` — **ATO escalation**
- Delete others' data: `DELETE /api/documents/{other_id}`

## Testing Matrix (two-account baseline)

For every endpoint accepting a resource identifier:

| Test | Request | Expected | IDOR If |
|------|---------|----------|---------|
| Own resource | User A → A's object | 200 OK | — |
| Other's resource | User A → B's object | 403/404 | 200 OK |
| Non-existent | User A → fake ID | 404 | — |
| No auth | No token | 401 | 200 OK |
| Different role | Low-priv → admin resource | 403 | 200 OK |
| Method switch | B's object via PUT/DELETE | 403 | 200 OK |
| Adjacent IDs | B's object id ±1 | 403 | 200 OK |

**Detection:** Response 200 + data presence (email/phone/address in body) = confirmed. If 200 with empty/redacted body = informational.

## Platform-Specific Patterns

### WordPress
- `?attachment_id=` in admin; REST: `/wp-json/wp/v2/users/{id}`, `/wp-json/wp/v2/media/{id}`, `/wp-json/wp/v2/comments/{id}`; AJAX actions with nonce; `?post=` in `admin-ajax.php` with different `action` names.
### E-commerce
- Order ID `/orders/{id}`, cart item manipulation, coupon assignment to other user, refund `{refund_id}` of other users.
### SaaS/Multi-tenant
- Tenant ID in subdomain/header `X-tenant-ID`; `?org=otherId`; endpoint without tenant check; switching tenant then ID.
### Healthcare/Finance
- Patient/record ID, PDF report access by ID, statement download, record modification.
### Mobile APIs
- Device tokens: `GET /devices?userID=x`; push token for other user; account-linking by user_id.

## Detection Patterns (Semgrep/grep)

```python
# Python Flask — IDOR sink
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # no ownership check
    return jsonify(user.to_dict())
```
```js
// Express — IDOR sink
app.get('/api/orders/:id', (req,res) => {
  const order = Order.findById(req.params.id); // no ownership check
  res.json(order);
});
```
```java
// Spring — IDOR sink
@GetMapping("/api/documents/{id}")
public Document get(@PathVariable Long id) { return repo.findById(id); }
```
Semgrep rule for the confirm-free pattern:
```yaml
rules:
  - id: idor-direct-object
    languages: [python, javascript, java]
    message: direct object fetch without owner filter
    severity: WARNING
    patterns:
      - pattern: $MODEL.query.get(id)
      - pattern: findBy$FIELD($id)
      - metavariable-regex: { metavariable: $id, regex: "(user|order|doc|ticket|account|invoice)" }
```

## Most Effective Payloads

1. Sequential increment `id=1→2`
2. UUID from search/export leak → reuse
3. Method switch GET→DELETE/PATCH
4. Body param `{"user_id": 2}` (URL param protected)
5. Batch `{"ids": [1,2,3]}` with other users IDs
6. Email/phone/username as object key

## Reporting Checklist (7-Question Gate)

- Reproduce with exact request/response pair (victim session + attacker session)
- Show victim data (email, order, doc name) in response — redact PVIII
- State impact: read (PII) vs write/delete (integrity) — write/delete + ATO = high/critical
- Confirm in-scope object types (program scope often specifically lists objects/IDs)
- CVSS: H1 → 3.1; others 4.0. L:P changes
- No hedging language. No "could".

## Prevention Checklist

- [ ] Every endpoint accepting object id enforces ownership server-side
- [ ] User id from session token, never from body/url
- [ ] Bulk endpoints validate ownership for ALL ids
- [ ] File download ids via DB lookup, not user-supplied paths
- [ ] GraphQL resolvers have per-field authorization
- [ ] Legacy API versions same authz as current
- [ ] Export/report endpoints enforce scoping
- [ ] UUIDs used in ADDITION to authorization — never replace
- [ ] 404 (not 403) for unauthorized to prevent enumeration
- [ ] Method routing consistent (all verbs, all versions)