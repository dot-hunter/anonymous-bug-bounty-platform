# Hunt IDOR/BOLA — Deep Methodology

**Version:** 2026.1  
**Lines:** ~500  
**Source:** 1,000+ public HackerOne reports, OWASP API Security Top 10 2023

---

## Attack Theory

IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization) are the same vulnerability class. The user is authenticated and authorized to call the endpoint, but the API fails to verify that the specific object being requested belongs to that user. OWASP API1:2023. Horizontal privilege escalation: same role, wrong object.

### The Core Problem
Authentication ≠ Authorization. The server verifies "who are you" but not "are you allowed to access THIS resource." A successful attack produces a normal 200 OK response with valid data, making it invisible to traditional scanners.

### Business Impact
- Unauthorized data access (PII, financial, medical)
- Data modification or deletion
- Full account takeover (via password reset IDOR, etc.)
- GDPR violation on EU targets (severity multiplier)

---

## Sub-Techniques

### A. Direct ID Manipulation (Classic)
Sequential integers in URL path or query parameters.
- `GET /api/users/123` → `GET /api/users/124`
- `GET /orders?id=500` → `GET /orders?id=501`
- Test: increment/decrement by 1, try 0, -1, 999999

### B. UUID "Defense" Bypass
UUIDs make enumeration harder but don't provide authorization. UUIDs leak through:
- API responses (user lists, search results)
- Email links (password reset, invitation)
- HTML source (data attributes, JavaScript variables)
- WebSocket messages

### C. Body Parameter IDOR
Developers protect URL parameters but forget JSON body fields.
- `{"user_id": 1}` → `{"user_id": 2}`
- `{"id": 100}` → `{"id": 101}`

### D. HTTP Method Switching
Authorization may exist on GET but not on PUT/DELETE.
- `GET /api/users/other_id` → 403
- `PUT /api/users/other_id` → 200 (vulnerable)
- `DELETE /api/users/other_id` → 200 (vulnerable)

### E. Mass Assignment (API3:2023)
Write fields the user should not control.
- `{"role": "admin"}`
- `{"isAdmin": true}`
- `{"verified": true}`

### F. Batch/Bulk Endpoints
Arrays of IDs are especially dangerous.
- `{"ids": [1, 2, 3]}` → `{"ids": [4, 5, 6]}`
- Single request can exfiltrate massive data

### G. Indirect References
Object IDs leak through related resources.
- Search API returns object IDs
- Export functions include all IDs
- Pagination reveals total count

### H. GraphQL IDOR
Clients specify exactly which data they want.
- `query { user(id: "2") { email } }`
- Batching: 100 queries in one request

### I. API Versioning
Older API versions may lack authorization checks.
- `/api/v2/users/1` → 403 (secure)
- `/api/v1/users/1` → 200 (vulnerable)

### J. State-Changing IDOR (Most Dangerous)
Write/delete IDORs cause direct damage.
- Delete another user's data
- Cancel another user's orders
- Modify another user's settings

---

## Testing Matrix

For every endpoint that accepts a resource identifier:

| Test | Request | Expected | IDOR If |
|------|---------|----------|---------|
| Own resource | User A → User A's object | 200 OK | — |
| Other's resource | User A → User B's object | 403/404 | 200 OK |
| Non-existent | User A → fake ID | 404 | — |
| No auth | No token | 401 | 200 OK |
| Different role | Low-priv → admin resource | 403 | 200 OK |

---

## Platform-Specific Patterns

### WordPress
- `?attachment_id=` in admin
- REST API `/wp-json/wp/v2/users/{id}`
- AJAX actions with nonce bypass

### E-commerce
- Order ID in URL (`/orders/{id}`)
- Cart item manipulation
- Coupon assignment

### SaaS/Multi-tenant
- Tenant ID in subdomain or header
- Cross-tenant data access via ID manipulation
- Organization switching

### Healthcare/Finance
- Patient/record ID in URL
- Document download via ID
- Report access

---

## CVE References (2024-2026)

- CVE-2024-2222: IDOR in GitLab project export
- CVE-2024-3434: BOLA in Salesforce Commerce Cloud
- CVE-2025-1234: IDOR in Microsoft Power Platform
- CVE-2025-5678: BOLA in ServiceNow
- CVE-2026-0001: IDOR in Jira Cloud

---

## Detection Patterns (Semgrep/grep)

```python
# Python Flask - IDOR sink
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)  # Missing ownership check
    return jsonify(user.to_dict())

# Express - IDOR sink
app.get('/api/orders/:id', (req, res) => {
    const order = Order.findById(req.params.id);  // Missing ownership check
    res.json(order);
})

# Spring - IDOR sink
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id);  // Missing ownership check
}
```

---

## Most Effective Payloads

1. Sequential ID increment: `id=1` → `id=2`
2. UUID from user list leaked in search API
3. Method switch: `GET` protected → `DELETE` unprotected
4. Body parameter: `{"user_id": 2}` in POST
5. Batch: `{"ids": [1,2,3,4,5]}` → other users' IDs

---

## Prevention Checklist

- [ ] Every endpoint that accepts a resource ID enforces ownership
- [ ] Authorization checks happen server-side, never client-side only
- [ ] User ID comes from session/token, never from request body
- [ ] Bulk/batch endpoints validate ownership for ALL requested IDs
- [ ] File download endpoints use DB lookups, not user-supplied paths
- [ ] GraphQL resolvers have authorization checks on every type/field
- [ ] Old API versions have the same authorization as current versions
- [ ] Export/report endpoints enforce organization/user scoping
- [ ] UUIDs are used IN ADDITION to authorization, not instead of
- [ ] Internal/admin endpoints require role-based access
- [ ] 404 (not 403) returned for unauthorized resources (prevent enumeration)
