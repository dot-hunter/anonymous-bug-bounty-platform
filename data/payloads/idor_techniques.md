# IDOR / BOLA technique bank

## Object enumeration
- Sequential IDs: /api/users/1 → /api/users/2 → /api/users/3
- UUID from search responses (search leaks UUIDs usable on profile endpoint)
- ID in JWT claims (change userId claim if alg allows)
- UUID v1 timestamps (predictable) — decode creation time

## Reference types to test
- body param: {"user_id": 123} — URL protected, body ignored?
- nested: /api/orders/1/user/2/profile
- array/batch: POST /api/export {"ids": [1,2,3]}
- file path: /api/files?path=/users/123/private.pdf
- versioned: /v1/user/123 → /v2/user/123
- websocket: ws://host/socket?user=123
- webhook: callback URLs with embedded object ids

## Method-based
- GET protected → DELETE/PUT unprotected
- GET /api/user/123 → PATCH /api/user/123 (write IDOR)
- OPTIONS reveals allowed methods

## Response-side
- Error message differences: 403 vs 404 (existence oracle)
- Timing: authorized vs unauthorized response time
- Count leaks in list endpoints
