---
description: Hunt a WordPress target using the ranked technique path: plugin CVEs, REST API enumeration, user enumeration, upload/auth checks. Authorization-gated. Usage: /wp-hunt <url or handle>
---

# /wp-hunt

Hunt a WordPress target following the ranked technique path.

## Preconditions

- Target must resolve `in_scope`:
  `program-intelligence resolve_authorization --handle <handle> --target <url>`
- Fingerprint first: `program-intelligence fingerprint_asset --url <url> --authorized true`
- Only hunt if ranked score warrants it (see /wp-targets).

## Technique Path (by rank component)

### 1. Plugin CVE surface (highest yield)
- From fingerprint `plugins` list, check each plugin's version.
- Readme `Stable tag:` reveals version: `GET /wp-content/plugins/<slug>/readme.txt`
- Cross-reference public CVE databases for plugin + version.
- If version is unknown, enumerate version strings from JS/CSS asset URLs
  (`?ver=`) and changelog files.

### 2. REST API custom endpoints
- `GET /wp-json/` → `namespaces` list.
- Enumerate each namespace's routes:
  `GET /wp-json/<namespace>/` — list routes with schemas.
- Look for custom endpoints (not core `wp/v2`): IDOR, missing auth checks,
  mass assignment on POST, excessive data exposure on GET.
- `wp/v2/users` — user enumeration (read-only GET, authorization permitting).

### 3. Login page & auth
- `wp-login.php` presence → check user enumeration (response difference on
  valid vs invalid usernames). NO password spraying.
- Check for exposed admin endpoints, `wp-admin` reachable without auth
  (misconfig).

### 4. Upload & media endpoints
- `wp-json/wp/v2/media` — auth checks on upload; file type validation.
- Test only within authorization rules (no payloads beyond benign test files).

### 5. XML-RPC
- `GET /xmlrpc.php` — if enabled (200), note for potential SSRF/pingback
  paths (authorization permitting).

## Output

```
WP HUNT: <url> (in_scope via <rule>)
──────────────────────────────────────
version: 6.5.2 | REST: wp/v2, custom-api/v1 | login: yes
plugins: contact-form-7, elementor, woocommerce
plan:
 1. CVE lookup on contact-form-7 (version from readme)
 2. Enumerate custom-api/v1 routes → IDOR/access-control
 3. wp/v2/users user enumeration
results:
 - <finding or clean per step>
```

## Rules

1. Authorization gate is MANDATORY per target — re-check if scope changed.
2. Passive fingerprinting only; no exploit payloads, no spraying.
3. Report only findings on in-scope assets, matching program's bounty scope.
4. Record outcomes: `program-intelligence save_memory --memory_type success|failure`
