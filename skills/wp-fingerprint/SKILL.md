# WordPress Fingerprinting — Passive Asset Enumeration

**Version:** 2026.1  
**Source:** program-intelligence MCP (wordpress.py)

---

## Purpose

Identify WordPress installations and enumerate version, REST API, login page,
themes, and plugins on **authorized in-scope targets only**. Fingerprinting is
passive: it reads publicly served metadata files (`readme.txt`, `style.css`),
the generator meta tag, `wp-json/` root, and the login page. No payloads, no
exploitation, no auth bypass attempts.

---

## Authorization Gate (MANDATORY)

Before fingerprinting any target:

```
program-intelligence resolve_authorization --handle <handle> --target <target>
```

Only proceed when verdict == `in_scope`. Pass `--authorized true` to
`fingerprint_asset` only for in-scope targets.

---

## Workflow

### 1. Fingerprint a single authorized asset

```
program-intelligence fingerprint_asset --url https://www.acme.com --authorized true
```

### 2. Find WordPress across a whole program

```
program-intelligence find_wordpress_assets --handle <handle> --max_targets 25
```

Probes in-scope domains, wildcard apexes, and previously discovered
subdomains; returns only assets that are WordPress.

### 3. Rank the WordPress targets

```
program-intelligence rank_wordpress_targets --handle <handle>
```

---

## What the Fingerprinter Checks

| Probe | Purpose |
|---|---|
| `GET /` | generator meta tag, `wp-content/themes|plugins/` references |
| `GET /wp-json/` | REST API root: `namespaces`, site name/description |
| `GET /wp-login.php` | login page presence (200/302) |
| `GET /feed/` | fallback generator detection |
| `GET /wp-content/plugins/<slug>/readme.txt` | plugin presence (metadata only) |
| `GET /wp-content/themes/<slug>/style.css` | theme presence (metadata only) |

Output fields: `is_wordpress`, `version`, `rest_api`, `rest_namespaces`,
`login_page`, `themes`, `plugins`, `detected_paths`, `errors`.

---

## Post-Fingerprint Analysis

For each detected plugin/theme:
1. Note the version if visible (readme "Stable tag:" or generator meta).
2. Cross-reference known CVEs for that plugin/version (public databases).
3. Enumerate REST namespaces for custom endpoints (authorization permitting).
4. Check `wp-json/wp/v2/users` for user enumeration (read-only GET).

---

## Rules

1. NEVER fingerprint without an `in_scope` verdict.
2. Passive only — metadata files and headers. No exploit payloads.
3. If a probe 404s, record it and move on. Don't brute-force paths.
4. Cap plugin/theme probes (10 plugins / 5 themes) to stay light.
5. Log all fingerprints with the authorization rule that allowed them.
