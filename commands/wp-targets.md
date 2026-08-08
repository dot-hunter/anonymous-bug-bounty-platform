---
description: Find and rank WordPress targets inside a program's authorized scope. Runs scope normalization, authorization resolution, passive WordPress fingerprinting, and 0-100 ranking. Usage: /wp-targets <handle>
---

# /wp-targets

Find WordPress assets in a program's scope and rank them by hunt value.

## Why WordPress

WordPress sites are consistently high-yield: plugins introduce CVE surface,
`wp-json` REST endpoints hide IDOR/access-control bugs, and login pages open
user-enumeration paths. The ranker turns a CMS fingerprint into a prioritized
hunt list (score 0–100).

## Usage

```
/wp-targets <handle>
```

## Flow

1. **Load program**: `program-intelligence get_program --handle <handle>`
2. **Normalize scope**: `program-intelligence normalize_scope --program <program>`
3. **Find WordPress**: `program-intelligence find_wordpress_assets --handle <handle>`
4. **Rank**: `program-intelligence rank_wordpress_targets --handle <handle>`

The command only probes in-scope domains, wildcard apexes, and known
subdomains. Authorization is enforced before every fingerprint.

## Scoring Quick Reference

| Component | Points |
|---|---|
| Base WordPress | +30 |
| Plugins | +5 each (cap +20) |
| Theme | +5 |
| REST API | +10 |
| Login page | +10 |
| Bounty program | +15 |
| Wildcard scope | +5 |
| **Cap** | **100** |

## Output

```
WORDPRESS TARGETS: <handle>
──────────────────────────────
1. https://blog.acme.com      (score 90 / 100) — P1
   version: 6.5.2 | REST: yes | login: yes
   plugins: contact-form-7, elementor, woocommerce
   → hunt: plugin CVEs, wp-json custom endpoints
```

## Rules

1. Authorization FIRST — only in_scope targets are fingerprinted.
2. Fingerprinting is passive (readme.txt / style.css / generator meta).
3. If a target scores < 40 it's P3 — skip unless P1/P2 are exhausted.
