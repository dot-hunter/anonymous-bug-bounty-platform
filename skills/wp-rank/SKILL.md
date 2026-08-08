# WordPress Target Ranking — Prioritize What to Hunt

**Version:** 2026.1  
**Source:** program-intelligence MCP (ranker.py)

---

## Purpose

Turn WordPress fingerprints into a prioritized hunt list. The ranker scores
each WordPress target by exploit-relevant features so limited hunting time
goes to the highest-value surface first.

---

## Scoring Model (cap 100)

| Component | Points | Why |
|---|---|---|
| WordPress in scope (base) | +30 | CMS = large, well-known attack surface |
| Per detected plugin | +5 (cap +20) | Each plugin = CVE surface + custom code |
| Theme detected | +5 | Theme code is often less reviewed |
| REST API enabled | +10 | Custom endpoints: IDOR/access-control gold |
| Login page exposed | +10 | Auth attacks + user enumeration |
| Program offers bounties | +15 | Reward exists → worth the effort |
| Wildcard scope entry | +5 | Wider surface, more assets |

## Interpretation

| Score | Tier | Action |
|---|---|---|
| ≥ 70 | P1 | Heavy surface (plugins + REST + login). Hunt plugin CVEs, REST namespaces, auth. |
| 40–69 | P2 | Standard install. Plugin CVEs, `wp-json` enumeration, JS endpoint mining. |
| < 40 | P3 | Minimal surface. Only test if P1/P2 exhausted. |

---

## Workflow

```
# Get ranked targets for a program (runs fingerprinting + ranking)
program-intelligence rank_wordpress_targets --handle <handle> --max_targets 25
```

Manual scoring (when fingerprints exist):
```
program-intelligence fingerprint_asset --url <url> --authorized true
```

Each ranked entry includes:
- `score`, `max_score`
- `components`: per-component points with reasons
- `reasons`: human-readable summary
- `version`, `authorized`

---

## Technique Routing (by score component)

- **Plugins detected** → plugin CVE lookup; check readme "Stable tag" for
  version; hunt known-vulnerable plugin versions.
- **REST API enabled** → enumerate `rest_namespaces`; test custom endpoints
  for IDOR/access control; check `wp/v2/users` enumeration.
- **Login page exposed** → check user enumeration (read-only), no spraying.
- **Bounty program** → prioritize this target over VDP-only WordPress assets.

---

## Rules

1. Ranking is a RECOMMENDATION — authorization still governs everything.
2. Only rank targets already resolved `in_scope`.
3. Score reflects attack surface, not likelihood of a bug.
4. Use `components` breakdown when explaining priority to hunters.
