---
description: Discover bug bounty programs from authorized public providers (HackerOne, Bugcrowd, Intigriti, YesWeHack, security.txt). Normalizes to one schema with provenance. Usage: /program-discover [provider] [max]
---

# /program-discover

Discover bug bounty programs from authorized public provider datasets.

## What It Does

- Runs provider-based discovery (HackerOne, Bugcrowd, Intigriti, YesWeHack, security.txt)
- Returns programs normalized to one schema with full provenance
- Uses 24h local caches — passive, no credentials, no testing
- Diffs against the local DB so you only see what's new

## Usage

```
/program-discover                     # all providers, 50 results
/program-discover hackerone           # single provider
/program-discover hackerone,bugcrowd  # multiple providers
/program-discover all 100             # raise the result cap
```

## Flow

1. **Discover**: `program-intelligence discover_programs --connector <all|name>`
2. **Diff**: `program-intelligence discover_new --connector all`
3. **Provenance**: `program-intelligence get_target_provenance --handle <handle>`
4. **Next**: hand promising handles to `/scope-aggregate` and `/recon`

## What You Get Back

Per program: `handle`, `name`, `platform`, `url`, `reward` (base/max),
`scope` (domains/wildcards/assets/out_of_scope), `source` (provider name),
`confidence`, `last_updated`.

## Rules

1. READ-ONLY — providers never send credentials or test anything.
2. Don't hammer sources; 24h cache means re-runs are cheap and local.
3. If a provider returns nothing, say so — never fabricate programs.
4. On later cycles prefer `discover_new` over full `discover`.
