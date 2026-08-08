# Program Discovery — Authorized Provider Workflow

**Version:** 2026.1  
**Source:** program-intelligence MCP providers (HackerOne, Bugcrowd, Intigriti, YesWeHack, security.txt)

---

## Purpose

Discover bug bounty programs from public provider datasets and load them into
the local intelligence database. This is **authorized discovery**: it reads
publicly published program scope data only — no credentials, no testing,
no active requests beyond fetching public dataset mirrors.

---

## Workflow

### 1. Discover programs from providers

```
program-intelligence discover_programs --connector all --max_results 50
```

Per-provider (comma-separated also works):
```
program-intelligence discover_programs --connector hackerone --max_results 20
program-intelligence discover_programs --connector bugcrowd --max_results 20
program-intelligence discover_programs --connector intigriti --max_results 20
program-intelligence discover_programs --connector yeswehack --max_results 20
```

Each provider returns programs normalized to the shared ProgramSchema with
provenance (`source: provider:<name>`).

### 2. security.txt policy discovery

For a candidate domain, check whether it publishes a disclosure policy:

```
program-intelligence discover_programs --connector securitytxt
```

Or use the SecurityTxtProvider directly with a domain list (e.g. newly found
subdomains) to check for VDP/safe-harbor policies. A security.txt with a
`Policy:` link and safe-harbor language signals a welcome target.

### 3. New-program diff

```
program-intelligence discover_new --connector all --max_results 20
```

Compares provider results against the local DB and returns only programs not
yet tracked.

---

## Normalized Output Fields

Each discovered program carries:
- `handle`, `name`, `platform`, `url`
- `reward`: `base_bounty` / `max_bounty`
- `scope`: `domains`, `wildcards`, `assets`, `subdomains`, `out_of_scope`
- `source`: `provider:<name>` (provenance)
- `confidence`, `tags`, `last_updated`

---

## Rules

1. Providers are READ-ONLY. Never send credentials or auth tokens.
2. Dataset mirrors refresh daily; local cache is 24h. Don't hammer sources.
3. Never fabricate programs — if a provider returns nothing, report that.
4. Prefer `discover_new` over full `discover` on subsequent cycles.
5. Always note provenance when presenting discovered programs.
