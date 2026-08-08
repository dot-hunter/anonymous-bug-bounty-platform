# Scope Resolution — Authorization Before Action

**Version:** 2026.1  
**Source:** program-intelligence MCP (normalizer.py + resolver.py)

---

## Purpose

Determine whether a target (hostname or URL) is **authorized** by a program's
scope before any fingerprinting or testing. This is the mandatory gate: never
touch a target that has not resolved to `in_scope`.

---

## Workflow

### 1. Normalize the program's scope

Heterogeneous scope shapes (dict-scope, flat lists, dataset rows, program
pages) collapse into one canonical form:

```
program-intelligence normalize_scope --scope '{"domains": ["acme.com"], "wildcards": ["*.api.acme.com"]}'
```

Canonical form:
```
{
  "domains":      ["acme.com"],
  "wildcards":    ["*.api.acme.com"],
  "assets":       ["https://acme.com/portal", "app://mobile"],
  "subdomains":   ["old.acme.com"],
  "out_of_scope": ["acme.com/admin", "dev.api.acme.com"]
}
```

### 2. Resolve authorization for each target

```
program-intelligence resolve_authorization --handle <handle> --target www.acme.com
program-intelligence resolve_authorization --handle <handle> --target https://acme.com/admin
```

Verdicts:
- `in_scope` — authorized. Proceed.
- `out_of_scope` — explicitly excluded. STOP.
- `unknown` — not covered by scope. STOP (do not assume).

Each verdict includes the matching `rule` (which scope entry matched) and a
human-readable `reason`.

### 3. Record the authorization gate

For every target you intend to probe, record the verdict in hunt memory:
```
program-intelligence save_memory --memory_type recon --key "<target>" --data '{"verdict": "in_scope", "rule": "*.acme.com", "ts": "<iso>"}'
```

---

## Resolution Priority (what the resolver checks)

1. Exact out-of-scope entry match → `out_of_scope`
2. Out-of-scope wildcard parent match → `out_of_scope`
3. Exact in-scope domain match → `in_scope`
4. In-scope wildcard parent match → `in_scope`
5. URL prefix match against in-scope URL asset → `in_scope`
6. Subdomain of an in-scope domain → `in_scope`
7. Otherwise → `unknown`

---

## Rules

1. Authorization resolution is PURE — no network requests, no testing.
2. `unknown` is NOT a green light. When in doubt, don't probe.
3. Out-of-scope beats in-scope: an OOS entry always wins over a parent domain.
4. Subdomains of in-scope domains are in scope by default (unless excluded).
5. Log every authorization decision for auditability.
