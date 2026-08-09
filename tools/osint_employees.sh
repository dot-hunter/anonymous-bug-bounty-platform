#!/usr/bin/env bash
# osint_employees.sh — employee enumeration + email format discovery (PASSIVE only).
# Usage:
#   osint_employees.sh acme.com "Acme Corp"
#
# Passive sources only (no login, no scraping aggressiveness):
#   1. GitHub org members (if org found)
#   2. crt.sh / search engines for @domain email strings
#   3. company domain name patterns from whois/website
# Outputs: osint/<domain>/employees.txt + emails.txt (candidate formats)
set -uo pipefail

DOMAIN="${1:-}"
COMPANY="${2:-}"
OUT="osint/${DOMAIN}"
[ -z "$DOMAIN" ] && { echo "usage: osint_employees.sh <domain> [company]" >&2; exit 2; }
mkdir -p "$OUT"

echo "◆ employee OSINT (passive) → $DOMAIN"

# 1. email strings from public index sources via crt.sh + google dorks (search engine fallback)
echo "[*] 1. harvesting public @${DOMAIN} emails"
{
  curl -s -m 20 "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null \
    | grep -oE "[a-zA-Z0-9._%+-]+@${DOMAIN//./\\.}" | sort -u
} > "$OUT/emails_raw.txt" 2>/dev/null
[ -s "$OUT/emails_raw.txt" ] || echo "[*] no public emails found via crt.sh"

# 2. GitHub org scan (if a likely org handle exists)
if [ -n "$COMPANY" ]; then
  ORG=$(echo "$COMPANY" | tr 'A-Z' 'a-z' | tr ' ' '-')
  echo "[*] 2. GitHub org lookup: $ORG"
  curl -s -m 15 "https://api.github.com/orgs/$ORG/members?per_page=100" 2>/dev/null \
    | grep '"login"' | sed 's/.*"login": "//;s/",*//' > "$OUT/github_members.txt" 2>/dev/null
  [ -s "$OUT/github_members.txt" ] && echo "[+] $(wc -l < "$OUT/github_members.txt") GitHub members"
fi

# 3. company name from website title (fallback if no COMPANY given)
if [ -z "$COMPANY" ]; then
  echo "[*] 3. fetching company name from site"
  COMPANY=$(curl -s -m 15 "https://$DOMAIN" 2>/dev/null | grep -oiE "<title>[^<]+" | head -1 | sed 's/<title>//')
  echo "    company: ${COMPANY:-unknown}"
fi

# 4. email format inference from any found emails
python3 - "$OUT" "$DOMAIN" <<'PY'
import sys, re
from pathlib import Path
out = Path(sys.argv[1]); dom = sys.argv[2]
emails = []
for f in ("emails_raw.txt", "github_members.txt"):
    p = out / f
    if p.exists():
        emails += [l.strip().lower() for l in p.read_text(errors='ignore').splitlines() if l.strip()]
# infer format from observed emails
fmts = set()
for e in emails:
    local = e.split("@")[0]
    if "." in local:
        fmts.add("first.last")
    elif "_" in local:
        fmts.add("first_last")
    elif len(local) <= 8:
        fmts.add("first")
    else:
        fmts.add("firstlast")
with open(out / "format.txt", "w") as f:
    f.write(f"observed formats: {', '.join(sorted(fmts)) or 'none (use first.last default)'}\n")
    for fmt in sorted(fmts):
        f.write(f"candidate: {fmt}@{dom}\n")
# build candidate email file from github usernames
gh = (out / "github_members.txt")
if gh.exists():
    cands = []
    for u in gh.read_text(errors='ignore').splitlines():
        u = u.strip().lower()
        if u:
            cands.append(f"{u}@{dom}")
    (out / "emails_candidates.txt").write_text("\n".join(sorted(set(cands))) + "\n")
print(f"formats -> {out}/format.txt")
PY

echo ""
echo "[✓] OSINT complete:"
echo "    raw emails:    $OUT/emails_raw.txt"
echo "    gh members:    $OUT/github_members.txt"
echo "    candidates:    $OUT/emails_candidates.txt"
echo "    format hints:  $OUT/format.txt"
echo "    next: /wordlist-gen → /breach-check (local only) → /spray --dry-run"