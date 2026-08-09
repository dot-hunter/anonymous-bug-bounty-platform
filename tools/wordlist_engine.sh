#!/usr/bin/env bash
# wordlist_engine.sh — target-aware wordlist generation.
# Usage:
#   wordlist_engine.sh --company "Acme Corp" --domain acme.com [--year 2026] [--count 5000]
#   wordlist_engine.sh --domain acme.com --from-recon            # seed from recon subdomains
#   wordlist_engine.sh --domain acme.com --extend base.txt       # mutate existing wordlist
#
# Generates: company-based, product-based, year-suffix, leet mutations,
# case variations, common password patterns. Output: wordlists/<domain>.txt
set -uo pipefail

COMPANY=""; DOMAIN=""; YEAR="2026"; COUNT="5000"; EXTEND=""; FROM_RECON=false

while [ $# -gt 0 ]; do
  case "$1" in
    --company) COMPANY="$2"; shift 2;;
    --domain) DOMAIN="$2"; shift 2;;
    --year) YEAR="$2"; shift 2;;
    --count) COUNT="$2"; shift 2;;
    --extend) EXTEND="$2"; shift 2;;
    --from-recon) FROM_RECON=true; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -z "$DOMAIN" ] && { echo "usage: wordlist_engine.sh --domain <d> [--company <c>] [--year 2026] [--count N]" >&2; exit 2; }

mkdir -p wordlists
OUT="wordlists/${DOMAIN}.txt"
: > "$OUT"

echo "◆ wordlist engine → $OUT"

# seed words
SEED="${COMPANY:-${DOMAIN%%.*}}"
SEED_LOWER=$(echo "$SEED" | tr 'A-Z' 'a-z')

# 1. base words
{
  echo "$SEED_LOWER"
  echo "${SEED_LOWER}corp"
  echo "${SEED_LOWER}inc"
  echo "${SEED_LOWER}labs"
  echo "${SEED_LOWER}tech"
  echo "${SEED_LOWER}dev"
  echo "${SEED_LOWER}admin"
  echo "${SEED_LOWER}support"
  echo "${SEED_LOWER}team"
  echo "${SEED_LOWER}official"
} >> "$OUT"

# 2. from recon subdomains (extract unique words)
if $FROM_RECON && [ -f "recon/$DOMAIN/subs.txt" ]; then
  cut -d. -f1 "recon/$DOMAIN/subs.txt" | tr 'A-Z' 'a-z' | sort -u >> "$OUT"
fi

# 3. extend existing
if [ -n "$EXTEND" ] && [ -f "$EXTEND" ]; then
  cat "$EXTEND" >> "$OUT"
fi

# 4. mutations: year suffix, !/@/# suffix, leet
python3 - "$OUT" "$YEAR" <<'PY'
import sys
words = set(l.strip().lower() for l in open(sys.argv[1], errors='ignore').read().splitlines() if l.strip())
year = sys.argv[2]
leet = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
new = set()
for w in words:
    new.add(w)
    new.add(f"{w}{year}")
    new.add(f"{w}@{year}")
    new.add(f"{w}!")
    new.add(f"{w}1")
    new.add(f"{w}123")
    new.add(f"{w}2025")
    new.add(f"{w}{year}!")
    new.add(w.translate(leet))
    new.add(f"{w}.{year}")
    new.add(w.capitalize())
    new.add(w.upper())
    # common patterns
    for common in ("admin", "password", "welcome", "changeme", "letmein", "qwerty"):
        new.add(f"{w}{common}")
        new.add(f"{common}{w}")
with open(sys.argv[1], 'w') as f:
    f.write("\n".join(sorted(new)) + "\n")
PY

# 5. trim to count
python3 - "$OUT" "$COUNT" <<'PY'
import sys
lines = [l for l in open(sys.argv[1], errors='ignore').read().splitlines() if l.strip()]
count = int(sys.argv[2])
with open(sys.argv[1], 'w') as f:
    f.write("\n".join(lines[:count]) + "\n")
PY

echo "[+] generated $(wc -l < "$OUT") words"
echo "    next: /osint-employees → real emails | /spray (dry-run first)"