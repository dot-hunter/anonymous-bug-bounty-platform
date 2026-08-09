#!/usr/bin/env bash
# param_discovery.sh — parameter discovery on a target.
# Usage: param_discovery.sh target.com [wordlist.txt]
#   - extracts params from historical URLs (gau/waybackurls)
#   - fuzzes common param names with arjun (if installed) or builtin list
#   - output: recon/<target>/params.txt (param-rich URLs) + fresh candidates
set -uo pipefail

TARGET="${1:-}"
WL="${2:-tools/wordlists/params_top.txt}"
OUT="recon/$TARGET"

[ -z "$TARGET" ] && { echo "usage: param_discovery.sh <target.com> [wordlist]" >&2; exit 2; }
mkdir -p "$OUT"

# Builtin top-param list (no external wordlist needed)
if [ ! -f "$WL" ]; then
  WL="$OUT/builtin_params.txt"
  cat > "$WL" <<'EOF'
id
uid
user_id
account_id
file
filename
path
url
redirect
next
return
return_to
dest
target
callback
page
page_id
post_id
order
order_id
invoice
invoice_id
report
download
img
image
file_url
doc
token
access_token
api_key
key
email
username
role
admin
debug
test
preview
EOF
fi

echo "◆ param discovery → $TARGET"
echo "[*] 1. historical params (gau/waybackurls)"
{
  command -v gau >/dev/null 2>&1 && gau --subs "$TARGET" 2>/dev/null
  command -v waybackurls >/dev/null 2>&1 && waybackurls "$TARGET" 2>/dev/null
} | sort -u > "$OUT/urls_all.txt" 2>/dev/null

# extract param names from historical urls
python3 - "$OUT/urls_all.txt" "$OUT/hist_params.txt" <<'PY'
import re, sys
from collections import Counter
try:
    urls = open(sys.argv[1], errors='ignore').read().splitlines()
except OSError:
    sys.exit(0)
c = Counter()
for u in urls:
    if '?' in u:
        q = u.split('?',1)[1].split('#',1)[0]
        for kv in q.split('&'):
            k = kv.split('=',1)[0]
            if k: c[k.lower()] += 1
with open(sys.argv[2], 'w') as f:
    for k, n in c.most_common():
        f.write(f"{k} ({n})\n")
PY
echo "[+] historical params: $(wc -l < "$OUT/hist_params.txt" 2>/dev/null || echo 0)"

echo "[*] 2. brute force fresh params on live endpoints"
LIVE_URLS="$OUT/live.txt"
[ -s "$LIVE_URLS" ] || LIVE_URLS="$OUT/urls_all.txt"

CANDIDATES=0
if command -v arjun >/dev/null 2>&1; then
  for u in $(head -5 "$LIVE_URLS" 2>/dev/null); do
    arjun -u "$u" -w "$WL" -q 2>/dev/null && CANDIDATES=$((CANDIDATES+1))
  done
else
  # builtin: check each param on first live URL, look for reflected/different status
  BASE_URL=$(head -1 "$LIVE_URLS" 2>/dev/null | grep -E "^https?" || echo "https://$TARGET")
  BASE_URL="${BASE_URL%%\?*}"
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    probe="$BASE_URL?${p}=zzzparamtest"
    code=$(curl -s -o /tmp/param_probe.html -w "%{http_code}" -m 8 "$probe" 2>/dev/null)
    if grep -q "zzzparamtest" /tmp/param_probe.html 2>/dev/null; then
      echo "  [reflected] $p"
      echo "$probe" >> "$OUT/reflected_params.txt"
      CANDIDATES=$((CANDIDATES+1))
    elif [ "$code" = "500" ] || [ "$code" = "400" ]; then
      echo "  [error $code] $p"
      echo "$probe" >> "$OUT/reflected_params.txt"
      CANDIDATES=$((CANDIDATES+1))
    fi
  done < "$WL"
fi

echo ""
echo "[✓] param discovery complete"
echo "    historical: $OUT/hist_params.txt"
echo "    reflected/error candidates: ${CANDIDATES:-0} → $OUT/reflected_params.txt"
echo "    next: test with /hunt or waf_encoder.py variants"