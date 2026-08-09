#!/usr/bin/env bash
# recon_engine.sh — full passive+active recon pipeline.
# Usage:
#   recon_engine.sh target.com [--quick]
#   recon_engine.sh target.com --scope-check     # gate on scope_checker.py first
#
# Stages:
#   1. Scope gate (if --scope-check)
#   2. Subdomain enumeration (subfinder, assetfinder, amass, crt.sh) — dedup
#   3. DNS resolution (dnsx) — live hosts
#   4. HTTP probing (httpx) — tech fingerprint, status, title
#   5. URL harvesting (gau, waybackurls, katana) — parameter extraction
#   6. Interesting param filter (gf-style patterns: id=, url=, redirect=, file=, next=)
#   7. Output to recon/<target>/{subs.txt,live.txt,urls.txt,params.txt,tech.txt}
set -uo pipefail

TARGET="${1:-}"
MODE="${2:-}"
OUT_DIR="recon/${TARGET}"

if [ -z "$TARGET" ]; then
  echo "usage: recon_engine.sh <target.com> [--quick|--scope-check]" >&2
  exit 2
fi

# --- Stage 0: scope gate ---
if [ "$MODE" = "--scope-check" ]; then
  python3 tools/scope_checker.py --check "$TARGET" --json | grep -q '"allowed": true' \
    || { echo "[-] $TARGET OUT OF SCOPE — aborting recon"; exit 1; }
fi

mkdir -p "$OUT_DIR"
echo "[*] recon_engine.sh → $OUT_DIR (target: $TARGET)"

# --- Stage 1: subdomain enumeration ---
echo "[*] Stage 1: subdomain enumeration"
{
  if command -v subfinder >/dev/null 2>&1; then subfinder -d "$TARGET" -silent 2>/dev/null; fi
  if command -v assetfinder >/dev/null 2>&1; then assetfinder --subs-only "$TARGET" 2>/dev/null; fi
  if command -v amass >/dev/null 2>&1; then amass enum -passive -d "$TARGET" -silent 2>/dev/null; fi
  # crt.sh passive
  curl -s -m 30 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
    | python3 -c "import sys,json
try:
  for r in json.load(sys.stdin):
    for n in r.get('name_value','').split('\n'):
      print(n.strip())
except Exception: pass" 2>/dev/null
  echo "$TARGET"   # include the apex domain
} | sed 's/\*\.//' | tr 'A-Z' 'a-z' | sort -u > "$OUT_DIR/subs.txt"
echo "[+] subs.txt: $(wc -l < "$OUT_DIR/subs.txt") unique subdomains"

# --- Stage 2: DNS resolution / live hosts ---
echo "[*] Stage 2: DNS resolution"
if command -v dnsx >/dev/null 2>&1; then
  dnsx -l "$OUT_DIR/subs.txt" -silent -a -resp 2>/dev/null > "$OUT_DIR/dns.txt"
  cut -f1 -d' ' "$OUT_DIR/dns.txt" | sort -u > "$OUT_DIR/resolved.txt"
else
  cp "$OUT_DIR/subs.txt" "$OUT_DIR/resolved.txt"   # fallback: no resolution
fi
echo "[+] resolved.txt: $(wc -l < "$OUT_DIR/resolved.txt") live-resolvable"

# --- Stage 3: HTTP probing ---
echo "[*] Stage 3: HTTP probing + fingerprint"
if command -v httpx >/dev/null 2>&1; then
  httpx -l "$OUT_DIR/resolved.txt" -silent -title -tech-detect -status-code \
    -follow-redirects -timeout 8 -threads 20 2>/dev/null > "$OUT_DIR/live.txt"
else
  # curl fallback
  : > "$OUT_DIR/live.txt"
  while IFS= read -r h; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "http://$h" 2>/dev/null)
    [ "$code" != "000" ] && echo "$h [$code]" >> "$OUT_DIR/live.txt"
  done < "$OUT_DIR/resolved.txt"
fi
echo "[+] live.txt: $(wc -l < "$OUT_DIR/live.txt") live hosts"

# --- Stage 4: URL harvesting ---
echo "[*] Stage 4: URL harvesting"
{
  if command -v gau >/dev/null 2>&1; then gau --subs "$TARGET" 2>/dev/null; fi
  if command -v waybackurls >/dev/null 2>&1; then waybackurls "$TARGET" 2>/dev/null; fi
  if [ "$MODE" != "--quick" ] && command -v katana >/dev/null 2>&1; then
    katana -u "https://$TARGET" -silent -d 2 2>/dev/null
  fi
} | sort -u > "$OUT_DIR/urls.txt"
echo "[+] urls.txt: $(wc -l < "$OUT_DIR/urls.txt") historical/live URLs"

# --- Stage 5: interesting parameter filter ---
echo "[*] Stage 5: interesting param extraction"
grep -Ei "(\?|&)(id|uid|user|account|file|url|redirect|next|return|path|doc|download|img|image|page|token|key|api|callback|link|to|dest|target|ref|src|site|host|domain|q|query|search|email|name|order|admin)=" \
  "$OUT_DIR/urls.txt" 2>/dev/null | sort -u > "$OUT_DIR/params.txt" || : > "$OUT_DIR/params.txt"
echo "[+] params.txt: $(wc -l < "$OUT_DIR/params.txt") param-rich URLs"

# --- Stage 6: tech summary (quick parse of httpx output) ---
if [ -s "$OUT_DIR/live.txt" ]; then
  grep -oiE "wordpress|drupal|joomla|laravel|django|rails|next\.js|nuxt|vue|react|angular|asp\.net|spring|express|graphql|swagger|api-docs" \
    "$OUT_DIR/live.txt" 2>/dev/null | sort | uniq -c | sort -rn > "$OUT_DIR/tech.txt" || :
  echo "[+] tech.txt: $(wc -l < "$OUT_DIR/tech.txt") technology signatures"
fi

echo ""
echo "[✓] RECON COMPLETE — outputs in $OUT_DIR/"
echo "    next: /hunt $TARGET   |   /param-discover $TARGET"