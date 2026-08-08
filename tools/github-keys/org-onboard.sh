#!/usr/bin/env bash
# org-onboard.sh — auto-join SSH public keys for an entire GitHub org.
#
# No per-user key sharing: for every public member of the org it fetches their
# GitHub-published SSH keys (https://github.com/<user>.keys — no auth, no rate
# limit) and appends them to the server's authorized_keys file.
#
# Usage:
#   org-onboard.sh <org>                        # print draft (no file changes)
#   org-onboard.sh <org> --install              # append to ~/.ssh/authorized_keys
#   GITHUB_KEYS_FILE=/etc/ssh/authorized_keys org-onboard.sh <org> --install
#   GITHUB_TOKEN=ghp_xxx org-onboard.sh <org>   # private orgs (member list needs auth)
set -euo pipefail

ORG="${1:-}"
ACTION="${2:-draft}"
KEYS_FILE="${GITHUB_KEYS_FILE:-$HOME/.ssh/authorized_keys}"
TOKEN="${GITHUB_TOKEN:-}"
API="https://api.github.com"

if [[ -z "$ORG" ]]; then
  echo "usage: $0 <org> [--install]" >&2
  exit 2
fi

auth_header=(-H "Accept: application/vnd.github+json")
[[ -n "$TOKEN" ]] && auth_header+=(-H "Authorization: Bearer $TOKEN")

# --- list public org members -------------------------------------------------
echo "[*] fetching public members of $ORG ..." >&2
members=""
page=1
while :; do
  resp="$(curl -fsSL --max-time 20 "${auth_header[@]}" \
    "$API/orgs/$ORG/public_members?per_page=100&page=$page" 2>/dev/null || true)"
  batch="$(echo "$resp" | python3 -c 'import json,sys
try:
    data = json.load(sys.stdin)
    print("\n".join(m["login"] for m in data if isinstance(data, list)))
except Exception:
    pass' 2>/dev/null || true)"
  members="$members$batch"$'\n'
  [[ -z "$batch" ]] && break
  count="$(echo "$batch" | grep -c . || true)"
  if (( count < 100 )); then break; fi
  page=$((page + 1))
done

member_list="$(echo "$members" | grep -v '^$' || true)"
n_members="$(echo "$member_list" | grep -c . || true)"
echo "[*] found $n_members public members" >&2
[[ -z "$member_list" ]] && { echo "error: org '$ORG' unknown or has no public members" >&2; exit 1; }

# Optional cap for CI/testing or huge orgs: ORG_ONBOARD_MAX_USERS=20
if [[ -n "${ORG_ONBOARD_MAX_USERS:-}" ]]; then
  member_list="$(echo "$member_list" | head -n "$ORG_ONBOARD_MAX_USERS")"
  echo "[*] capped to $ORG_ONBOARD_MAX_USERS members (ORG_ONBOARD_MAX_USERS)" >&2
fi

# --- fetch keys for every member --------------------------------------------
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

found=0
skipped=0
while IFS= read -r user; do
  keys="$(curl -fsSL --max-time 15 "https://github.com/$user.keys" 2>/dev/null \
    | grep -E '^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-(ssh-ed25519|ecdsa-sha2-))[[:space:]]' || true)"
  if [[ -z "$keys" ]]; then
    skipped=$((skipped + 1))
    continue
  fi
  while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    printf '%s # github:%s (org:%s)\n' "$k" "$user" "$ORG" >> "$TMP"
    found=$((found + 1))
  done <<< "$keys"
done <<< "$member_list"

# --- output ------------------------------------------------------------------
if [[ "$ACTION" == "--install" ]]; then
  mkdir -p "$(dirname "$KEYS_FILE")"
  touch "$KEYS_FILE"
  chmod 600 "$KEYS_FILE"
  [[ -f "$KEYS_FILE" && ! -f "$KEYS_FILE.bak" ]] && cp "$KEYS_FILE" "$KEYS_FILE.bak"

  added=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if ! grep -qF -- "$line" "$KEYS_FILE"; then
      echo "$line" >> "$KEYS_FILE"
      added=$((added + 1))
    fi
  done < "$TMP"

  echo "[+] org $ORG: $found keys fetched, $added new keys installed (skipped $skipped users without keys)"
  echo "    backup at $KEYS_FILE.bak"
else
  echo "# draft for org $ORG ($found keys, skip $skipped without keys)"
  cat "$TMP"
fi