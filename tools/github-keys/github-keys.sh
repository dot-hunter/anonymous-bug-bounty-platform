#!/usr/bin/env bash
# github-keys.sh — one-liner SSH server access from GitHub public keys.
#
#   curl github.com/<user>.keys >> ~/.ssh/authorized_keys
#
# This script wraps that one-liner with safety checks: it verifies the
# response actually contains ssh-rsa/ecdsa/ed25519 lines before touching
# authorized_keys, dedupes against keys already installed, and writes a
# backup on first modification.
#
# Usage:
#   github-keys.sh <github-user>                  # print keys to stdout
#   github-keys.sh <github-user> --install        # append to ~/.ssh/authorized_keys
#   GITHUB_KEYS_FILE=/path/custom_authorized_keys github-keys.sh <user> --install
set -euo pipefail

USER="${1:-}"
ACTION="${2:-print}"

if [[ -z "$USER" ]]; then
  echo "usage: $0 <github-user> [--install]" >&2
  exit 2
fi

URL="https://github.com/${USER}.keys"
KEYS_FILE="${GITHUB_KEYS_FILE:-$HOME/.ssh/authorized_keys}"

fetch_keys() {
  curl -fsSL --max-time 15 "$URL" || {
    echo "error: failed to fetch $URL (user missing or network blocked)" >&2
    exit 1
  }
}

# Sanitize: only accept real OpenSSH public key lines.
KEYS="$(fetch_keys | grep -E '^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-(ssh-ed25519|ecdsa-sha2-))[[:space:]]' || true)"

if [[ -z "$KEYS" ]]; then
  echo "warning: no public keys published for '${USER}' at ${URL}" >&2
  exit 1
fi

if [[ "$ACTION" == "--install" ]]; then
  mkdir -p "$(dirname "$KEYS_FILE")"
  chmod 700 "$(dirname "$KEYS_FILE")"
  [[ -f "$KEYS_FILE" ]] && [[ ! -f "$KEYS_FILE.bak" ]] && cp "$KEYS_FILE" "$KEYS_FILE.bak"
  touch "$KEYS_FILE"
  chmod 600 "$KEYS_FILE"

  # Add only keys not already present (dedupe by full line).
  ADDED=0
  while IFS= read -r key; do
    [[ -z "$key" ]] && continue
    if ! grep -qF -- "$key" "$KEYS_FILE"; then
      printf '%s # github:%s\n' "$key" "$USER" >> "$KEYS_FILE"
      ADDED=$((ADDED + 1))
    fi
  done <<< "$KEYS"

  echo "[+] installed $ADDED new key(s) for github:$USER into $KEYS_FILE"
  echo "    (backup kept at $KEYS_FILE.bak on first run)"
else
  printf '%s # github:%s\n' "$KEYS" "$USER"
fi
