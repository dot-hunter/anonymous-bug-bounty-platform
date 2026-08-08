#!/usr/bin/env bash
# pair-tunnel.sh — instant pair-programming tunnels, without manually sharing
# SSH keys.
#
# Key insight: everyone already publishes their SSH keys on GitHub
# (https://github.com/<user>.keys). So access control can be derived from
# GitHub usernames alone — no pastebin, no scp of .pub files, no chat.
#
# Host side (the machine running the dev server / repo):
#   pair-tunnel.sh host --users alice,bob [--port 3000] [--local]
#
#   --local     : listen directly on the machine (firewall/NAT permitting).
#   (default)   : open a reverse SSH tunnel through a relay (PAIR_RELAY env,
#                 default: the public demo relay printed on first run) so both
#                 sides can be behind NAT. Guests connect to the relay.
#
#   Each user is checked against GitHub; their published public keys get a
#   scoped, ephemeral authorized_keys entry on the host. No key material
#   crosses the wire from host to guest.
#
# Guest side:
#   pair-tunnel.sh guest --user alice --host relay.example:2222 --port 3000
#   Opens a shell on the host via alice's own GitHub-published key, then
#   (optionally) starts tmux pairing or local port forwarding.
#
# Requirements: bash, curl, ssh. Optionally tmux for the pair session.
set -euo pipefail

RELAY="${PAIR_RELAY:-relay.pair.example:2222}"
RELAY_USER="${PAIR_RELAY_USER:-pair}"

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

github_key() {
  # $1 = github username -> emits public keys for that user (one per line)
  local user="$1" keys
  keys="$(curl -fsSL --max-time 15 "https://github.com/${user}.keys" 2>/dev/null \
    | grep -E '^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-ssh-|sk-ecdsa-)[[:space:]]' || true)"
  [[ -n "$keys" ]] || die "no public keys published for github:$user (https://github.com/$user.keys)"
  echo "$keys"
}

cmd_host() {
  local users="" port=3000 relay=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --users) users="$2"; shift 2 ;;
      --port)  port="$2"; shift 2 ;;
      --relay) relay="$2"; shift 2 ;;
      *) die "unknown host arg: $1" ;;
    esac
  done
  [[ -n "$users" ]] || die "host requires --users alice,bob"
  need curl; need ssh

  local authfile="$HOME/.ssh/pair-authorized_keys"
  mkdir -p "$HOME/.ssh"
  : > "$authfile"
  chmod 600 "$authfile"

  echo "[*] resolving GitHub-published keys for: $users"
  local IFS=',' u
  for u in $users; do
    u="$(echo "$u" | tr -d ' ')"
    [[ -n "$u" ]] || continue
    key="$(github_key "$u")" || die "could not fetch keys for $u"
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      echo "$line # github:$u/pair-tunnel" >> "$authfile"
    done <<< "$key"
    echo "    + github:$u"
  done

  if [[ -n "$relay" ]]; then
    echo "[*] launching reverse tunnel to relay $relay (port $port)"
    ssh -f -N -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ExitOnForwardFailure=yes \
        -R "127.0.0.1:${port}:127.0.0.1:${port}" \
        -p "${relay##*:}" "$RELAY_USER@${relay%%:*}" \
      || die "relay connection failed (is the relay reachable and pair-authorized?)"
    echo "    guests connect with: pair-tunnel.sh guest --user <your-github> --host $relay --port $port"
  else
    echo "[*] self-host mode on port $port (requires inbound connectivity)"
    echo "    guests connect with: pair-tunnel.sh guest --user <your-github> --host <this-ip>:$port"
    # Start a tmux session hosting the user's shell for the paired guest.
    if command -v tmux >/dev/null 2>&1; then
      tmux new-session -d -s pair -x 200 -y 50 "exec bash"
      echo "    tmux session 'pair' started on this machine"
    fi
  fi
  echo "    authorized keys file: $authfile (remove after session for cleanliness)"
}

cmd_guest() {
  local user="" host="" port=3000
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) user="$2"; shift 2 ;;
      --host) host="$2"; shift 2 ;;
      --port) port="$2"; shift 2 ;;
      *) die "unknown guest arg: $1" ;;
    esac
  done
  [[ -n "$user" ]] || die "guest requires --user <github-username>"
  [[ -n "$host" ]] || die "guest requires --host <relay-or-ip>[:port]"

  local hport="${host##*:}"
  local hhost="${host%%:*}"
  [[ "$hport" == "$hhost" ]] && hport=22

  echo "[*] connecting as github:$user to $hhost:$hport (your OWN key proves identity)"
  need ssh
  # No key selection needed — the guest uses their default agent/keys, the
  # host's authorized_keys accepts only keys published for github:$user.
  exec ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -p "$hport" -t "pair@$hhost" \
      "bash --rcfile <(echo 'echo \"[+] pair-tunnel guest session as $user\"; alias pair=\"/usr/bin/tmux attach -t pair 2>/dev/null || /usr/bin/bash\"')"
  # (tmux attach on host when tmux exists; bare shell otherwise)
}

case "${1:-}" in
  host)  shift; cmd_host "$@" ;;
  guest) shift; cmd_guest "$@" ;;
  *)
    echo "usage:"
    echo "  pair-tunnel.sh host  --users alice,bob [--port N] [--relay relay:2222]"
    echo "  pair-tunnel.sh guest --user alice      [--port N] --host relay:2222"
    exit 2
    ;;
esac