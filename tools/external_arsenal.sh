#!/usr/bin/env bash
# external_arsenal.sh — check/install/run external security tools.
# Usage:
#   external_arsenal.sh --status            # what's installed
#   external_arsenal.sh --install all       # install everything (go-based)
#   external_arsenal.sh --install nuclei,ffuf
#   external_arsenal.sh --run nuclei -- -u https://target.com
#   external_arsenal.sh --run wafw00f -- -u https://target.com
set -uo pipefail

TOOLS=(subfinder assetfinder amass dnsx httpx katana gau waybackurls \
       nuclei ffuf wafw00f dalfox sqlmap arjun gf interactsh-client nmap \
       nikto wpscan ffuf jq dig curl python3)

# go-installable tools (github path)
declare -A GO_INSTALL=(
  [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
  [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
  [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [gau]="github.com/lc/gau/v2/cmd/gau@latest"
  [waybackurls]="github.com/tomnomnom/waybackurls@latest"
  [assetfinder]="github.com/tomnomnom/assetfinder@latest"
  [dalfox]="github.com/hahwul/dalfox/v2@latest"
  [ffuf]="github.com/ffuf/ffuf/v2@latest"
  [gf]="github.com/tomnomnom/gf@latest"
  [arjun]="github.com/s0md3v/Arjun@latest"
  [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)

status() {
  echo "◆ external arsenal status"
  for t in "${TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      echo "  [✓] $t → $(command -v "$t")"
    else
      echo "  [ ] $t"
    fi
  done
}

install_one() {
  local t="$1"
  if command -v "$t" >/dev/null 2>&1; then echo "  [✓] $t already installed"; return 0; fi
  if [ -n "${GO_INSTALL[$t]:-}" ]; then
    echo "  [*] go install $t..."
    go install "${GO_INSTALL[$t]}" 2>&1 | tail -2 || echo "  [x] $t install failed"
  else
    echo "  [?] $t not go-installable — install manually (apt/pip/brew)"
  fi
}

case "${1:-}" in
  --status) status;;
  --install)
    if [ "${2:-}" = "all" ]; then
      for t in subfinder assetfinder dnsx httpx katana gau waybackurls nuclei ffuf dalfox arjun interactsh-client; do
        install_one "$t"
      done
    else
      IFS=',' read -ra list <<< "${2:-}"
      for t in "${list[@]}"; do install_one "$t"; done
    fi
    ;;
  --run)
    TOOL="${2:-}"; shift 2
    command -v "$TOOL" >/dev/null 2>&1 || { echo "[-] $TOOL not installed — run: external_arsenal.sh --install $TOOL" >&2; exit 1; }
    echo "[*] running $TOOL $*"
    "$TOOL" "$@"
    ;;
  *) echo "usage: external_arsenal.sh --status | --install <t> | --run <t> -- <args>" >&2; exit 2;;
esac