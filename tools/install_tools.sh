#!/usr/bin/env bash
# install_tools.sh — install the full toolchain (go-based + pip + apt where possible).
# Usage: bash tools/install_tools.sh [--minimal]
set -uo pipefail

echo "◆ installing hunt toolchain"
mkdir -p ~/go/bin
export PATH="$PATH:$HOME/go/bin:$(go env GOPATH 2>/dev/null)/bin"

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/s0md3v/Arjun@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)

install_go() {
  local pkg="$1"
  local name
  name=$(basename "$pkg" | sed 's/@latest//' | tr 'A-Z' 'a-z')
  if command -v "$name" >/dev/null 2>&1; then
    echo "  [✓] $name"
  else
    echo "  [*] go install $name ..."
    go install "$pkg" 2>&1 | tail -1 || true
  fi
}

if command -v go >/dev/null 2>&1; then
  for t in "${GO_TOOLS[@]}"; do install_go "$t"; done
else
  echo "  [!] go not found — skipping go tools (install: https://go.dev/dl/)"
fi

# pip tools (user-level, no sudo)
if command -v pip3 >/dev/null 2>&1; then
  for p in wafw00f; do
    pip3 install --user -q "$p" 2>/dev/null && echo "  [✓] $p (pip)" || echo "  [ ] $p install failed"
  done
fi

# apt tools (best effort, no sudo → skip silently)
if [ "$(id -u)" = "0" ]; then
  apt-get install -y -q nmap nikto jq 2>/dev/null && echo "  [✓] nmap/nikto/jq (apt)"
else
  for t in nmap nikto jq; do
    command -v "$t" >/dev/null 2>&1 && echo "  [✓] $t" || echo "  [ ] $t (install manually: sudo apt install $t)"
  done
fi

echo ""
echo "[✓] toolchain complete. Re-run recon for best results."
echo "    status: bash tools/external_arsenal.sh --status"