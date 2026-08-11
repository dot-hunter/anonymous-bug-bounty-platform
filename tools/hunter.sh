#!/usr/bin/env bash
# hunter.sh — NEXT-GEN unified autopilot launcher (scope-gated full pipeline).
#
# One-shot entry point that runs the entire anonymous autopilot pipeline for a
# target while enforcing the deterministic scope gate on EVERY stage.
#
# Usage:
#   bash tools/hunter.sh --program <handle> --platform hackerone
#   bash tools/hunter.sh --target target.com --quick
#   bash tools/hunter.sh --target target.com --focus xss,ssrf
#   bash tools/hunter.sh --target target.com --recon-only
#   bash tools/hunter.sh --target target.com --hunt-only
#   bash tools/hunter.sh --audit <repo> [--sandbox jail|docker|auto]
#   bash tools/hunter.sh --retest <report.json> --target-dir <repo> [--sandbox jail]
#   bash tools/hunter.sh --status
#
# Pipeline (scope-gated):
#   0. OPSEC bootstrap check (honest mode)
#   1. Scope load + gate verification
#   2. OSINT (passive)
#   3. Recon (recon_engine.sh)
#   4. Takeover sweep + token scan
#   5. Active hunt (hunt.py or focused class tests)
#   6. WAF analysis + bypass if blocked
#   7. Agentic PoC validation (--audit / --retest)
#   8. Summary → findings/<target>/summary.txt
set -uo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_ROOT="$(dirname "$TOOLS_DIR")"
TARGET=""; PROGRAM=""; PLATFORM="hackerone"; MODE="full"; FOCUS=""; SANDBOX="auto"
AUDIT_REPO=""; RETEST_REPORT=""; RETEST_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --program) PROGRAM="$2"; shift 2;;
    --platform) PLATFORM="$2"; shift 2;;
    --target) TARGET="$2"; shift 2;;
    --quick) MODE="quick"; shift;;
    --recon-only) MODE="recon"; shift;;
    --hunt-only) MODE="hunt"; shift;;
    --focus) FOCUS="$2"; shift 2;;
    --status) MODE="status"; shift;;
    --audit) MODE="audit"; AUDIT_REPO="$2"; shift 2;;
    --retest) MODE="retest"; RETEST_REPORT="$2"; shift 2;;
    --target-dir) RETEST_DIR="$2"; shift 2;;
    --sandbox) SANDBOX="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

echo "╔══════════════════════════════════════════════╗"
echo "║  NEXT-GEN ANONYMOUS AUTOPILOT HUNTER          ║"
echo "╚══════════════════════════════════════════════╝"

if [ "$MODE" = "status" ]; then
  echo "◆ platform status"
  bash "$TOOLS_DIR/external_arsenal.sh" --status
  echo ""
  echo "◆ scope"
  python3 "$TOOLS_DIR/scope_checker.py" --list 2>/dev/null | head -20
  echo ""
  echo "◆ RAG index"
  [ -f "$OUT_ROOT/rag-index.db" ] && echo "  [✓] rag-index.db exists" || echo "  [ ] rag-index.db missing — run: python3 tools/rag-builder/build.py --corpus data"
  echo ""
  echo "◆ agentic validator"
  python3 "$TOOLS_DIR/agentic/sandbox_runner.py" --detect
  exit 0
fi

# ---------- STAGE 0b: agentic audit / retest (no network target needed) ----------
if [ "$MODE" = "audit" ]; then
  echo "◆ Agentic PoC validation — $AUDIT_REPO (sandbox: $SANDBOX)"
  python3 "$TOOLS_DIR/agentic/agentic_audit.py" --target-dir "$AUDIT_REPO" --sandbox "$SANDBOX"
  exit $?
fi
if [ "$MODE" = "retest" ]; then
  echo "◆ Retest — $RETEST_REPORT vs $RETEST_DIR (sandbox: $SANDBOX)"
  python3 "$TOOLS_DIR/agentic/agentic_audit.py" --retest "$RETEST_REPORT" --target-dir "$RETEST_DIR" --sandbox "$SANDBOX"
  exit $?
fi

# ---------- STAGE 0: OPSEC bootstrap (honest mode) ----------
echo "◆ Stage 0 — OPSEC bootstrap"
EGRESS="$(curl -s -m 5 https://api.ipify.org 2>/dev/null || echo unknown)"
echo "  egress IP: $EGRESS (direct = honest mode)"
mkdir -p ~/.config/vulnera-mcp
echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"hunter_start\",\"egress\":\"$EGRESS\",\"mode\":\"$MODE\"}" >> ~/.config/vulnera-mcp/audit.jsonl

# ---------- STAGE 1: scope ----------
if [ -n "$PROGRAM" ]; then
  echo "◆ Stage 1 — scope load: $PROGRAM ($PLATFORM)"
  bash "$TOOLS_DIR/scope_aggregator.sh" --program "$PROGRAM" --platform "$PLATFORM" 2>/dev/null \
    || echo "  [!] program scope fetch failed — verify scope.yaml manually"
  # if no target set, pick first in-scope host
  if [ -z "$TARGET" ]; then
    TARGET=$(python3 "$TOOLS_DIR/scope_checker.py" --list 2>/dev/null | grep -A100 in_scope | grep '"- ' | head -1 | sed 's/.*"\(.*\)"/\1/' | sed 's|https\?://||')
  fi
fi

if [ -z "$TARGET" ]; then
  echo "[-] no target — use --target <domain> or --program <handle>" >&2
  exit 2
fi

echo "◆ Stage 1.5 — scope gate"
GATE=$(python3 "$TOOLS_DIR/scope_checker.py" --check "$TARGET" --json 2>/dev/null)
echo "  $GATE"
if ! echo "$GATE" | grep -q '"allowed": true'; then
  echo "[-] TARGET OUT OF SCOPE — aborting pipeline" >&2
  exit 1
fi

# ---------- STAGE 2: recon (unless hunt-only) ----------
if [ "$MODE" != "hunt" ]; then
  echo "◆ Stage 2 — recon pipeline"
  bash "$TOOLS_DIR/recon_engine.sh" "$TARGET" $([ "$MODE" = "quick" ] && echo "--quick") 2>&1 | tail -8
  echo ""
  echo "◆ Stage 2.5 — takeover sweep + token scan"
  if [ -f "$OUT_ROOT/recon/$TARGET/subs.txt" ]; then
    bash "$TOOLS_DIR/takeover_scanner.sh" -f "$OUT_ROOT/recon/$TARGET/subs.txt" 2>/dev/null | tail -5
  fi
  if [ -f "$OUT_ROOT/recon/$TARGET/urls.txt" ]; then
    python3 "$TOOLS_DIR/token_scanner.py" --path "$OUT_ROOT/recon/$TARGET/urls.txt" --entropy 5.0 2>/dev/null | head -8
  fi
fi

# ---------- STAGE 3: active hunt ----------
if [ "$MODE" != "recon" ]; then
  echo "◆ Stage 3 — active hunt (mode: $MODE, focus: ${FOCUS:-all})"
  if [ -n "$FOCUS" ] && [ "$FOCUS" != "all" ]; then
    echo "  focused testing requires MCP layer (autopilot-hunter agent) — use: opencode --agent autopilot-hunter"
  fi
  python3 "$TOOLS_DIR/hunt.py" --target "$TARGET" --scan-only $([ "$MODE" = "quick" ] && echo --quick) 2>&1 | tail -5
fi

echo ""
echo "◆ Stage 4 — WAF analysis"
python3 "$TOOLS_DIR/waf_response_analyzer.py" --url "https://$TARGET" 2>/dev/null | head -4 || true

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  PIPELINE COMPLETE — results in:              ║"
echo "║    recon/$TARGET/   findings/$TARGET/          ║"
echo "║  Next: opencode --agent autopilot-hunter      ║"
echo "╚══════════════════════════════════════════════╝"