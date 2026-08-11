#!/usr/bin/env bash
# agentic_audit.sh — wrapper for the Agentic PoC Validation Layer (VALIDATOR).
# Usage:
#   agentic_audit.sh --target-dir <repo> [--sandbox auto|docker|jail] [--json]
#   agentic_audit.sh --retest <prior-report.json> --target-dir <repo>
#   agentic_audit.sh --self-test
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/agentic_audit.py" "$@"