#!/usr/bin/env bash
# ============================================================================
# MCP Security Scanner — Docker CI Entrypoint
# ============================================================================
# Entrypoint script for Docker-based CI usage (GitLab CI, Jenkins, CircleCI).
#
# Usage:
#   docker run --rm \
#     -v $(pwd):/workspace \
#     -e CONFIG_PATH=mcp.json \
#     -e SEVERITY=high \
#     -e FORMAT=sarif \
#     -e OUTPUT_FILE=results.sarif \
#     ghcr.io/norbi0801/mcp-scanner:latest
#
# Environment variables:
#   CONFIG_PATH   — Path to MCP config file (required)
#   SEVERITY      — Minimum severity: critical, high, medium, low, info (default: low)
#   FORMAT        — Output format: table, json, sarif, markdown (default: table)
#   OUTPUT_FILE   — Write report to file (optional; prints to stdout if omitted)
#   FAIL_ON       — Fail if findings at this severity or above: critical, high,
#                   medium, low, info, none (default: high)
# ============================================================================

set -euo pipefail

CONFIG_PATH="${CONFIG_PATH:-}"
SEVERITY="${SEVERITY:-low}"
FORMAT="${FORMAT:-table}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
FAIL_ON="${FAIL_ON:-high}"

# ── Validate inputs ──────────────────────────────────────────────────────

if [ -z "$CONFIG_PATH" ]; then
  echo "Error: CONFIG_PATH environment variable is required."
  echo ""
  echo "Usage:"
  echo "  docker run --rm -v \$(pwd):/workspace -e CONFIG_PATH=mcp.json ghcr.io/norbi0801/mcp-scanner:latest"
  exit 2
fi

if [ ! -f "$CONFIG_PATH" ]; then
  echo "Error: Configuration file not found: ${CONFIG_PATH}"
  exit 2
fi

# ── Build scan command ───────────────────────────────────────────────────

SCAN_ARGS=(scan --source "$CONFIG_PATH")

if [ "$SEVERITY" != "low" ]; then
  SCAN_ARGS+=(--severity "$SEVERITY")
fi

SCAN_ARGS+=(--format "$FORMAT")

if [ -n "$OUTPUT_FILE" ]; then
  SCAN_ARGS+=(-o "$OUTPUT_FILE")
fi

# ── Run scan ─────────────────────────────────────────────────────────────

echo "MCP Security Scanner"
echo "===================="
echo "Config:   ${CONFIG_PATH}"
echo "Severity: ${SEVERITY}"
echo "Format:   ${FORMAT}"
echo "Fail-on:  ${FAIL_ON}"
echo ""

SCAN_EXIT=0
mcp-scanner "${SCAN_ARGS[@]}" || SCAN_EXIT=$?

echo ""
echo "Exit code: ${SCAN_EXIT}"

# ── Apply fail-on threshold ──────────────────────────────────────────────

SHOULD_FAIL=false

case "$FAIL_ON" in
  critical|high)
    if [ "$SCAN_EXIT" -eq 1 ]; then
      SHOULD_FAIL=true
    fi
    ;;
  medium)
    if [ "$SCAN_EXIT" -ne 0 ]; then
      SHOULD_FAIL=true
    fi
    ;;
  low|info)
    if [ "$SCAN_EXIT" -ne 0 ]; then
      SHOULD_FAIL=true
    fi
    ;;
  none)
    ;;
  *)
    echo "Warning: Unknown FAIL_ON value '${FAIL_ON}', treating as 'high'."
    if [ "$SCAN_EXIT" -eq 1 ]; then
      SHOULD_FAIL=true
    fi
    ;;
esac

if [ "$SHOULD_FAIL" = "true" ]; then
  echo ""
  echo "FAILED: Findings at or above '${FAIL_ON}' severity threshold."
  exit 1
fi

echo "Scan complete."
exit 0
