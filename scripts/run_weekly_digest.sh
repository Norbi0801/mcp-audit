#!/usr/bin/env bash
# Weekly MCP Ecosystem Digest Generator
# ─────────────────────────────────────
# Designed to be run via cron:
#   0 8 * * 1 /path/to/scripts/run_weekly_digest.sh
#
# Workflow:
#   1. Poll all monitors for fresh data
#   2. Generate a Markdown digest for the previous week
#   3. Optionally copy to a publishing directory
#
# Environment variables (optional):
#   GITHUB_TOKEN          — GitHub PAT for higher rate limits
#   NVD_API_KEY           — NVD API key for higher rate limits
#   MCP_SCANNER_STATE_DIR — State directory (default: ~/.mcp-scanner)
#   DIGEST_OUTPUT_DIR     — Directory for generated digests (default: ~/.mcp-scanner/digests)
#   MCP_SCANNER_BIN       — Path to the mcp-scanner binary (default: searches $PATH)

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────

SCANNER="${MCP_SCANNER_BIN:-mcp-scanner}"
STATE_DIR="${MCP_SCANNER_STATE_DIR:-$HOME/.mcp-scanner}"
OUTPUT_DIR="${DIGEST_OUTPUT_DIR:-$STATE_DIR/digests}"
DATE=$(date +%Y-%m-%d)
WEEK_LABEL=$(date -d 'last monday' +%G-W%V 2>/dev/null || date -v-monday +%G-W%V 2>/dev/null || echo "unknown")

# Ensure output directory exists.
mkdir -p "$OUTPUT_DIR"

DIGEST_FILE="$OUTPUT_DIR/digest-${WEEK_LABEL}-${DATE}.md"

echo "=== MCP Scanner Weekly Digest ==="
echo "  Date:       $DATE"
echo "  Week:       $WEEK_LABEL"
echo "  State dir:  $STATE_DIR"
echo "  Output:     $DIGEST_FILE"
echo ""

# ── Step 1: Poll all monitors for fresh data ───────────────────────────

echo "[1/2] Polling all monitors..."
"$SCANNER" monitor --source all --format json --quiet 2>/dev/null || {
    echo "Warning: monitor poll returned non-zero exit code (some sources may have failed)."
    echo "Continuing with available data..."
}
echo "      Done."

# ── Step 2: Generate the digest ────────────────────────────────────────

echo "[2/2] Generating digest for $WEEK_LABEL..."
"$SCANNER" digest \
    --format markdown \
    --include-seo \
    --output "$DIGEST_FILE"

echo ""
echo "Digest written to: $DIGEST_FILE"
echo "Size: $(wc -c < "$DIGEST_FILE") bytes"
echo ""
echo "=== Done ==="
