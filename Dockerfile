# ============================================================================
# MCP Security Scanner — Docker Image
# ============================================================================
# Multi-stage build for minimal image size.
#
# Usage (standalone):
#   docker build -t mcp-audit .
#   docker run --rm -v $(pwd):/workspace mcp-audit scan --source /workspace/mcp.json
#
# Usage (CI — GitLab CI, Jenkins, etc.):
#   image: ghcr.io/norbi0801/mcp-audit:latest
#   script:
#     - mcp-audit scan --source mcp.json --format sarif -o results.sarif
#
# Usage (GitHub Actions — Docker-based):
#   See action.yml for the recommended composite action.
#   For Docker-based action alternative, use:
#     - uses: docker://ghcr.io/norbi0801/mcp-audit:latest
#       with:
#         args: scan --source mcp.json --format sarif -o results.sarif
# ============================================================================

# ── Stage 1: Build ─────────────────────────────────────────────────────────
FROM rust:1.83-bookworm AS builder

WORKDIR /build

# Cache dependency compilation by building a dummy project first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Copy full source and build
COPY . .
RUN cargo build --release && \
    strip target/release/mcp-audit 2>/dev/null || true

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Labels for container registries
LABEL org.opencontainers.image.title="MCP Security Scanner"
LABEL org.opencontainers.image.description="npm audit for MCP servers — scans configurations for OWASP MCP Top 10 vulnerabilities"
LABEL org.opencontainers.image.source="https://github.com/Norbi0801/mcp-audit"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.vendor="Norbi0801"

# Install minimal runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      jq \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary
COPY --from=builder /build/target/release/mcp-audit /usr/local/bin/mcp-audit

# Non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner -d /workspace scanner
USER scanner

WORKDIR /workspace

ENTRYPOINT ["mcp-audit"]
CMD ["--help"]
