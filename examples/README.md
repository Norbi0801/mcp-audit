# Example Configurations

This directory contains example MCP server configurations for testing MCP Audit.

## Files

### `safe-config.json` — Clean, hardened configuration

A fully secured MCP config that produces **zero findings**. Use this to see what a properly configured setup looks like:

- Pinned package versions (`@1.2.0`, `@1.0.0`)
- Secrets via environment variable references (`${GITHUB_TOKEN}`)
- Scoped filesystem access with `--read-only`
- Logging enabled (`LOG_LEVEL`)
- Timeouts configured (`REQUEST_TIMEOUT`)
- Response size limits set (`MAX_RESPONSE_SIZE`)

```bash
mcp-audit scan --config examples/safe-config.json
```

### `vulnerable-config.json` — Intentionally insecure (demo findings)

A config packed with security issues across all severity levels. Use this to see MCP Audit in action — it triggers **60+ findings** including:

- **Hardcoded API keys** — OpenAI, AWS, Stripe, GitHub, Slack tokens in plain text
- **Shell injection** — `sh -c "eval $USER_INPUT"`, `curl | sh`
- **Root filesystem access** — `/`, `/home`, `/etc/shadow`
- **Disabled authentication** — `AUTH_DISABLED=true`, `SKIP_VERIFICATION=true`
- **Disabled logging** — `LOG_LEVEL=off`, `--silent`
- **Typosquatting** — `@modeicontextprotocol` (note the `i` instead of `l`)
- **Insecure transport** — `http://` ngrok tunnel URL
- **Prompt injection** — `{{user.query}}` template syntax in args

```bash
mcp-audit scan --config examples/vulnerable-config.json
```

### `claude-desktop-example.json` — Typical Claude Desktop setup

A realistic Claude Desktop configuration using official MCP servers. Produces **only low-severity findings** (auto-install flags, missing timeouts) — the kind of results most users will see on their real configs:

- 5 official servers: filesystem, github, brave-search, memory, puppeteer
- Env var references for secrets
- Logging configured
- Minor findings typical of real-world setups

```bash
mcp-audit scan --config examples/claude-desktop-example.json
```

## Quick start

```bash
# Clone the repo and build
git clone https://github.com/Norbi0801/mcp-audit.git
cd mcp-audit
cargo build

# Try the vulnerable config — see all the findings
cargo run -- scan --config examples/vulnerable-config.json

# Try the safe config — see a clean report
cargo run -- scan --config examples/safe-config.json

# Try different output formats
cargo run -- scan --config examples/vulnerable-config.json --format json
cargo run -- scan --config examples/vulnerable-config.json --format markdown
cargo run -- scan --config examples/vulnerable-config.json --format sarif
```

## Using examples to test your own configs

Copy one of these files and modify it to match your setup:

```bash
cp examples/claude-desktop-example.json my-config.json
# Edit my-config.json with your actual MCP server configuration
mcp-audit scan --config my-config.json
```
