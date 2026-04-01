<p align="center">
  <img src="design/logo-full.svg" alt="MCP Audit" width="420" />
</p>

<p align="center">
  <strong>Security scanner for MCP (Model Context Protocol) servers</strong>
  <br />
  <em>Think <code>npm audit</code>, but for your MCP server configurations.</em>
</p>

<p align="center">
  <a href="https://crates.io/crates/mcp-audit"><img src="https://img.shields.io/crates/v/mcp-audit.svg?style=flat-square&color=2F81F7" alt="crates.io" /></a>
  <a href="https://github.com/Norbi0801/mcp-audit/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Norbi0801/mcp-audit/ci.yml?style=flat-square&label=CI" alt="CI" /></a>
  <a href="https://github.com/Norbi0801/mcp-audit/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square" alt="License" /></a>
  <a href="https://crates.io/crates/mcp-audit"><img src="https://img.shields.io/crates/d/mcp-audit.svg?style=flat-square&color=3FB950" alt="Downloads" /></a>
  <a href="https://github.com/Norbi0801/mcp-audit/stargazers"><img src="https://img.shields.io/github/stars/Norbi0801/mcp-audit?style=flat-square&color=D29922" alt="Stars" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#security-rules">Rules</a> &middot;
  <a href="#ci-integration">CI Integration</a> &middot;
  <a href="docs/rules-reference.md">Full Docs</a> &middot;
  <a href="#roadmap">Roadmap</a>
</p>


---

## The Problem

The MCP (Model Context Protocol) ecosystem is growing exponentially — **642K+ monthly searches**, hundreds of new servers every week, rapid adoption by Claude, Cursor, Windsurf, and more.

But security hasn't kept pace:

- **30% of the top 50 MCP servers have High or Critical vulnerabilities** — based on our scan of the most popular public servers
- **296 security findings** across just 50 servers — averaging **5.9 per server**, with **22% shipping hardcoded credentials**
- **30 CVE in 60 days** — Q1 2026 saw an explosion of MCP-related vulnerabilities
- **OWASP published the [MCP Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)** — a dedicated attack surface taxonomy for AI tool integrations
- **Zero dedicated tooling** existed at the developer/SMB level for MCP security auditing

Every `claude_desktop_config.json` or `.mcp.json` you commit is a potential attack surface: hardcoded API keys, shell injection vectors, overly broad filesystem access, unverified server sources. One misconfigured MCP server can expose your entire system.

**MCP Audit fills this gap.** It scans your MCP configurations for known vulnerability patterns before they become incidents — in your terminal, in your CI pipeline, or on a schedule.

## Real-World Results

We scanned the **50 most popular public MCP servers** on GitHub (350,000+ combined stars) with all 19 rules. Here's what we found:

| Metric | Value |
|--------|-------|
| Servers scanned | **50** |
| Total findings | **296** |
| Critical findings | **8** (across 6 servers) |
| High findings | **12** (across 9 servers) |
| Avg. findings per server | **5.9** |
| Servers with Critical issues | **6** (12%) |
| Servers with High+ issues | **15** (30%) |

### Most triggered rules

| Rule | What It Detects | Servers Affected |
|------|-----------------|:----------------:|
| MCP-11 | Missing timeout / response size limit | 50 (100%) |
| MCP-09 | Missing logging configuration | 50 (100%) |
| MCP-06 | Unpinned dependencies / auto-install | 49 (98%) |
| MCP-01 | Unverified package source | 27 (54%) |
| MCP-04 | Hardcoded credentials / secrets | 11 (22%) |

> Run `mcp-audit scan` on your own configs to check for similar issues.

## Quick Start

### Install

```bash
cargo install mcp-audit
```

### Run your first scan

```bash
# Auto-detect and scan MCP configs (claude_desktop_config.json, .mcp.json)
mcp-audit scan
```

That's it. MCP Audit auto-detects configuration files on macOS, Linux, and Windows.

### Try it with example configs

The `examples/` directory contains ready-to-use configs for testing:

```bash
# Scan a vulnerable config — see what MCP Audit catches
mcp-audit scan --config examples/vulnerable-config.json

# Scan a safe config — see a clean report
mcp-audit scan --config examples/safe-config.json

# Scan a typical Claude Desktop config
mcp-audit scan --config examples/claude-desktop-example.json
```

| File | Description |
|------|-------------|
| [`examples/safe-config.json`](examples/safe-config.json) | Clean config (0 findings) — pinned versions, env var references, scoped paths, timeouts, logging |
| [`examples/vulnerable-config.json`](examples/vulnerable-config.json) | Intentionally insecure — hardcoded secrets, shell injection, root access, and more |
| [`examples/claude-desktop-example.json`](examples/claude-desktop-example.json) | Typical Claude Desktop setup with official MCP servers |

### Example output

```
MCP Security Scan Report
  Source: claude_desktop_config.json
  Servers scanned: 3
  Rules applied: 19
  Scanned at: 2026-03-29 12:00:00 UTC

  ! 5 finding(s)
    CRITICAL 2
    HIGH     2
    MEDIUM   1

+-----------+--------+----------------------------------------------------+
| Severity  | Rule   | Title                                              |
+-----------+--------+----------------------------------------------------+
| CRITICAL  | MCP-07 | Shell interpreter used as command in server 'build' |
| CRITICAL  | MCP-04 | Hardcoded OpenAI API key in server 'ai-tools'      |
| HIGH      | MCP-02 | Root filesystem access in server 'filesystem'      |
| HIGH      | MCP-10 | Auth disabled in server 'api-server'               |
| MEDIUM    | MCP-06 | Unpinned npm package in server 'utils'             |
+-----------+--------+----------------------------------------------------+
```

### More options

```bash
# Scan a specific config file
mcp-audit scan --source path/to/config.json

# Only report high and critical findings
mcp-audit scan --severity high

# Output as JSON for scripts
mcp-audit scan --format json

# Output SARIF for GitHub Code Scanning
mcp-audit scan --format sarif -o results.sarif

# Generate a Markdown report
mcp-audit scan --format markdown -o report.md

# Initialize a sample config to experiment with
mcp-audit init
```

## Features

| Feature | Description |
|---------|-------------|
| **19 Security Rules** | Comprehensive coverage of every OWASP MCP Top 10 category and beyond — from tool poisoning to excessive tool permissions |
| **Auto-detection** | Automatically finds `claude_desktop_config.json`, `.mcp.json`, and platform-specific config paths |
| **4 Output Formats** | Human-readable table, JSON, Markdown, and SARIF — use the right format for every context |
| **GitHub Code Scanning** | Native SARIF output with a ready-to-use GitHub Action for seamless CI/CD integration |
| **Severity Filtering** | Focus on what matters with `--severity` threshold (critical, high, medium, low) |
| **CI Exit Codes** | Returns `1` on critical/high findings, `2` on medium/low — gate your deployments automatically |
| **Ecosystem Monitoring** | Track new MCP CVEs, GitHub security advisories, OWASP updates, and adoption metrics |
| **Weekly Digests** | Generate weekly security digest reports to stay on top of the MCP threat landscape |
| **Fast & Lightweight** | Single binary, no runtime dependencies — built in Rust for speed and reliability |
| **Open Source** | AGPL-3.0 licensed — inspect the rules, contribute new ones, trust the results |

## Security Rules

MCP Audit implements **19 security rules** covering all OWASP MCP Top 10 categories and beyond, with **40+ individual detection patterns**:

| Rule | Name | Severity | What It Detects |
|:----:|------|:--------:|-----------------|
| **MCP-01** | Tool Poisoning | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Unverified sources, typosquatting (`modeicontextprotocol`), untrusted registries, Git URL installs |
| **MCP-02** | Excessive Permissions | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Root-level paths (`/`, `/home`, `C:\`), sensitive dirs (`.ssh`, `.aws`, `.kube`), wildcards (`**`) |
| **MCP-03** | Prompt Injection via Tools | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Template syntax (`${...}`, `{{...}}`), user-controlled env vars, stdin/pipe arguments |
| **MCP-04** | Insecure Credentials | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | Hardcoded API keys (`sk-`, `ghp_`, `AKIA`), tokens, passwords, Bearer/Basic auth in configs |
| **MCP-05** | Server Spoofing | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Service impersonation, tunnel URLs (ngrok, localtunnel), unencrypted HTTP, domain typosquatting |
| **MCP-06** | Insecure Dependencies | ![Medium](https://img.shields.io/badge/-MEDIUM-D29922?style=flat-square) | Unpinned versions, deprecated packages (`event-stream`, `ua-parser-js`), auto-install flags |
| **MCP-07** | Command Injection | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | Shell interpreters as commands (`sh`, `bash`, `cmd`), metacharacters (`;`, `&&`, `` ` ``), eval/exec |
| **MCP-08** | Data Exfiltration | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Sensitive files (`.env`, `id_rsa`, `/etc/shadow`), database connection strings, unrestricted DB access |
| **MCP-09** | Insufficient Logging | ![Medium](https://img.shields.io/badge/-MEDIUM-D29922?style=flat-square) | Disabled logging (`--silent`, `LOG_LEVEL=off`), missing audit configuration |
| **MCP-10** | Unauthorized Access | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Auth disabled (`AUTH_DISABLED=true`), dev mode, bypass flags (`--no-auth`, `--insecure`), missing SSL |
| **MCP-12** | Tool Shadowing | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | Servers shadowing built-in tool names (`Read`, `Bash`, `Edit`), impersonating well-known MCP tools, deceptive replacement naming |
| **MCP-13** | Resource Exposure | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Path traversal in resource URIs, filesystem access outside sandbox, sensitive file patterns (`.env`, `.git/`, credentials) |
| **MCP-14** | Insecure Transport | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Plain HTTP without TLS, disabled certificate verification, missing auth on HTTP endpoints, overly permissive CORS (`*`) |
| **MCP-15** | Tool Command Injection | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | Tools vulnerable to command/code/SQL injection via dangerous tool names, execution-related descriptions, unsanitized input |
| **MCP-16** | Missing Input Validation | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Tools with no `inputSchema`, no required fields, unconstrained strings, open `additionalProperties`, missing enum constraints |
| **MCP-17** | Data Leakage | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | Tools returning env vars, secrets, or API keys; resources exposing credential files; missing output redaction |
| **MCP-18** | Prompt Injection Vectors | ![Critical](https://img.shields.io/badge/-CRITICAL-DA3633?style=flat-square) | LLM directive injection in descriptions, unicode deception (homoglyphs, bidi overrides), hidden content (HTML comments, base64) |
| **MCP-19** | Excessive Tool Permissions | ![High](https://img.shields.io/badge/-HIGH-F85149?style=flat-square) | Overly broad tool capabilities: unrestricted shell/filesystem/network access, schemaless tools, maximally permissive schemas |

> **6 Critical** &middot; **10 High** &middot; **3 Medium** severity rules
>
> See the **[full rules reference](docs/rules-reference.md)** for detailed documentation, vulnerable vs. safe examples, and remediation guidance for each rule.

## CI Integration

### GitHub Action (recommended)

Add MCP security scanning to your CI pipeline in 30 seconds:

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan

on:
  push:
    paths: ['**/claude_desktop_config.json', '**/.mcp.json']
  pull_request:
    paths: ['**/claude_desktop_config.json', '**/.mcp.json']

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Run MCP Audit
        uses: Norbi0801/mcp-audit/.github/actions/mcp-audit@main
        with:
          config-path: 'claude_desktop_config.json'
          severity: 'medium'
          format: 'sarif'
          sarif-upload: 'true'
```

Findings appear directly in the **Security** tab of your GitHub repository, alongside CodeQL and Dependabot alerts.

### Manual SARIF upload

```bash
# Generate SARIF
mcp-audit scan --format sarif -o results.sarif

# Upload via GitHub CLI
gh api repos/{owner}/{repo}/code-scanning/sarifs \
  -f "sarif=$(gzip -c results.sarif | base64)"
```

### Generic CI (GitLab, Jenkins, etc.)

```bash
# Install
cargo install mcp-audit

# Scan — exit code gates the pipeline
mcp-audit scan --source .mcp.json --severity high

# Exit codes:
#   0 = clean (no findings)
#   1 = critical or high severity findings
#   2 = medium or low severity findings only
```

## Why Not Just Review Code Manually?

| | Manual Review | MCP Audit |
|---|:---:|:---:|
| **Catches typosquatting** (`modeicontextprotocol` vs `modelcontextprotocol`) | Easily missed | Automatic |
| **Detects 40+ secret patterns** (`sk-`, `ghp_`, `AKIA`, Bearer tokens...) | Tedious, error-prone | Instant |
| **Runs in CI on every PR** | Requires discipline | Set-and-forget |
| **OWASP MCP Top 10 coverage** | Requires expertise | Built-in |
| **Catches shell injection vectors** (`sh -c`, `;`, `&&`, backticks) | Easy to overlook | Pattern-matched |
| **SARIF output for GitHub Security tab** | Not possible | Native |
| **Consistent across team members** | Varies by reviewer | Deterministic |
| **Time per config review** | 10-30 minutes | < 1 second |

Manual code review is essential — but it's not enough. MCP Audit catches the patterns humans miss, enforces policy consistently, and runs on every commit without asking.

## Ecosystem Monitoring

Beyond config scanning, MCP Audit tracks the evolving MCP threat landscape:

```bash
# Poll all sources for new security events
mcp-audit monitor

# Watch a specific source
mcp-audit monitor --source cve --watch --interval 3600

# Generate a weekly security digest
mcp-audit digest --format markdown -o weekly-digest.md
```

**Monitor sources:**

| Source | What It Tracks |
|--------|---------------|
| **GitHub** | New MCP repositories, security advisories, trending projects |
| **CVE** | NVD vulnerabilities related to MCP and AI tool integrations |
| **OWASP** | Updates to MCP security guidelines and Top 10 |
| **Adoption** | Ecosystem growth metrics across npm, crates.io, and PyPI |

## CLI Reference

```
MCP Security Scanner -- "npm audit" for MCP servers.

Usage: mcp-audit <COMMAND>

Commands:
  scan      Scan MCP server configurations for security vulnerabilities
  init      Initialize a sample MCP scanner configuration
  rules     List all available security rules
  monitor   Poll ecosystem monitors for new events
  digest    Generate a weekly digest report
  status    Show the current state of all monitors
  config    Display or validate configuration

Options:
  -f, --format <FORMAT>    Output format [default: table] [possible: json, table, markdown, sarif]
  -v, --verbose            Enable verbose (debug) logging
  -q, --quiet              Suppress all output except errors
  -h, --help               Print help
  -V, --version            Print version
```

## Configuration

API keys enhance monitoring capabilities but are **not required** for scanning:

```bash
# Environment variables (or .env file)
GITHUB_TOKEN=ghp_...                    # GitHub API (higher rate limits)
NVD_API_KEY=...                         # NVD API (higher rate limits)
MCP_SCANNER_STATE_DIR=~/.mcp-audit    # Custom state directory
```

## Roadmap

- [x] **v0.1** — Core scanner with OWASP MCP Top 10 rules
- [x] SARIF output + GitHub Action
- [x] Ecosystem monitoring (GitHub, CVE, OWASP, adoption)
- [x] Weekly digest generation
- [ ] **v0.2** — Remote MCP server scanning (HTTP/SSE transport)
- [ ] Custom rule definitions (YAML/TOML rule files)
- [ ] `--fix` mode — auto-remediation suggestions
- [ ] VS Code / Cursor extension
- [ ] **v0.3** — Runtime analysis (connect to MCP server, test actual behavior)
- [ ] Policy-as-code (OPA/Rego integration)
- [ ] **v1.0** — Stable API, plugin system

Have a feature request? [Open an issue](https://github.com/Norbi0801/mcp-audit/issues).

## Contributing

Contributions are welcome! MCP Audit is open source and we value every contribution — from bug reports to new rules.

### Getting started

```bash
git clone https://github.com/Norbi0801/mcp-audit.git
cd mcp-audit
cargo build
cargo test
```

### Adding a new scanning rule

Each rule is a self-contained file in `src/rules/`:

1. Create `src/rules/my_rule.rs` implementing the `Rule` trait
2. Register it in `src/rules/mod.rs`
3. Add unit tests (mandatory for all rules)
4. Document in `docs/rules-reference.md`
5. Submit a pull request

### Guidelines

- Follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, etc.)
- Code and comments in English
- All rules must have tests — `cargo test` must pass
- Run `cargo clippy` before submitting

See the [full rules reference](docs/rules-reference.md) for examples of rule structure.

## License

MCP Audit is licensed under the [GNU Affero General Public License v3.0](LICENSE).

```
Copyright (C) 2026 Norbi0801

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

## Links

- [Rules Reference](docs/rules-reference.md) — detailed documentation for all 19 rules
- [OWASP MCP Top 10](https://owasp.org/www-project-machine-learning-security-top-10/) — the standard we implement
- [Model Context Protocol](https://modelcontextprotocol.io/) — official MCP specification
- [Report an Issue](https://github.com/Norbi0801/mcp-audit/issues) — bugs, feature requests, questions

## Star History

<p align="center">
  <a href="https://star-history.com/#Norbi0801/mcp-audit&Date">
    <img src="https://api.star-history.com/svg?repos=Norbi0801/mcp-audit&type=Date" alt="Star History Chart" width="600" />
  </a>
</p>

---

<p align="center">
  <sub>Built with Rust. Powered by OWASP. Securing the MCP ecosystem.</sub>
  <br />
  <sub>If MCP Audit helped you, consider giving it a <a href="https://github.com/Norbi0801/mcp-audit">star</a>.</sub>
</p>
