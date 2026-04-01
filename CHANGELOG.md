# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-01

### Added

- **19 OWASP MCP Top 10 security rules:**
  - MCP-01: Tool Poisoning (unverified sources, typosquatting)
  - MCP-02: Excessive Permissions (overly broad filesystem access)
  - MCP-03: Prompt Injection (prompt-based attacks)
  - MCP-04: Insecure Credentials (hardcoded secrets, API keys, tokens)
  - MCP-05: Server Spoofing (unauthorized server impersonation)
  - MCP-06: Insecure Dependencies (vulnerable package versions)
  - MCP-07: Command Injection (shell command vulnerabilities)
  - MCP-08: Data Exfiltration (unauthorized data access/transmission)
  - MCP-09: Insufficient Logging (missing audit trails)
  - MCP-10: Unauthorized Access (broken access controls)
  - MCP-11: Denial of Service (resource exhaustion)
  - MCP-12: Tool Shadowing (name collision attacks)
  - MCP-13: Resource Exposure (public/sensitive resource leaks)
  - MCP-14: Insecure Transport (unencrypted communication)
  - MCP-15: Tool Injection (malicious tool code execution)
  - MCP-16: Missing Input Validation (unsafe parameter handling)
  - MCP-17: Data Leakage (unintended information disclosure)
  - MCP-18: Prompt Injection Vectors (tool description-based attacks)
  - MCP-19: Excessive Tool Permissions (overly permissive tool access)
- **CLI commands:** `scan`, `init`, `rules`, `monitor`, `digest`, `status`, `config`, `seo`
- **Output formats:** JSON, Table (human-readable), Markdown, SARIF (CI/CD integration)
- **Scan targets:** auto-detect MCP configs, specific config files, stdio servers, HTTP/SSE URLs
- **Ecosystem monitors:** GitHub, CVE, OWASP, adoption metrics with watch mode
- **Weekly digest reports** with severity summaries
- **Configuration** via `.mcp-audit.toml` with CI-friendly init
- **Severity filtering** (critical, high, medium, low, info)
- **GitHub Action** for CI/CD pipeline integration
- **Docker image** for containerized scanning

[0.1.0]: https://github.com/Norbi0801/mcp-audit/releases/tag/v0.1.0
