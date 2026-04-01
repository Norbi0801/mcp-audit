# MCP Audit — Rules Reference

All rules implement the [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/) security framework for Model Context Protocol servers.

## Quick Reference

| Rule ID | Name | Default Severity | OWASP Category |
|---------|------|:----------------:|----------------|
| [MCP-01](./MCP-01-tool-poisoning.md) | Tool Poisoning | **High** | OWASP-MCP-01 |
| [MCP-02](./MCP-02-excessive-permissions.md) | Excessive Permissions | **High** | OWASP-MCP-02 |
| [MCP-03](./MCP-03-prompt-injection.md) | Prompt Injection via Tools | **High** | OWASP-MCP-03 |
| [MCP-04](./MCP-04-insecure-credentials.md) | Insecure Credentials | **Critical** | OWASP-MCP-04 |
| [MCP-05](./MCP-05-server-spoofing.md) | Server Spoofing | **High** | OWASP-MCP-05 |
| [MCP-06](./MCP-06-insecure-dependencies.md) | Insecure Dependencies | **Medium** | OWASP-MCP-06 |
| [MCP-07](./MCP-07-command-injection.md) | Command Injection | **Critical** | OWASP-MCP-07 |
| [MCP-08](./MCP-08-data-exfiltration.md) | Data Exfiltration | **High** | OWASP-MCP-08 |
| [MCP-09](./MCP-09-insufficient-logging.md) | Insufficient Logging & Monitoring | **Medium** | OWASP-MCP-09 |
| [MCP-10](./MCP-10-unauthorized-access.md) | Unauthorized Access | **High** | OWASP-MCP-10 |
| [MCP-11](./MCP-11-denial-of-service.md) | Denial of Service | **Medium** | OWASP-MCP-11 |
| [MCP-12](./MCP-12-tool-shadowing.md) | Tool Shadowing | **Critical** | OWASP-MCP-01 |
| [MCP-13](./MCP-13-resource-exposure.md) | Resource Exposure | **High** | OWASP-MCP-06 |
| [MCP-14](./MCP-14-insecure-transport.md) | Insecure Transport | **High** | OWASP-MCP-14 |
| [MCP-15](./MCP-15-tool-injection.md) | Tool Command Injection | **Critical** | OWASP-MCP-07 |
| [MCP-16](./MCP-16-missing-input-validation.md) | Missing Input Validation | **High** | OWASP-MCP-04 |
| [MCP-17](./MCP-17-data-leakage.md) | Data Leakage | **Critical** | OWASP-MCP-17 |
| [MCP-18](./MCP-18-prompt-injection-vectors.md) | Prompt Injection Vectors in Tool Descriptions | **Critical** | OWASP-MCP-03 |
| [MCP-19](./MCP-19-excessive-tool-permissions.md) | Excessive Tool Permissions | **High** | OWASP-MCP-02 |

## Severity Levels

| Level | Description | Exit Code |
|-------|-------------|:---------:|
| **Critical** | Immediate exploitation risk. Hardcoded secrets, command injection, authentication bypass. | 1 |
| **High** | Serious vulnerability. Excessive permissions, prompt injection, data exfiltration paths. | 1 |
| **Medium** | Notable concern. Unpinned dependencies, missing logging, development mode. | 2 |
| **Low** | Informational. Auto-install flags, missing best practices. | 2 |

The scanner returns exit code **0** when no findings are detected.

## How Rules Work

Each rule performs static analysis on MCP server configurations (typically `claude_desktop_config.json`, `mcp.json`, or similar). The scanner checks:

- **Command** — the binary being executed (e.g., `npx`, `node`, `python`)
- **Arguments** — command-line arguments passed to the server
- **Environment variables** — `env` block in the configuration
- **URL** — remote endpoint for HTTP-based MCP servers
- **Transport** — protocol type (`stdio`, `sse`, `streamable-http`)
- **Tools** — tool definitions exposed by the server (name, description, inputSchema)

Rules do not execute the MCP server — all analysis is static and safe to run in CI/CD.

## Usage

```bash
# Scan with all rules
mcp-audit scan --source claude_desktop_config.json

# Filter by minimum severity
mcp-audit scan --severity high

# List all rules
mcp-audit rules

# Output formats
mcp-audit scan --format json
mcp-audit scan --format sarif -o results.sarif
mcp-audit scan --format table
mcp-audit scan --format markdown
```

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/)
- [MCP Specification](https://modelcontextprotocol.io/specification)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/concepts/security)
