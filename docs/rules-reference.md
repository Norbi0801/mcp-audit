# MCP Audit — Rules Reference

All rules are based on the [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/).

## Rules Overview

| Rule ID | Name | Default Severity | OWASP Category |
|---------|------|-----------------|----------------|
| MCP-01 | Tool Poisoning | High | OWASP-MCP-01 |
| MCP-02 | Excessive Permissions | High | OWASP-MCP-02 |
| MCP-03 | Prompt Injection via Tools | High | OWASP-MCP-03 |
| MCP-04 | Insecure Credentials | Critical | OWASP-MCP-04 |
| MCP-05 | Server Spoofing | High | OWASP-MCP-05 |
| MCP-06 | Insecure Dependencies | Medium | OWASP-MCP-06 |
| MCP-07 | Command Injection | Critical | OWASP-MCP-07 |
| MCP-08 | Data Exfiltration | High | OWASP-MCP-08 |
| MCP-09 | Insufficient Logging | Medium | OWASP-MCP-09 |
| MCP-10 | Unauthorized Access | High | OWASP-MCP-10 |

---

## MCP-01: Tool Poisoning

**Severity:** High | **OWASP:** OWASP-MCP-01

Detects MCP servers from unverified or potentially malicious sources, including typosquatting attacks and packages from untrusted registries.

### What it checks
- Typosquatting patterns in package names (e.g., `modeicontextprotocol` vs `modelcontextprotocol`)
- Packages not from recognized scopes (`@modelcontextprotocol/`, `@anthropic-ai/`, etc.)
- Installation from Git URLs without pinned commits

### Vulnerable configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modeicontextprotocol/server-filesystem", "/tmp"]
}
```

### Safe configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"]
}
```

### Remediation
- Use official `@modelcontextprotocol/` packages
- Pin to specific versions
- Verify package authenticity before installation

---

## MCP-02: Excessive Permissions

**Severity:** High | **OWASP:** OWASP-MCP-02

Detects MCP servers configured with overly broad file system access, including root-level paths and sensitive directories.

### What it checks
- Root-level paths (`/`, `/home`, `/etc`, `C:\`)
- Sensitive directories (`.ssh`, `.aws`, `.gnupg`, `.kube`)
- Wildcard patterns (`**`, `*.*`)
- Full home directory access (`~`)

### Vulnerable configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
}
```

### Safe configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects/my-app"]
}
```

### Remediation
- Restrict file access to specific project directories
- Never expose root, home, or system directories
- Avoid sensitive directories (`.ssh`, `.aws`, `.config`)

---

## MCP-03: Prompt Injection via Tools

**Severity:** High | **OWASP:** OWASP-MCP-03

Detects MCP servers that may be vulnerable to prompt injection through unsanitized tool inputs, dynamic templates, or user-controlled environment variables.

### What it checks
- Template interpolation syntax (`${...}`, `{{...}}`, `<%= ... %>`)
- Environment variables suggesting dynamic user input (`USER_INPUT`, `PROMPT`, `QUERY`)
- Raw stdin arguments (`--stdin`, `-i`)

### Vulnerable configuration
```json
{
  "command": "node",
  "args": ["server.js", "--template", "${USER_INPUT}"]
}
```

### Safe configuration
```json
{
  "command": "node",
  "args": ["server.js", "--port", "3000"]
}
```

### Remediation
- Validate and sanitize all tool inputs
- Avoid template interpolation in server arguments
- Use structured input mechanisms instead of raw text

---

## MCP-04: Insecure Credentials

**Severity:** Critical | **OWASP:** OWASP-MCP-04

Detects hardcoded API keys, tokens, passwords, and other secrets in MCP server environment variables and command arguments.

### What it checks
- Known secret prefixes: OpenAI (`sk-`), GitHub (`ghp_`), AWS (`AKIA`), Slack (`xoxb-`), Stripe (`sk_live_`), etc.
- Environment variable names suggesting secrets (`PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`)
- Secrets passed as command arguments

### Vulnerable configuration
```json
{
  "command": "node",
  "args": ["server.js"],
  "env": {
    "OPENAI_API_KEY": "sk-abc123def456..."
  }
}
```

### Safe configuration
```json
{
  "command": "node",
  "args": ["server.js"],
  "env": {
    "OPENAI_API_KEY": "${OPENAI_API_KEY}"
  }
}
```

### Remediation
- Use environment variable references (`${VAR}`) instead of literal values
- Store secrets in a secrets manager (Vault, AWS Secrets Manager, 1Password)
- Never commit secrets to version control

---

## MCP-05: Server Spoofing

**Severity:** High | **OWASP:** OWASP-MCP-05

Detects MCP servers that may be impersonating legitimate services or connecting to suspicious endpoints.

### What it checks
- Well-known server names using non-official packages
- Tunnel/proxy services (ngrok, localtunnel, webhook.site)
- Unencrypted HTTP connections (non-localhost)
- Domain typosquatting (e.g., `anthroplc.com` vs `anthropic.com`)

### Vulnerable configuration
```json
{
  "url": "http://api.example.com/mcp",
  "transport": "sse"
}
```

### Safe configuration
```json
{
  "url": "https://api.example.com/mcp",
  "transport": "sse",
  "env": { "API_KEY": "${MCP_API_KEY}" }
}
```

### Remediation
- Always use HTTPS for remote connections
- Verify server URLs point to legitimate endpoints
- Avoid tunnel services in production

---

## MCP-06: Insecure Dependencies

**Severity:** Medium | **OWASP:** OWASP-MCP-06

Detects MCP servers using unpinned package versions, deprecated packages, or known-vulnerable dependencies.

### What it checks
- Unpinned npm packages (`npx -y package` without `@version`)
- Deprecated/vulnerable packages (e.g., `node-ipc`, `event-stream`)
- Auto-install flags (`-y`, `--yes`)
- Unpinned Python packages
- Risky installation flags (`--pre`, `--no-verify`)

### Vulnerable configuration
```json
{
  "command": "npx",
  "args": ["-y", "some-mcp-server"]
}
```

### Safe configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"]
}
```

### Remediation
- Pin all packages to specific versions (`package@1.2.3`)
- Pre-install packages instead of using `npx -y`
- Regularly audit dependencies for vulnerabilities

---

## MCP-07: Command Injection

**Severity:** Critical | **OWASP:** OWASP-MCP-07

Detects MCP server configurations vulnerable to command injection through shell interpreters, metacharacters, and eval/exec patterns.

### What it checks
- Shell interpreters as command (`sh`, `bash`, `cmd`, `powershell`)
- Shell metacharacters in arguments (`;`, `&&`, `||`, `|`, `` ` ``, `$(...)`)
- Eval/exec patterns (`eval`, `exec`, `system()`, `child_process`)
- Variable expansion in shell commands (`$VAR`)

### Vulnerable configuration
```json
{
  "command": "sh",
  "args": ["-c", "eval $INPUT && node server.js"]
}
```

### Safe configuration
```json
{
  "command": "node",
  "args": ["server.js", "--port", "3000"]
}
```

### Remediation
- Use direct command execution (`node`, `python`) instead of shell wrappers
- Never use `eval`, `exec`, or shell metacharacters
- Pass configuration via environment variables, not shell commands

---

## MCP-08: Data Exfiltration

**Severity:** High | **OWASP:** OWASP-MCP-08

Detects MCP servers with access to sensitive files, databases, or network services that could facilitate data exfiltration.

### What it checks
- Access to sensitive files (`.env`, `id_rsa`, `credentials.json`, `/etc/shadow`)
- Access to sensitive directories (`.ssh`, `.aws`, `.gnupg`, `.kube`)
- Database connection strings with embedded credentials
- Unrestricted database access (no `--read-only` or `--allowed-tables`)

### Vulnerable configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-postgres"],
  "env": {
    "DATABASE_URL": "postgres://admin:password@db.example.com/production"
  }
}
```

### Safe configuration
```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-postgres", "--read-only", "--allowed-tables", "public_data"],
  "env": {
    "DATABASE_URL": "${DATABASE_URL}"
  }
}
```

### Remediation
- Use least-privilege database users
- Restrict accessible tables and schemas
- Use read-only access when possible
- Never embed credentials in connection strings

---

## MCP-09: Insufficient Logging

**Severity:** Medium | **OWASP:** OWASP-MCP-09

Detects MCP servers without logging configuration, with logging explicitly disabled, or lacking audit trail capabilities.

### What it checks
- Missing logging environment variables (`LOG_LEVEL`, `DEBUG`, `SENTRY_DSN`, etc.)
- Missing logging arguments (`--log-level`, `--verbose`, `--audit-log`)
- Explicitly disabled logging (`LOG_LEVEL=off`, `--silent`, `--no-log`)

### Vulnerable configuration
```json
{
  "command": "node",
  "args": ["server.js", "--silent"],
  "env": { "LOG_LEVEL": "off" }
}
```

### Safe configuration
```json
{
  "command": "node",
  "args": ["server.js", "--log-level", "info", "--audit-log"],
  "env": {
    "LOG_LEVEL": "info",
    "SENTRY_DSN": "${SENTRY_DSN}"
  }
}
```

### Remediation
- Configure logging at `info` or `debug` level
- Enable audit logging for security events
- Use an observability service (Sentry, Datadog, OpenTelemetry)

---

## MCP-10: Unauthorized Access

**Severity:** High | **OWASP:** OWASP-MCP-10

Detects MCP servers with missing or weakened authentication, disabled auth configurations, and development mode settings.

### What it checks
- Authentication explicitly disabled (`AUTH_DISABLED=true`, `--no-auth`)
- Development mode enabled (`NODE_ENV=development`, `--dev`)
- HTTP servers without authentication configuration
- Authentication bypass flags (`--insecure`, `--allow-anonymous`)

### Vulnerable configuration
```json
{
  "url": "https://api.example.com/mcp",
  "transport": "sse",
  "env": {
    "AUTH_DISABLED": "true",
    "NODE_ENV": "development"
  }
}
```

### Safe configuration
```json
{
  "url": "https://api.example.com/mcp",
  "transport": "sse",
  "env": {
    "API_KEY": "${MCP_API_KEY}",
    "NODE_ENV": "production"
  }
}
```

### Remediation
- Enable authentication on all HTTP-based MCP servers
- Use API keys, JWT tokens, or OAuth for access control
- Never run production servers in development mode
- Remove authentication bypass flags

---

## Running the Scanner

```bash
# Install
cargo install mcp-audit

# Scan with all rules
mcp-audit scan --source claude_desktop_config.json

# Filter by severity
mcp-audit scan --severity high

# SARIF output for CI/CD
mcp-audit scan --format sarif -o results.sarif

# List all rules
mcp-audit rules
```
