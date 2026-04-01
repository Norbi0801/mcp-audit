# MCP-06: Insecure Dependencies

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-06 |
| **Name** | Insecure Dependencies |
| **Default Severity** | Medium |
| **OWASP Category** | [OWASP-MCP-06](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers using unpinned versions, deprecated packages, or packages with known vulnerabilities.

MCP servers are typically installed via package managers (`npx`, `pip`, `uvx`) at runtime. Without version pinning, a server automatically fetches the latest version each time it starts — meaning a compromised update could be silently installed. This rule also detects known-malicious packages that have been involved in supply-chain attacks, as well as deprecated MCP packages that have been superseded by official alternatives.

## What It Checks

### 1. Deprecated / Vulnerable Packages (High)

Flags packages that are deprecated or have known security issues:

| Package | Advice |
|---------|--------|
| `mcp-server-fetch` | Use `@modelcontextprotocol/server-fetch` instead |
| `mcp-server-filesystem` | Use `@modelcontextprotocol/server-filesystem` instead |
| `mcp-server-github` | Use `@modelcontextprotocol/server-github` instead |
| `mcp-server-postgres` | Use `@modelcontextprotocol/server-postgres` instead |
| `mcp-server-sqlite` | Use `@modelcontextprotocol/server-sqlite` instead |
| `mcp-server-brave-search` | Use `@modelcontextprotocol/server-brave-search` instead |
| `mcp-server-puppeteer` | Use `@modelcontextprotocol/server-puppeteer` instead |
| `mcp-server-memory` | Use `@modelcontextprotocol/server-memory` instead |
| `mcp-server-everything` | Use `@modelcontextprotocol/server-everything` instead |
| `node-ipc` | Known malicious package (protestware incident) |
| `event-stream` | Known compromised package (supply chain attack) |
| `ua-parser-js` | Had malicious versions published |
| `coa` | Had malicious versions published |
| `rc` | Had malicious versions published |

### 2. Unpinned npm Packages (Medium)

Detects packages installed via `npx` or `bunx` without a version specifier:

- `@scope/package` (unpinned) vs `@scope/package@1.2.3` (pinned)
- `package` (unpinned) vs `package@1.2.3` (pinned)

### 3. Unpinned Python Packages (Medium)

Detects packages installed via `pip`, `pip3`, `uvx`, or `pipx` without version constraints:

- `package` (unpinned) vs `package==1.2.3` (pinned)

### 4. Auto-Install Flags (Low)

Flags `-y` / `--yes` flags that bypass installation confirmation, removing the opportunity to review what will be installed.

### 5. Risky Installation Flags (Medium)

Detects flags that bypass package manager safety checks:

| Flag | Risk |
|------|------|
| `--pre` | Installs pre-release versions that may be unstable or malicious |
| `--force-reinstall` | Bypasses version caching, forcing a fresh download |
| `--no-deps` | Skips dependency resolution, may miss security patches |
| `--no-verify` | Skips package integrity verification |

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "mcp-server-filesystem", "/tmp"]
    }
  }
}
```

**Findings:**
1. `Deprecated/vulnerable package in server 'filesystem'` (High) — Use `@modelcontextprotocol/server-filesystem` instead.
2. `Unpinned npm package in server 'filesystem'` (Medium) — No version specified.
3. `Auto-install flag in server 'filesystem'` (Low) — `-y` bypasses confirmation.

```json
{
  "mcpServers": {
    "custom": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  }
}
```

**Finding:** `Unpinned npm package in server 'custom'` (Medium)
Even official packages should be pinned to a specific version.

```json
{
  "mcpServers": {
    "python-server": {
      "command": "pip",
      "args": ["install", "--pre", "mcp-server-custom"]
    }
  }
}
```

**Findings:**
1. `Unpinned Python package in server 'python-server'` (Medium)
2. `Risky package install flag in server 'python-server'` (Medium) — `--pre` allows pre-release versions.

### Safe Configuration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/home/user/projects"]
    }
  }
}
```

Uses the official package with a pinned version.

```json
{
  "mcpServers": {
    "python-server": {
      "command": "uvx",
      "args": ["mcp-server-custom==2.1.0"]
    }
  }
}
```

Python package pinned to an exact version.

## Remediation

1. **Pin all package versions** — Use `package@version` for npm and `package==version` for pip.
2. **Use official packages** — Replace deprecated `mcp-server-*` packages with `@modelcontextprotocol/server-*`.
3. **Pre-install packages** — Use `npm install` or `pip install` in a controlled environment instead of runtime installation with `npx -y`.
4. **Remove risky flags** — Avoid `--pre`, `--force-reinstall`, `--no-deps`, and `--no-verify` unless strictly necessary.
5. **Use lock files** — Maintain `package-lock.json` or `requirements.txt` with pinned versions and integrity hashes.
6. **Audit dependencies regularly** — Run `npm audit` or `pip-audit` to detect known vulnerabilities.
7. **Use a private registry** — Host verified packages on a private npm/PyPI registry for production environments.

## References

- [OWASP MCP Top 10: MCP-06 Insecure Dependencies](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- [npm Security Advisories](https://www.npmjs.com/advisories)
- [event-stream Supply Chain Attack Post-mortem](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)
- [node-ipc Protestware Incident](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
