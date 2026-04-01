# MCP-01: Tool Poisoning

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-01 |
| **Name** | Tool Poisoning |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-01](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers from unverified or potentially malicious sources, including typosquatting attacks and packages from untrusted registries.

Tool poisoning occurs when an attacker publishes a malicious MCP server package with a name similar to a legitimate one (typosquatting) or distributes a compromised server through unofficial channels. Because MCP servers execute with significant privileges — accessing files, databases, and APIs — installing a poisoned tool can lead to full credential theft, data exfiltration, or remote code execution.

## What It Checks

### 1. Typosquatting in Package Names (Critical)

Detects package names that are visually similar to legitimate MCP packages through character substitution or addition:

| Typosquat Pattern | Legitimate Package |
|-------------------|--------------------|
| `modeicontextprotocol` | `modelcontextprotocol` |
| `modelcontextprotoco1` | `modelcontextprotocol` |
| `mode1contextprotocol` | `modelcontextprotocol` |
| `modelccontextprotocol` | `modelcontextprotocol` |
| `anthropic-ai-` | `@anthropic-ai/` |
| `mcp_server` | `mcp-server` |

### 2. Unverified Package Sources (Medium)

Flags npm packages that are not from recognized trusted scopes:

- `@modelcontextprotocol/`
- `@anthropic-ai/`
- `@cloudflare/`
- `@aws/`
- `@google-cloud/`
- `@azure/`
- `@vercel/`
- `@supabase/`

### 3. Git Repository Installs (Medium)

Detects packages installed directly from GitHub/GitLab URLs without pinned commit hashes, which bypasses registry security checks and enables supply-chain attacks.

## Examples

### Vulnerable Configuration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modeicontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

**Finding:** `Possible typosquatting in server 'filesystem'` (Critical)
The package name `modeicontextprotocol` is a typosquat of `modelcontextprotocol` (letter `i` instead of `l`).

```json
{
  "mcpServers": {
    "custom-tool": {
      "command": "npx",
      "args": ["-y", "some-random-mcp-tool"]
    }
  }
}
```

**Finding:** `Unverified package source in server 'custom-tool'` (Medium)
Package is not from any recognized MCP package scope.

```json
{
  "mcpServers": {
    "git-server": {
      "command": "npx",
      "args": ["-y", "github.com/user/mcp-server"]
    }
  }
}
```

**Finding:** `Server 'git-server' installed from Git repository` (Medium)
Direct Git install bypasses registry security checks.

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

Uses the official `@modelcontextprotocol/` scope with a pinned version.

## Remediation

1. **Use official packages** — Always use packages from the `@modelcontextprotocol/` scope or other trusted scopes.
2. **Pin to specific versions** — Use `package@version` syntax (e.g., `@modelcontextprotocol/server-filesystem@2025.1.14`).
3. **Verify package authenticity** — Check the npm registry page, verify the publisher, and review download counts before installing.
4. **Pin Git installs to commits** — If you must install from Git, use a specific commit hash (e.g., `github.com/org/repo#abc123`).
5. **Pre-install packages** — Use `npm install` in a controlled environment instead of `npx -y` which fetches at runtime.

## References

- [OWASP MCP Top 10: MCP-01 Tool Poisoning](https://owasp.org/www-project-model-context-protocol-top-10/)
- [npm Security Best Practices](https://docs.npmjs.com/packages-and-modules/securing-your-code)
- [Typosquatting in npm (Snyk)](https://snyk.io/blog/typosquatting-attacks/)
- [CVE-2024-24576 — Rust std::process Command injection on Windows](https://nvd.nist.gov/vuln/detail/CVE-2024-24576)
