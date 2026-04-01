# MCP-13: Resource Exposure

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-13 |
| **Name** | Resource Exposure |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-06](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers that expose sensitive resources through the MCP protocol. This includes path traversal patterns in resource URIs, filesystem access outside sandboxed boundaries, sensitive file patterns (.env, .git/, credentials, keys), and missing access control on resource-serving servers.

MCP servers that provide resource access (e.g., filesystem servers) can expose sensitive data if not properly configured. Path traversal vulnerabilities can allow access to files outside the intended directory. Sensitive files like environment variables, SSH keys, and credentials should never be exposed as MCP resources. Resource-serving servers should always have explicit access control configuration.

## What It Checks

### 1. Path Traversal in Resource URIs (Critical)

Detects directory traversal patterns in arguments, URLs, and environment variables:

| Pattern | Description |
|---------|-------------|
| `../` | Dot-dot-slash directory traversal |
| `..\` | Dot-dot-backslash directory traversal |
| `%2e%2e%2f` | URL-encoded directory traversal |
| `..%2f` | Partially URL-encoded traversal |
| `..%5c` | URL-encoded backslash traversal |
| `%252e%252e%252f` | Double URL-encoded traversal |
| `....//` | Double-dot-double-slash bypass |
| `..;/` | Semicolon-based traversal bypass |

### 2. Sensitive File Patterns (High)

Detects resource servers exposing sensitive files:

| Pattern | Risk |
|---------|------|
| `.env`, `.env.local`, `.env.production` | Environment variables with secrets |
| `.git/`, `.git/config`, `.git/HEAD` | Git repository internals |
| `id_rsa`, `id_ed25519`, `id_ecdsa` | SSH private keys |
| `.pem`, `.key`, `.p12`, `.pfx`, `.jks` | Certificate and key files |
| `credentials.json`, `secrets.json` | Application credentials |
| `service-account.json` | Cloud service account keys |
| `.npmrc`, `.pypirc` | Package manager credentials |
| `.htaccess`, `.htpasswd` | Apache configuration |
| `wp-config.php`, `web.config` | Web app configuration |
| `/etc/passwd`, `/etc/shadow` | System files |
| `/proc/`, `/sys/` | Linux kernel filesystems |
| `docker-compose.yml` | Docker configuration |
| `.kube/config`, `kubeconfig` | Kubernetes configuration |

### 3. Sensitive Directory Exposure (High)

Detects resource servers exposing sensitive directories:

| Directory | Risk |
|-----------|------|
| `.ssh` | SSH keys and configuration |
| `.gnupg` | GPG keys and keyrings |
| `.aws` | AWS credentials |
| `.azure` | Azure credentials |
| `.gcloud` | Google Cloud credentials |
| `.kube` | Kubernetes configuration |
| `.docker` | Docker configuration |
| `.vault-token` | HashiCorp Vault token |
| `.password-store` | Password store |
| `node_modules` | npm packages (supply chain risk) |

### 4. Dangerous Resource URI Schemes (Critical/High)

Detects dangerous resource URI patterns:

- `file:///` — Root filesystem access via file URI
- `resource://*` or `resource://**` — Unrestricted wildcard resource access

### 5. Missing Access Control on Resource Servers (High)

Flags resource-serving MCP servers (filesystem, files, storage, etc.) that have no apparent access control configuration. The rule looks for:

**Arguments:**
`--allowed-paths`, `--read-only`, `--sandbox`, `--acl`, `--deny-list`, `--exclude-pattern`, `--max-depth`, `--restrict`, etc.

**Environment variables:**
`ALLOWED_PATHS`, `SANDBOX_DIR`, `READ_ONLY`, `RESOURCE_POLICY`, `DENY_LIST`, `MAX_DEPTH`, etc.

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "unsafe-fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/app/../../etc"]
    }
  }
}
```

**Findings:**
1. `Path traversal in resource URI for server 'unsafe-fs'` (Critical) — `../` pattern allows escaping the intended directory.
2. `No access control on resource server 'unsafe-fs'` (High) — No ACL configured.

```json
{
  "mcpServers": {
    "secrets-exposed": {
      "command": "npx",
      "args": ["-y", "server-filesystem", "/app/.env"]
    }
  }
}
```

**Findings:**
1. `Sensitive resource exposed by server 'secrets-exposed'` (High) — `.env` file may contain secrets.
2. `No access control on resource server 'secrets-exposed'` (High) — No ACL configured.

```json
{
  "mcpServers": {
    "open-filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/data"]
    }
  }
}
```

**Finding:** `No access control on resource server 'open-filesystem'` (High) — Resource server has no allowlist, denylist, sandbox, or read-only configuration.

```json
{
  "mcpServers": {
    "git-exposed": {
      "command": "npx",
      "args": ["-y", "server-filesystem", "/project/.git/config"]
    }
  }
}
```

**Finding:** `Sensitive resource exposed by server 'git-exposed'` (High) — `.git/config` may contain credentials and repository metadata.

```json
{
  "mcpServers": {
    "traversal-url": {
      "url": "https://mcp.example.com/resources/../../admin"
    }
  }
}
```

**Finding:** `Path traversal in server URL for 'traversal-url'` (Critical) — URL contains directory traversal pattern.

### Safe Configuration

```json
{
  "mcpServers": {
    "safe-filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/home/user/projects/public",
        "--read-only",
        "--allowed-paths",
        "/home/user/projects/public"
      ]
    }
  }
}
```

Read-only access with explicit allowed paths — no sensitive files, no traversal, access control configured.

```json
{
  "mcpServers": {
    "sandboxed-fs": {
      "command": "npx",
      "args": ["-y", "server-filesystem", "/app/data", "--sandbox"],
      "env": {
        "ALLOWED_PATHS": "/app/data/public",
        "READ_ONLY": "true"
      }
    }
  }
}
```

Sandboxed filesystem with environment-based access control.

## Remediation

1. **Remove path traversal sequences** — Never use `../`, URL-encoded variants, or other traversal patterns in resource paths. Use absolute, validated paths.
2. **Exclude sensitive files** — Do not expose `.env`, `.git/`, SSH keys, certificates, or credential files as MCP resources. Use `.gitignore`-style deny lists.
3. **Configure access control** — Always set `--read-only`, `--allowed-paths`, `--sandbox`, or equivalent flags on resource-serving MCP servers.
4. **Use allowlists over denylists** — Define explicit allowed paths rather than trying to block sensitive ones. Allowlists are more secure against novel attack paths.
5. **Restrict URI schemes** — Avoid `file:///` URIs that reference root or system paths. Use scoped, application-specific paths.
6. **Limit directory depth** — Use `--max-depth` to prevent deep directory traversal even within allowed paths.
7. **Audit resource scope** — Regularly review which files and directories are accessible through MCP resource servers.
8. **Validate inputs server-side** — Ensure the MCP server implementation validates and sanitizes all resource URIs before accessing the filesystem.

## References

- [OWASP MCP Top 10: Resource Exposure](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-23: Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)
- [CWE-36: Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [MCP Specification — Resources](https://modelcontextprotocol.io/specification)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
