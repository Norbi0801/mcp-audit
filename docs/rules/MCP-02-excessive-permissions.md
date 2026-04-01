# MCP-02: Excessive Permissions

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-02 |
| **Name** | Excessive Permissions |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-02](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers configured with overly broad file system access, including root-level paths, sensitive directories, and wildcard patterns.

MCP servers — particularly the filesystem server — require explicit path arguments that define their access scope. Granting a server access to `/`, `~`, or sensitive directories like `.ssh` or `.aws` violates the principle of least privilege and enables an AI model to read, modify, or exfiltrate any file on the system. A single misconfigured path can expose SSH keys, cloud credentials, password databases, and environment secrets.

## What It Checks

### 1. Root-Level / System-Wide Paths (Critical)

Flags arguments that grant access to entire directory trees:

| Path | OS |
|------|----|
| `/` | Linux/macOS |
| `/home` | Linux |
| `/Users` | macOS |
| `/etc` | Linux/macOS |
| `/var` | Linux/macOS |
| `/usr` | Linux/macOS |
| `/root` | Linux |
| `/opt` | Linux/macOS |
| `C:\` / `C:/` | Windows |
| `D:\` / `D:/` | Windows |

### 2. Sensitive Directories (Critical)

Flags paths containing directories known to store secrets and credentials:

| Directory | Contents |
|-----------|----------|
| `.ssh` | SSH keys, known_hosts, config |
| `.gnupg` / `.gpg` | GPG keys and keyrings |
| `.aws` | AWS credentials and config |
| `.azure` | Azure credentials |
| `.gcloud` | Google Cloud credentials |
| `.kube` | Kubernetes config and tokens |
| `.docker` | Docker registry credentials |
| `.config` | Application configurations |
| `.local/share` | Local application data |
| `.password-store` | pass password manager |
| `.vault-token` | HashiCorp Vault tokens |
| `id_rsa` / `id_ed25519` | SSH private keys |
| `.env` | Environment variables with secrets |

### 3. Wildcard Patterns (High)

Detects glob patterns like `**` or `*.*` that grant unintended broad access.

### 4. Home Directory Expansion (High)

Detects `~` or `~/` as an argument, which grants access to the entire home directory.

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    }
  }
}
```

**Finding:** `Root-level path access in server 'filesystem'` (Critical)
Grants access to the entire file system.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/.ssh"]
    }
  }
}
```

**Finding:** `Sensitive directory access in server 'filesystem'` (Critical)
Exposes SSH keys and configuration.

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "~"]
    }
  }
}
```

**Finding:** `Full home directory access in server 'filesystem'` (High)
Grants access to the entire home directory, including all hidden config directories.

### Safe Configuration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@2025.1.14",
        "/home/user/projects/my-app"
      ]
    }
  }
}
```

Restricts access to a specific project directory only.

## Remediation

1. **Use specific project paths** — Only grant access to the directories the server actually needs (e.g., `/home/user/projects/my-app`).
2. **Never expose root or home** — Avoid `/`, `~`, `/home`, `C:\`, or any system-level path.
3. **Avoid sensitive directories** — Never include `.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, or `.config` in the access scope.
4. **Avoid wildcards** — Do not use `**` or `*.*` patterns; enumerate specific directories instead.
5. **Review Windows paths** — On Windows, ensure paths are scoped to specific folders under `C:\Users\<name>\` rather than the drive root.
6. **Audit regularly** — Periodically review MCP configurations to ensure paths haven't been broadened.

## References

- [OWASP MCP Top 10: MCP-02 Excessive Permissions](https://owasp.org/www-project-model-context-protocol-top-10/)
- [Principle of Least Privilege (OWASP)](https://owasp.org/www-community/Access_Control)
- [MCP Filesystem Server Docs](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
