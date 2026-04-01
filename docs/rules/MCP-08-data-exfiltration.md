# MCP-08: Data Exfiltration

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-08 |
| **Name** | Data Exfiltration |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-08](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers with access to sensitive files, databases, or network services that could facilitate data exfiltration.

MCP servers can read files, query databases, and make network requests on behalf of the AI model. If a server is configured with access to sensitive files (SSH keys, `.env` files, credential stores) or databases (with embedded credentials and no access restrictions), an attacker — or even a benign prompt gone wrong — can exfiltrate this data through the MCP conversation. Data exfiltration through MCP is particularly dangerous because the data flows through the AI model's context, potentially being logged, cached, or transmitted to third parties.

## What It Checks

### 1. Sensitive File Access (Critical)

Flags arguments that reference files known to contain secrets or sensitive data:

| File | Contents |
|------|----------|
| `/etc/passwd` | System user database |
| `/etc/shadow` | System password hashes |
| `/etc/hosts` | Network host mappings |
| `/etc/sudoers` | Sudo privilege configuration |
| `.env` | Environment variables (may contain secrets) |
| `.env.local` | Local environment variables |
| `.env.production` | Production environment variables |
| `.bashrc` | Shell configuration (may contain secrets) |
| `.bash_history` | Command history (may contain secrets) |
| `.zsh_history` | Command history |
| `.netrc` | Network authentication credentials |
| `.pgpass` | PostgreSQL password file |
| `.my.cnf` | MySQL configuration (may contain passwords) |
| `.npmrc` | npm configuration (may contain auth tokens) |
| `.pypirc` | PyPI credentials |
| `.docker/config.json` | Docker registry credentials |
| `credentials.json` | Application credentials |
| `service-account.json` | Service account credentials |
| `id_rsa` | SSH private key |
| `id_ed25519` | SSH private key |
| `known_hosts` | SSH known hosts |

### 2. Sensitive Directory Access (High)

Flags arguments referencing directories that typically contain credentials:

| Directory | Contents |
|-----------|----------|
| `.ssh` | SSH keys and configuration |
| `.gnupg` | GPG keys and keyrings |
| `.aws` | AWS credentials and configuration |
| `.azure` | Azure credentials |
| `.gcloud` | Google Cloud credentials |
| `.kube` | Kubernetes configuration |
| `.config/gcloud` | Google Cloud configuration |
| `.vault-token` | HashiCorp Vault token |
| `.password-store` | pass password store |
| `secrets` | Secrets directory |

### 3. Database Connection Strings (Critical with credentials, High without)

Detects database connection strings in environment variables:

| Pattern | Database |
|---------|----------|
| `postgres://` / `postgresql://` | PostgreSQL |
| `mysql://` | MySQL |
| `mongodb://` / `mongodb+srv://` | MongoDB |
| `redis://` / `rediss://` | Redis |
| `amqp://` | RabbitMQ |
| `mssql://` | SQL Server |
| `sqlite:///` | SQLite (absolute path) |

Connection strings with embedded credentials (e.g., `postgres://user:password@host/db`) are flagged as **Critical**.

### 4. Unrestricted Database Access (Medium)

Flags database MCP servers that lack explicit access restrictions. The rule checks for the absence of:

- `--table` / `--allowed-tables` (table restrictions)
- `--schema` (schema restrictions)
- `--read-only` / `--readonly` (read-only mode)
- `--deny-write` (write denial)

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/etc/passwd"]
    }
  }
}
```

**Finding:** `Access to sensitive file in server 'filesystem'` (Critical)
Server can read the system user database.

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

**Finding:** `Access to sensitive directory in server 'filesystem'` (High)
Server can read SSH keys and configuration.

```json
{
  "mcpServers": {
    "database": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "postgres://admin:s3cret@db.example.com/production"
      }
    }
  }
}
```

**Findings:**
1. `PostgreSQL connection string in server 'database'` (Critical) — Connection string has embedded credentials (`admin:s3cret`).
2. `Unrestricted database access in server 'database'` (Medium) — No table or schema restrictions.

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

Access restricted to a specific project directory with no sensitive files.

```json
{
  "mcpServers": {
    "database": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-postgres",
        "--read-only",
        "--allowed-tables",
        "public_data,products,categories"
      ],
      "env": {
        "DATABASE_URL": "${DATABASE_URL}"
      }
    }
  }
}
```

Database access is read-only, restricted to specific tables, and credentials are loaded from the environment.

## Remediation

1. **Restrict file access** — Only grant access to specific project directories. Never include system files, credential files, or history files.
2. **Use least-privilege database users** — Create database users with minimal permissions (SELECT-only on specific tables).
3. **Restrict accessible tables** — Use `--read-only`, `--allowed-tables`, and `--schema` flags to limit database access.
4. **Externalize credentials** — Use `${DATABASE_URL}` environment variable references instead of embedding credentials in connection strings.
5. **Audit data flows** — Monitor which files and database tables are accessed through MCP to detect anomalous data access patterns.
6. **Separate environments** — Never configure MCP servers to access production databases. Use read replicas or staging environments.

## References

- [OWASP MCP Top 10: MCP-08 Data Exfiltration](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [OWASP Data Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
