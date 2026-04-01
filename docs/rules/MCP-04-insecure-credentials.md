# MCP-04: Insecure Credentials

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-04 |
| **Name** | Insecure Credentials |
| **Default Severity** | **Critical** |
| **OWASP Category** | [OWASP-MCP-04](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects hardcoded API keys, tokens, passwords, and other secrets in MCP server environment variables and command arguments.

Hardcoded credentials in MCP configuration files are one of the most dangerous vulnerabilities. These files are often committed to version control, shared across teams, and synced to cloud storage — exposing secrets to anyone with access. MCP config files sit in well-known locations (`~/.config/claude/`, `~/Library/Application Support/Claude/`), making them prime targets. A single leaked API key can lead to unauthorized access to cloud services, data breaches, and financial losses.

## What It Checks

### 1. Known Secret Prefixes (Critical)

Detects values starting with well-known secret patterns:

| Prefix | Service |
|--------|---------|
| `sk-` | OpenAI API key |
| `sk-proj-` | OpenAI project key |
| `ghp_` | GitHub personal access token |
| `gho_` | GitHub OAuth token |
| `ghu_` | GitHub user-to-server token |
| `ghs_` | GitHub server-to-server token |
| `ghr_` | GitHub refresh token |
| `glpat-` | GitLab personal access token |
| `xoxb-` | Slack bot token |
| `xoxp-` | Slack user token |
| `xoxs-` | Slack session token |
| `xoxa-` | Slack app token |
| `AKIA` | AWS access key ID |
| `ABIA` | AWS STS token |
| `ACCA` | AWS account ID |
| `eyJ` | JWT / base64-encoded token |
| `Bearer ` | Bearer authentication token |
| `Basic ` | Basic authentication header |
| `npm_` | npm access token |
| `pypi-` | PyPI API token |
| `SG.` | SendGrid API key |
| `xkeysib-` | Brevo (Sendinblue) API key |
| `sq0atp-` | Square access token |
| `sk_live_` | Stripe live secret key |
| `sk_test_` | Stripe test secret key |
| `pk_live_` | Stripe public live key |
| `rk_live_` | Stripe restricted live key |
| `whsec_` | Stripe webhook secret |
| `AGE-SECRET-KEY-` | age encryption key |

### 2. Secret-Sounding Environment Variable Names (High)

Flags environment variables whose names suggest they hold secrets, when combined with a non-trivial value (8+ characters):

- `PASSWORD`, `PASSWD`
- `SECRET`
- `TOKEN`
- `API_KEY`, `APIKEY`
- `ACCESS_KEY`
- `PRIVATE_KEY`
- `AUTH_TOKEN`
- `CLIENT_SECRET`
- `CREDENTIALS`
- `DATABASE_URL`
- `CONNECTION_STRING`, `CONN_STR`

### 3. Secrets in Command Arguments (Critical)

Detects known secret prefixes appearing in command-line arguments, which are visible in process listings (`ps aux`).

### Safe Value Detection

The rule ignores values that are clearly placeholders, not real secrets:

- `your-api-key-here`, `xxx`, `CHANGE_ME`, `TODO`, `FIXME`, `placeholder`
- Environment variable references: `${VAR}`, `$(VAR)`, `process.env.VAR`, `os.environ`

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuv"
      }
    }
  }
}
```

**Finding:** `Hardcoded GitHub personal access token in server 'github'` (Critical)
The value starts with `ghp_`, a known GitHub PAT prefix.

```json
{
  "mcpServers": {
    "openai": {
      "command": "node",
      "args": ["server.js", "--token", "sk-abc123def456ghi789jkl012mno345"],
      "env": {
        "OPENAI_API_KEY": "sk-abc123def456ghi789jkl012mno345"
      }
    }
  }
}
```

**Findings:**
1. `Hardcoded OpenAI API key in server 'openai'` (Critical) — secret in env var
2. `OpenAI API key exposed in command arguments of server 'openai'` (Critical) — secret in args, visible via `ps`

```json
{
  "mcpServers": {
    "database": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "MY_SECRET_TOKEN": "a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5"
      }
    }
  }
}
```

**Finding:** `Potential hardcoded secret in server 'database'` (High)
Variable name contains `SECRET` and `TOKEN`, and the value is 32 characters.

### Safe Configuration

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Uses an environment variable reference instead of a hardcoded value.

```json
{
  "mcpServers": {
    "api-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "API_KEY": "your-api-key-here",
        "NODE_ENV": "production",
        "PORT": "3000"
      }
    }
  }
}
```

Placeholder values and non-secret variables are not flagged.

## Remediation

1. **Use environment variable references** — Replace hardcoded values with `${VAR_NAME}` references that resolve at runtime.
2. **Use a secrets manager** — Store secrets in HashiCorp Vault, AWS Secrets Manager, 1Password, or your platform's native secrets store.
3. **Never commit secrets** — Add MCP config files with secrets to `.gitignore`. Use templates with placeholder values for version control.
4. **Rotate exposed secrets immediately** — If a secret was committed, consider it compromised. Revoke it and generate a new one.
5. **Avoid secrets in arguments** — Secrets passed as command arguments are visible in process listings. Always use environment variables instead.
6. **Use short-lived tokens** — Prefer short-lived, auto-rotating credentials over long-lived API keys.

## References

- [OWASP MCP Top 10: MCP-04 Insecure Credentials](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
