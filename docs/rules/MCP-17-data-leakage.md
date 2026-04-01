# MCP-17: Data Leakage

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-17 |
| **Name** | Data Leakage |
| **Default Severity** | **Critical** |
| **OWASP Category** | [OWASP-MCP-17](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers that risk leaking sensitive data through tool outputs, resource responses, or logging. Checks for tools that return environment variables, secrets, or API keys; resources that expose credential files; missing output redaction; and debug/verbose modes that may dump sensitive data.

MCP tool outputs are sent to the LLM conversation context, where they may be visible to the user, forwarded to other tools, or stored in conversation logs. A tool that returns raw secrets, credentials, or PII creates a data leakage path that can be exploited by prompt injection attacks or simply by asking the right question.

## What It Checks

### 1. Sensitive Tool Names (Critical)

Flags tools whose names directly indicate they return sensitive data:

| Category | Tool Name Patterns |
|----------|-------------------|
| Environment variables | `get_env`, `get_environment`, `list_env`, `read_env`, `dump_env`, `env_vars`, `printenv` |
| Secrets | `get_secrets`, `list_secrets`, `read_secrets`, `dump_secrets` |
| Credentials | `get_credentials`, `list_credentials`, `read_credentials`, `dump_credentials` |
| API keys / tokens | `get_api_keys`, `list_api_keys`, `get_tokens`, `list_tokens` |
| Configuration | `get_config`, `dump_config`, `show_config` |
| Passwords | `get_password`, `get_passwords` |
| Private keys | `read_private_key`, `get_private_key` |
| Database | `dump_database`, `export_database`, `get_connection_string` |
| Identity / PII | `whoami`, `get_identity`, `get_user_data`, `export_users`, `dump_users`, `list_users` |

Detection is case-insensitive and matches both exact names and substrings.

### 2. Leakage Keywords in Tool Descriptions (Critical)

Detects keywords in tool descriptions indicating the tool returns sensitive data:

| Category | Keywords |
|----------|----------|
| Environment variables | `return environment variable`, `return env var`, `return all env` |
| Secrets | `output secret`, `returns secret`, `return secret` |
| API keys | `return api key`, `output api key` |
| Tokens | `return token`, `output token` |
| Passwords | `return password` |
| Credentials | `return credential`, `display credential` |
| Private keys | `return private key`, `show private key`, `output private key` |
| Unfiltered output | `dump all`, `dump everything`, `raw output`, `unfiltered output` |
| Missing redaction | `without redact`, `without mask`, `no redact`, `no sanitiz`, `no filter` |
| Plain text secrets | `plain text secret`, `plaintext password` |
| Included secrets | `include secret`, `include credential` |
| PII | `personal data`, `personally identifiable`, `social security`, `credit card`, `bank account` |

### 3. Sensitive Resource URIs (Critical)

Detects server arguments that reference sensitive file patterns as resources:

| Category | Patterns |
|----------|----------|
| Environment files | `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development` |
| Git internals | `.git/config`, `.git/credentials` |
| SSH keys | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa` |
| Certificates/keys | `.pem`, `.key`, `.p12`, `.pfx`, `.keystore`, `.jks` |
| Package credentials | `.npmrc`, `.pypirc`, `.netrc` |
| Database credentials | `.pgpass`, `.my.cnf` |
| Application credentials | `credentials.json`, `credentials.yaml`, `service-account.json` |
| Application secrets | `secrets.json`, `secrets.yaml`, `secrets.yml` |
| Cloud credentials | `.aws/credentials`, `.aws/config`, `.docker/config.json`, `.kube/config` |
| Auth files | `htpasswd`, `shadow`, `vault-token`, `token.json`, `auth.json` |

### 4. Verbose/Debug Output (High)

Detects server configurations with verbose or debug output modes that may dump sensitive data:

| Pattern | Risk |
|---------|------|
| `--verbose`, `-vvv` | Verbose output may include secrets |
| `--debug` | Debug mode may output secrets and tokens |
| `--log-level=debug`, `--log-level=trace` | Debug/trace logging may include sensitive data |
| `LOG_LEVEL=debug`, `LOG_LEVEL=trace` | Debug/trace logging via env var |
| `DEBUG=*`, `DEBUG=true` | Debug wildcard/flag logs everything |
| `--dump-headers`, `--show-headers` | HTTP headers may contain auth tokens |
| `--print-env`, `--dump-env` | Prints/dumps environment variables |
| `--expose-secrets`, `--no-redact`, `--no-mask` | Explicitly disables redaction |
| `--raw-output`, `--include-secrets` | Raw/unfiltered output |

### 5. Secret Environment Variable Passthrough (High)

Detects when secret-named environment variables are passed to the server, as the server could inadvertently echo them back in tool output:

| Pattern | Description |
|---------|-------------|
| `PASSWORD`, `PASSWD` | Password values |
| `SECRET`, `PRIVATE_KEY` | Secret/key values |
| `ACCESS_KEY`, `SECRET_KEY` | Cloud access keys |
| `API_KEY`, `APIKEY` | API keys |
| `AUTH_TOKEN`, `CLIENT_SECRET` | Auth tokens/secrets |
| `MASTER_KEY`, `ENCRYPTION_KEY` | Encryption keys |
| `SIGNING_KEY`, `JWT_SECRET` | Signing/JWT secrets |
| `SESSION_SECRET`, `COOKIE_SECRET` | Session secrets |

Values that appear to be references (e.g., `${VAR}`, `process.env.VAR`, `placeholder`) are excluded.

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "debug-server": {
      "command": "node",
      "args": ["server.js", "--verbose", "--debug"],
      "env": {
        "API_KEY": "sk-live-abc123",
        "DATABASE_PASSWORD": "supersecret"
      },
      "tools": [
        {
          "name": "get_env",
          "description": "Returns all environment variables"
        }
      ]
    }
  }
}
```

**Findings:**
1. `Tool 'get_env' in server 'debug-server' may leak sensitive data` (Critical) — Tool name indicates it returns environment variables.
2. `Tool 'get_env' description indicates data leakage risk` (Critical) — Description says it returns environment variables.
3. `Server 'debug-server' verbose/debug output risk` (High) — `--verbose` and `--debug` flags may dump secrets.
4. `Server 'debug-server' passes secret environment variables` (High) — `API_KEY` and `DATABASE_PASSWORD` could be echoed.

```json
{
  "mcpServers": {
    "file-server": {
      "command": "npx",
      "args": ["-y", "server-filesystem", "/app/.env"]
    }
  }
}
```

**Finding:** `Server 'file-server' may expose environment file as a resource` (Critical) — `.env` file contains secrets.

### Safe Configuration

```json
{
  "mcpServers": {
    "safe-server": {
      "command": "node",
      "args": ["server.js", "--log-level", "warn", "--redact-secrets"],
      "env": {
        "API_KEY": "${API_KEY}",
        "LOG_LEVEL": "warn"
      },
      "tools": [
        {
          "name": "get_status",
          "description": "Returns the system health status without sensitive details"
        }
      ]
    }
  }
}
```

No sensitive tool names, no verbose/debug output, env vars use references, and logging is at warn level.

## Remediation

1. **Redact secrets from tool output** — Never return raw API keys, passwords, tokens, or private keys in tool responses. Mask values (e.g., `sk-****abc123`).
2. **Avoid sensitive tool names** — Do not create tools named `get_env`, `dump_secrets`, etc. Use purpose-specific names that describe the actual operation.
3. **Exclude sensitive files from resources** — Do not expose `.env`, `.git/`, SSH keys, or credential files through MCP resource servers. Use deny-lists and access controls.
4. **Disable debug/verbose mode in production** — Use `warn` or `error` log levels. Never use `--debug`, `--verbose`, or `LOG_LEVEL=trace` in production configurations.
5. **Use environment variable references** — Pass secrets via runtime references (`${API_KEY}`) rather than hardcoded values in configuration files.
6. **Implement output filtering** — Add server-side output filters that scan responses for patterns matching secrets (API key prefixes, JWT tokens, etc.) and redact them.
7. **Minimize env var passthrough** — Only pass environment variables that the server actually needs. Avoid passing `PASSWORD`, `SECRET`, `API_KEY` unless required.
8. **Audit tool descriptions** — Review all tool descriptions for language suggesting they return sensitive data. Rewrite to describe the operation without mentioning secrets.
9. **Sanitize PII** — Tools that access user data should redact or pseudonymize PII (emails, SSNs, credit card numbers) before returning results.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-215: Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [MCP Specification — Tools](https://modelcontextprotocol.io/specification/2025-03-26/server/tools)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
