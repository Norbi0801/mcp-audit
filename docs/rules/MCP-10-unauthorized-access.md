# MCP-10: Unauthorized Access

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-10 |
| **Name** | Unauthorized Access |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-10](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers with missing or weakened authentication, disabled auth configurations, and development mode settings that bypass security controls.

HTTP-based MCP servers (using SSE or streamable-http transport) expose network endpoints that must be authenticated. Without proper authentication, any network-reachable client can connect and issue tool calls. This rule also detects configurations where authentication has been explicitly disabled, development mode is enabled (which often weakens security), and privilege escalation patterns that grant the server excessive system access.

## What It Checks

### 1. Authentication Bypass Arguments (High)

Detects command-line flags that disable or weaken authentication:

| Flag | Effect |
|------|--------|
| `--no-auth` | Disables authentication |
| `--disable-auth` | Disables authentication |
| `--skip-auth` | Skips authentication |
| `--insecure` | Disables security checks |
| `--allow-anonymous` | Allows unauthenticated access |
| `--no-verify` | Disables verification |
| `--no-ssl-verify` | Disables SSL certificate verification |
| `--skip-ssl` | Skips SSL verification |
| `--dev` | Enables development mode |
| `--development` | Enables development mode |
| `--unsafe` | Enables unsafe mode |

### 2. Authentication Disabled via Environment (Critical)

Detects environment variables that explicitly disable authentication:

| Variable | Disabling Values |
|----------|-----------------|
| `AUTH_DISABLED` | `true`, `1`, `yes` |
| `DISABLE_AUTH` | `true`, `1`, `yes` |
| `NO_AUTH` | `true`, `1`, `yes` |
| `SKIP_AUTH` | `true`, `1`, `yes` |
| `AUTH_ENABLED` | `false`, `0`, `no` |
| `REQUIRE_AUTH` | `false`, `0`, `no` |
| `AUTH_REQUIRED` | `false`, `0`, `no` |
| `SKIP_VERIFICATION` | `true`, `1`, `yes` |
| `VERIFY_TOKEN` | `false`, `0`, `no` |
| `INSECURE` | `true`, `1`, `yes` |

### 3. Development Mode (Medium)

Detects environment variables indicating development/debug mode, which often disables security features:

| Variable | Development Values |
|----------|-------------------|
| `NODE_ENV` | `development`, `dev`, `test` |
| `ENVIRONMENT` | `development`, `dev`, `test`, `staging` |
| `ENV` | `development`, `dev`, `test` |
| `DEBUG_MODE` | `true`, `1`, `yes` |
| `DEV_MODE` | `true`, `1`, `yes` |
| `DEVELOPMENT` | `true`, `1`, `yes` |

### 4. HTTP Server Without Authentication (High)

Flags HTTP-based MCP servers (with a `url` field) that have no auth-related environment variables or arguments. The rule looks for environment variable names containing:
`AUTH`, `TOKEN`, `API_KEY`, `BEARER`, `SECRET`

And arguments containing:
`--auth`, `--token`, `--api-key`, `--bearer`

### 5. Privilege Escalation Commands (Critical)

Detects commands that run with elevated privileges:
- `sudo`
- `doas`
- `su`

### 6. Container Privilege Escalation (High)

Detects Docker/container flags that grant elevated privileges:
- `--privileged`
- `--cap-add`
- `--security-opt`

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "open-server": {
      "url": "https://api.example.com/mcp",
      "transport": "sse",
      "env": {
        "AUTH_DISABLED": "true",
        "NODE_ENV": "development"
      }
    }
  }
}
```

**Findings:**
1. `Authentication disabled in server 'open-server'` (Critical) — `AUTH_DISABLED=true` explicitly disables auth.
2. `Development mode enabled in server 'open-server'` (Medium) — `NODE_ENV=development` may weaken security.

```json
{
  "mcpServers": {
    "no-auth-server": {
      "command": "node",
      "args": ["server.js", "--no-auth", "--insecure"]
    }
  }
}
```

**Findings:**
1. `Authentication bypass flag in server 'no-auth-server'` (High) — `--no-auth` disables authentication.
2. `Authentication bypass flag in server 'no-auth-server'` (High) — `--insecure` disables security checks.

```json
{
  "mcpServers": {
    "privileged-server": {
      "command": "sudo",
      "args": ["node", "server.js"]
    }
  }
}
```

**Finding:** `Privilege escalation command in server 'privileged-server'` (Critical)
Server runs with root privileges via `sudo`.

```json
{
  "mcpServers": {
    "docker-server": {
      "command": "docker",
      "args": ["run", "--privileged", "mcp-server-image"]
    }
  }
}
```

**Finding:** `Container privilege escalation in server 'docker-server'` (High)
The `--privileged` flag grants full host access to the container.

```json
{
  "mcpServers": {
    "http-no-auth": {
      "url": "https://api.example.com/mcp",
      "transport": "sse"
    }
  }
}
```

**Finding:** `No authentication for HTTP server 'http-no-auth'` (High)
HTTP endpoint has no auth configuration, allowing any client to connect.

### Safe Configuration

```json
{
  "mcpServers": {
    "production-api": {
      "url": "https://api.example.com/mcp",
      "transport": "sse",
      "env": {
        "API_KEY": "${MCP_API_KEY}",
        "NODE_ENV": "production"
      }
    }
  }
}
```

HTTPS endpoint with API key authentication and production mode enabled.

```json
{
  "mcpServers": {
    "local-server": {
      "command": "node",
      "args": ["server.js", "--port", "3000"],
      "env": {
        "NODE_ENV": "production",
        "AUTH_TOKEN": "${AUTH_TOKEN}"
      }
    }
  }
}
```

Direct execution (no sudo), production mode, authentication configured.

## Remediation

1. **Enable authentication** — Configure API keys, JWT tokens, or OAuth for all HTTP-based MCP servers.
2. **Remove bypass flags** — Remove `--no-auth`, `--insecure`, `--allow-anonymous`, and `--dev` from production configurations.
3. **Use production settings** — Set `NODE_ENV=production` and `ENVIRONMENT=production` in all non-development environments.
4. **Remove auth-disabled variables** — Remove or set to `false` any `AUTH_DISABLED`, `DISABLE_AUTH`, `NO_AUTH`, or `SKIP_AUTH` variables.
5. **Avoid privilege escalation** — Never use `sudo`, `doas`, or `su` to run MCP servers. Configure proper file permissions and user accounts instead.
6. **Use minimal container privileges** — Avoid `--privileged`. Use `--cap-drop=ALL` and selectively add only required capabilities.
7. **Implement network segmentation** — Restrict which network clients can reach the MCP server endpoint.
8. **Use mTLS** — For server-to-server MCP connections, implement mutual TLS for strong bidirectional authentication.

## References

- [OWASP MCP Top 10: MCP-10 Unauthorized Access](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
