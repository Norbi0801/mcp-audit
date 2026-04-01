# MCP-14: Insecure Transport

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-14 |
| **Name** | Insecure Transport |
| **Default Severity** | **High** |
| **OWASP Category** | [OWASP-MCP-14](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects insecure transport configurations on HTTP-based MCP servers: plain HTTP without TLS encryption, disabled TLS certificate verification, missing authentication on HTTP endpoints, absent rate limiting, and overly permissive CORS configuration (Access-Control-Allow-Origin: *).

HTTP-based MCP servers communicate over the network, making them vulnerable to eavesdropping, credential theft, man-in-the-middle attacks, and unauthorized access if transport security is not properly configured. Unlike stdio-based servers which communicate through local process pipes, HTTP servers are exposed to network-level threats.

## What It Checks

### 1. Plain HTTP Without TLS (High)

Detects remote MCP servers using `http://` instead of `https://`. Unencrypted HTTP exposes all tool invocations, parameters, and responses to network eavesdroppers.

Local addresses (`localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`) are excluded from this check.

### 2. Disabled TLS Certificate Verification (High)

Detects environment variables and command-line arguments that disable TLS/SSL certificate verification, allowing man-in-the-middle attacks even when HTTPS is used.

**Environment variables:**

| Variable | Disabling Value | Description |
|----------|----------------|-------------|
| `NODE_TLS_REJECT_UNAUTHORIZED` | `0` | Node.js TLS verification disabled |
| `PYTHONHTTPSVERIFY` | `0` | Python HTTPS verification disabled |
| `SSL_VERIFY`, `VERIFY_SSL` | `false` | SSL verification disabled |
| `TLS_VERIFY`, `VERIFY_TLS` | `false` | TLS verification disabled |
| `SSL_CERT_VERIFY` | `false` | SSL cert verification disabled |
| `REQUESTS_CA_BUNDLE` | *(empty)* | Python requests CA bundle cleared |
| `CURL_CA_BUNDLE` | *(empty)* | cURL CA bundle cleared |
| `GIT_SSL_NO_VERIFY` | `true` | Git SSL verification disabled |
| `SSL_NO_VERIFY` | `true` | SSL verification disabled |
| `DISABLE_TLS`, `NO_TLS` | `true` | TLS explicitly disabled |
| `INSECURE_SKIP_VERIFY` | `true` | Go-style TLS skip |

**Command-line arguments:**

| Argument | Description |
|----------|-------------|
| `--no-tls-verify`, `--no-ssl-verify` | Disables TLS/SSL verification |
| `--no-check-certificate` | Disables certificate verification |
| `--insecure-skip-tls-verify` | Skips TLS verification |
| `--disable-tls`, `--no-tls` | Disables TLS |
| `--ssl=false`, `--tls=false` | Disables SSL/TLS |
| `--skip-ssl-validation`, `--skip-tls-verify` | Skips SSL/TLS validation |
| `--allow-insecure` | Allows insecure connections |
| `-k` | Disables certificate verification (curl-style) |

### 3. Missing Authentication on HTTP Transport (High)

Flags HTTP-based MCP servers that lack any form of authentication. Without authentication, anyone who can reach the endpoint can invoke tools and access resources.

**Authentication indicators recognized:**

| Category | Patterns |
|----------|----------|
| Environment variables | `AUTH`, `TOKEN`, `API_KEY`, `APIKEY`, `BEARER`, `SECRET` |
| Environment variables | `AUTHORIZATION`, `ACCESS_KEY`, `CREDENTIAL`, `PASSWORD`, `PASSPHRASE` |
| Arguments | `--auth`, `--token`, `--api-key`, `--bearer`, `--authorization` |
| Arguments | `--access-key`, `--credential`, `--password`, `--secret`, `--header` |
| URL-based | Basic auth in URL (`http://user:pass@host`) |

This check only applies to HTTP-based servers (not stdio).

### 4. Missing Rate Limiting on HTTP Transport (Medium)

Flags HTTP-based MCP servers without rate limiting configuration. Without rate limiting, the endpoint is vulnerable to abuse, resource exhaustion, and brute-force attacks.

**Rate limiting indicators recognized:**

| Category | Patterns |
|----------|----------|
| Environment variables | `RATE_LIMIT`, `MAX_REQUESTS`, `REQUESTS_PER_SECOND`, `REQUESTS_PER_MINUTE` |
| Environment variables | `THROTTLE`, `MAX_RPS`, `MAX_RPM`, `CONCURRENT_LIMIT`, `BURST_LIMIT` |
| Arguments | `--rate-limit`, `--max-requests`, `--throttle`, `--max-rps`, `--max-rpm` |
| Arguments | `--burst-limit`, `--max-burst`, `--concurrent-limit` |

This check only applies to HTTP-based servers.

### 5. CORS Wildcard Origin (High)

Detects CORS configuration with a wildcard origin (`*`), which allows any website to make cross-origin requests to the MCP server, enabling browser-based CSRF and data exfiltration attacks.

**CORS indicators checked:**

| Category | Patterns |
|----------|----------|
| Environment variables | `CORS_ORIGIN`, `CORS_ORIGINS`, `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_ORIGIN` |
| Environment variables | `ACCESS_CONTROL_ALLOW_ORIGIN`, `ALLOWED_ORIGINS`, `CORS` |
| Arguments | `--cors-origin`, `--cors-origins`, `--cors-allowed-origins`, `--cors` |

Only flagged when the value is `*` (wildcard).

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "remote-tools": {
      "url": "http://mcp.example.com/api"
    }
  }
}
```

**Findings:**
1. `Plain HTTP transport without TLS in server 'remote-tools'` (High) — Unencrypted connection to a remote server.
2. `No authentication on HTTP transport for server 'remote-tools'` (High) — No auth configured.
3. `No rate limiting on HTTP transport for server 'remote-tools'` (Medium) — No rate limiting.

```json
{
  "mcpServers": {
    "insecure-node": {
      "url": "https://mcp.example.com/api",
      "env": {
        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
      }
    }
  }
}
```

**Finding:** `TLS verification disabled in server 'insecure-node'` (High) — Setting `NODE_TLS_REJECT_UNAUTHORIZED=0` disables certificate verification, allowing MITM attacks.

```json
{
  "mcpServers": {
    "cors-open": {
      "url": "https://mcp.example.com/api",
      "env": {
        "CORS_ORIGIN": "*",
        "API_KEY": "sk-abc123"
      }
    }
  }
}
```

**Finding:** `CORS wildcard origin in server 'cors-open'` (High) — Any website can make cross-origin requests to this MCP server.

### Safe Configuration

```json
{
  "mcpServers": {
    "secure-api": {
      "url": "https://mcp.example.com/api",
      "env": {
        "API_KEY": "sk-abc123",
        "RATE_LIMIT": "100",
        "CORS_ORIGIN": "https://myapp.example.com"
      }
    }
  }
}
```

HTTPS with authentication, rate limiting, and restricted CORS origin.

```json
{
  "mcpServers": {
    "local-dev": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

Local HTTP is acceptable — `localhost` is excluded from the plain HTTP check because the traffic doesn't leave the machine.

## Remediation

1. **Use HTTPS for all remote endpoints** — Never use `http://` for MCP servers accessible over a network. Use `https://` with a valid TLS certificate.
2. **Do not disable TLS verification** — Remove `NODE_TLS_REJECT_UNAUTHORIZED=0`, `--no-tls-verify`, and similar flags. If you have certificate issues, fix them properly with valid CA certificates.
3. **Configure authentication** — Set up API key, bearer token, or other authentication mechanism on every HTTP-based MCP server. Use environment variables to pass credentials securely.
4. **Enable rate limiting** — Configure `RATE_LIMIT`, `MAX_REQUESTS`, or equivalent to prevent abuse and brute-force attacks.
5. **Restrict CORS origins** — Never use `CORS_ORIGIN=*`. Specify exact trusted origins (e.g., `https://myapp.example.com`).
6. **Use mutual TLS (mTLS)** — For high-security deployments, configure client certificate authentication in addition to server TLS.
7. **Rotate credentials regularly** — API keys and tokens used for MCP server authentication should be rotated on a schedule.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [MCP Specification — Transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
