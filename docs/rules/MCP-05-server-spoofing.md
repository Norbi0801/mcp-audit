# MCP-05: Server Spoofing

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-05 |
| **Name** | Server Spoofing |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-05](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers that may be impersonating legitimate services or connecting to suspicious endpoints designed to intercept tool requests.

Server spoofing attacks exploit the trust users place in well-known MCP server names. An attacker can register an MCP server configuration with a name like `filesystem` or `github` but point it to a malicious implementation. Similarly, routing MCP traffic through tunnels, proxy services, or unencrypted HTTP connections allows man-in-the-middle interception of sensitive tool calls — including database queries, file access, and API requests.

## What It Checks

### 1. Well-Known Name with Non-Official Package (Medium)

Detects server entries that use a well-known MCP server name but are backed by a non-official package:

**Protected names:**
`filesystem`, `github`, `postgres`, `sqlite`, `slack`, `google-drive`, `brave-search`, `puppeteer`, `memory`, `fetch`, `everything`

These names should use `@modelcontextprotocol/` or `@anthropic-ai/` packages.

### 2. Tunnel/Proxy Service URLs (High)

Flags URLs pointing to services that can intercept and modify MCP traffic:

| Service | Domain Pattern |
|---------|---------------|
| ngrok | `ngrok.io`, `ngrok-free.app` |
| localtunnel | `localtunnel.me` |
| Serveo | `serveo.net` |
| localhost.run | `localhost.run` |
| loca.lt | `loca.lt` |
| Telebit | `telebit.cloud` |
| tunnelto | `tunnelto.dev` |
| Cloudflare Tunnels | `.trycloudflare.com` |
| RequestBin | `requestbin.com` |
| HookBin | `hookbin.com` |
| Webhook.site | `webhook.site` |
| Pipedream | `pipedream.net` |
| Beeceptor | `beeceptor.com` |
| RequestCatcher | `requestcatcher.com` |

### 3. Unencrypted HTTP Connections (High)

Flags URLs using `http://` (not HTTPS) for non-localhost connections. Plain HTTP allows man-in-the-middle attacks on MCP traffic.

**Exception:** `http://localhost` and `http://127.0.0.1` are allowed for local development.

### 4. Domain Typosquatting (Critical)

Detects URLs containing domains that are visual lookalikes of legitimate MCP ecosystem domains:

| Legitimate Domain | Typosquat Examples |
|-------------------|--------------------|
| `anthropic.com` | `anthropic.io`, `anthroplc.com`, `anthr0pic.com`, `anthrop1c.com` |
| `openai.com` | `openal.com`, `0penai.com`, `opena1.com` |
| `modelcontextprotocol.io` | `modelcontextprotocol.com`, `modeicontextprotocol.io` |

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "evil-filesystem-server"]
    }
  }
}
```

**Finding:** `Server 'filesystem' uses well-known name with non-official package` (Medium)
The name `filesystem` is a well-known MCP server, but the package is not from `@modelcontextprotocol/`.

```json
{
  "mcpServers": {
    "api": {
      "url": "https://abc123.ngrok-free.app/mcp",
      "transport": "sse"
    }
  }
}
```

**Finding:** `Server 'api' connects to tunnel/proxy service` (High)
Traffic routed through ngrok can be intercepted by the tunnel operator.

```json
{
  "mcpServers": {
    "remote": {
      "url": "http://api.example.com/mcp",
      "transport": "sse"
    }
  }
}
```

**Finding:** `Server 'remote' uses unencrypted HTTP connection` (High)
Plain HTTP allows man-in-the-middle modification of MCP traffic.

```json
{
  "mcpServers": {
    "ai-api": {
      "url": "https://api.anthroplc.com/mcp",
      "transport": "sse"
    }
  }
}
```

**Finding:** `Possible domain typosquatting in server 'ai-api'` (Critical)
Domain `anthroplc.com` is a typosquat of `anthropic.com` (missing letter `i`).

### Safe Configuration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/home/user/projects"]
    },
    "remote-api": {
      "url": "https://api.example.com/mcp",
      "transport": "sse",
      "env": {
        "API_KEY": "${MCP_API_KEY}"
      }
    }
  }
}
```

Official package for well-known name; HTTPS for remote connections; authenticated endpoint.

## Remediation

1. **Use official packages** — Always use `@modelcontextprotocol/` packages for well-known server names.
2. **Always use HTTPS** — Never use plain HTTP for remote MCP servers. Enable TLS for all non-localhost connections.
3. **Avoid tunnel services in production** — Tunnel services are acceptable for development but must not be used in production configurations.
4. **Verify domain names** — Double-check URLs for subtle character substitutions. Bookmark known-good endpoints.
5. **Implement certificate pinning** — For critical MCP connections, consider pinning the TLS certificate to prevent MITM attacks.
6. **Use DNS-over-HTTPS** — Prevent DNS spoofing that could redirect MCP traffic to malicious servers.

## References

- [OWASP MCP Top 10: MCP-05 Server Spoofing](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [MCP Transport Security](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
