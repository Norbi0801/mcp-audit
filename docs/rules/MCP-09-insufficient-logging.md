# MCP-09: Insufficient Logging & Monitoring

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-09 |
| **Name** | Insufficient Logging & Monitoring |
| **Default Severity** | Medium |
| **OWASP Category** | [OWASP-MCP-09](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers without logging configuration, with logging explicitly disabled, or lacking audit trail capabilities.

Without proper logging and monitoring, security incidents involving MCP servers go undetected. An attacker exploiting a vulnerability — whether data exfiltration, command injection, or unauthorized access — leaves no trace if logging is disabled. Incident response becomes impossible when there is no audit trail of which tools were called, what data was accessed, and what actions were performed. This rule ensures MCP servers maintain visibility into their operations.

## What It Checks

### 1. Explicitly Disabled Logging (High)

Detects arguments that suppress log output:

| Flag | Effect |
|------|--------|
| `--no-log` | Disables logging |
| `--no-logging` | Disables logging |
| `--quiet` | Suppresses output |
| `-q` | Suppresses output |
| `--silent` | Suppresses all output |
| `--no-audit` | Disables audit logging |
| `--disable-logging` | Disables logging |
| `--disable-audit` | Disables audit logging |

### 2. Logging Disabled via Environment (High)

Detects environment variable values that explicitly disable logging:

| Variable | Disabling Values |
|----------|-----------------|
| `LOG_LEVEL` | `off`, `none`, `silent` |
| `LOGGING` | `false`, `0`, `off` |
| `AUDIT_LOG` | `false`, `0`, `off` |
| `DEBUG` | `false`, `0` |

### 3. Missing Logging Configuration (Low)

Flags servers that have neither logging environment variables nor logging arguments.

**Recognized logging environment variables:**

| Variable | Purpose |
|----------|---------|
| `LOG_LEVEL` | Log verbosity level |
| `LOG_FILE` | Log file path |
| `LOG_DIR` | Log directory |
| `LOG_PATH` | Log file path |
| `LOGGING` | Logging toggle |
| `DEBUG` | Debug mode |
| `VERBOSE` | Verbose output |
| `TRACE` | Trace logging |
| `RUST_LOG` | Rust env_logger filter |
| `NODE_DEBUG` | Node.js debug modules |
| `SENTRY_DSN` | Sentry error tracking |
| `DATADOG_API_KEY` | Datadog monitoring |
| `NEW_RELIC_LICENSE_KEY` | New Relic APM |
| `SPLUNK_TOKEN` | Splunk logging |
| `ELASTIC_APM_SERVER_URL` | Elastic APM |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry endpoint |
| `OTEL_SERVICE_NAME` | OpenTelemetry service name |
| `AUDIT_LOG` | Audit logging toggle |

**Recognized logging arguments:**
`--log`, `--log-level`, `--log-file`, `--log-dir`, `--verbose`, `-v`, `-vv`, `-vvv`, `--debug`, `--trace`, `--audit`, `--audit-log`

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "silent-server": {
      "command": "node",
      "args": ["server.js", "--silent"],
      "env": {
        "LOG_LEVEL": "off"
      }
    }
  }
}
```

**Findings:**
1. `Logging explicitly disabled in server 'silent-server'` (High) — `--silent` flag suppresses all output.
2. `Logging disabled via environment in server 'silent-server'` (High) — `LOG_LEVEL=off` disables logging.

```json
{
  "mcpServers": {
    "bare-server": {
      "command": "node",
      "args": ["server.js", "--port", "3000"]
    }
  }
}
```

**Finding:** `No logging configuration in server 'bare-server'` (Low)
No logging environment variables or arguments detected.

### Safe Configurations

```json
{
  "mcpServers": {
    "logged-server": {
      "command": "node",
      "args": ["server.js", "--log-level", "info", "--audit-log"],
      "env": {
        "LOG_LEVEL": "info",
        "SENTRY_DSN": "${SENTRY_DSN}"
      }
    }
  }
}
```

Logging configured at `info` level with audit logging enabled and Sentry error tracking.

```json
{
  "mcpServers": {
    "otel-server": {
      "command": "node",
      "args": ["server.js", "--verbose"],
      "env": {
        "OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.com:4317",
        "OTEL_SERVICE_NAME": "mcp-server"
      }
    }
  }
}
```

OpenTelemetry configured for distributed tracing and monitoring.

## Remediation

1. **Enable logging** — Configure `LOG_LEVEL=info` (or `debug` for development) as an environment variable.
2. **Enable audit logging** — Use `--audit-log` or `AUDIT_LOG=true` to track security-relevant events (tool calls, data access, errors).
3. **Remove suppression flags** — Remove `--silent`, `--quiet`, `-q`, and `--no-log` flags from production configurations.
4. **Use a monitoring service** — Integrate with Sentry, Datadog, New Relic, Splunk, Elastic APM, or OpenTelemetry for centralized monitoring and alerting.
5. **Log to persistent storage** — Use `--log-file` or `LOG_FILE` to write logs to disk, ensuring they survive process restarts.
6. **Set up alerts** — Configure alerts for error spikes, unusual tool call patterns, and access to sensitive resources.
7. **Retain logs** — Maintain logs for at least 90 days for incident investigation and compliance.

## References

- [OWASP MCP Top 10: MCP-09 Insufficient Logging & Monitoring](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
