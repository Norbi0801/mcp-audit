# MCP-11: Denial of Service

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-11 |
| **Name** | Denial of Service |
| **Default Severity** | **Medium** |
| **OWASP Category** | [OWASP-MCP-11](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP server configurations that expose clients to denial-of-service risks: missing timeouts, unbounded response sizes, infinite streams without cancellation, and resource subscriptions without unsubscribe capability.

An MCP server that can block the client indefinitely, return arbitrarily large payloads, stream events forever, or accumulate subscriptions without cleanup can exhaust client resources (CPU, memory, network) and render the AI assistant unresponsive. These issues are especially dangerous because MCP tool invocations are typically awaited synchronously by the LLM — a single hung call can freeze the entire session.

## What It Checks

### 1. Missing Timeout Configuration (Medium)

Flags servers with no timeout configured via environment variables or command-line arguments. Without a timeout, a malicious or buggy tool can block the client indefinitely by never returning a response.

**Environment variables recognized:**

| Variable | Description |
|----------|-------------|
| `TIMEOUT`, `MCP_TIMEOUT` | General timeout |
| `REQUEST_TIMEOUT`, `RESPONSE_TIMEOUT` | Request/response timeout |
| `CONNECTION_TIMEOUT`, `SOCKET_TIMEOUT` | Connection-level timeout |
| `EXECUTION_TIMEOUT`, `TOOL_TIMEOUT` | Tool execution timeout |
| `READ_TIMEOUT`, `WRITE_TIMEOUT` | I/O timeout |
| `IDLE_TIMEOUT`, `KEEPALIVE_TIMEOUT` | Idle/keepalive timeout |
| `HTTP_TIMEOUT`, `CLIENT_TIMEOUT`, `SERVER_TIMEOUT` | HTTP-level timeout |
| `OPERATION_TIMEOUT` | Operation timeout |

**Arguments recognized:**

| Argument | Description |
|----------|-------------|
| `--timeout`, `-t` | General timeout |
| `--request-timeout`, `--response-timeout` | Request/response timeout |
| `--connection-timeout`, `--execution-timeout` | Connection/execution timeout |
| `--tool-timeout`, `--read-timeout`, `--write-timeout` | Tool/I/O timeout |
| `--idle-timeout` | Idle timeout |

### 2. Missing Response Size Limit (Medium)

Flags servers with no response size limit. A tool can return arbitrarily large payloads, exhausting client memory and causing out-of-memory crashes.

**Environment variables recognized:**

| Variable | Description |
|----------|-------------|
| `MAX_RESPONSE_SIZE`, `RESPONSE_SIZE_LIMIT` | Response size limit |
| `MAX_BODY_SIZE`, `BODY_SIZE_LIMIT` | Body size limit |
| `MAX_PAYLOAD_SIZE`, `PAYLOAD_LIMIT` | Payload size limit |
| `MAX_MESSAGE_SIZE`, `MAX_OUTPUT_SIZE` | Message/output size |
| `MAX_CONTENT_LENGTH`, `MAX_BUFFER_SIZE` | Content/buffer size |
| `MAX_RESULT_SIZE`, `SIZE_LIMIT` | Result/generic size limit |
| `MAX_TOKENS`, `OUTPUT_LIMIT` | Token/output count limit |

**Arguments recognized:**

| Argument | Description |
|----------|-------------|
| `--max-response-size`, `--max-body-size` | Response/body limit |
| `--body-limit`, `--max-payload` | Payload limit |
| `--max-message-size`, `--max-output-size` | Message/output limit |
| `--max-content-length`, `--max-buffer-size` | Content/buffer limit |
| `--size-limit`, `--payload-limit` | Generic size limit |
| `--max-tokens`, `--output-limit`, `--max-result-size` | Token/result limit |

### 3. Unbounded Streaming Without Cancellation (Medium)

Detects servers using streaming transports (SSE, WebSocket, streamable-http) that lack cancellation or stream-bounding configuration. An infinite stream can block the client forever and consume unbounded resources.

**Streaming transports detected:**

| Transport | Detection |
|-----------|-----------|
| SSE | `transport: "sse"`, URL containing `/sse` or `/events`, `--sse` arg |
| WebSocket | `transport: "websocket"` or `"ws"`, URL containing `/ws` or `/websocket` |
| Streamable HTTP | `transport: "streamable-http"`, `--stream` arg |

**Cancellation indicators recognized:**

| Pattern | Description |
|---------|-------------|
| `ENABLE_CANCELLATION`, `CANCEL_ENABLED` | Cancellation support |
| `STREAM_TIMEOUT`, `MAX_STREAM_DURATION` | Stream timeout |
| `SSE_TIMEOUT`, `STREAM_IDLE_TIMEOUT` | SSE/idle timeout |
| `MAX_EVENTS`, `MAX_STREAM_EVENTS`, `EVENT_LIMIT` | Event count limit |
| `--enable-cancellation`, `--stream-timeout` | Cancellation args |
| `--max-events`, `--event-limit` | Event limit args |

A generic timeout (from Check 1) is also accepted as partial mitigation.

### 4. Resource Subscriptions Without Unsubscribe (Medium)

Detects servers that support resource subscriptions (watch, notify, pub/sub) but have no unsubscribe or subscription management capability. Without cleanup, leaked subscriptions accumulate and exhaust resources.

**Subscription indicators:**

| Pattern | Description |
|---------|-------------|
| `--subscribe`, `--enable-subscriptions` | Subscription support |
| `--watch`, `--notify`, `--pubsub` | Watch/notify support |
| `ENABLE_SUBSCRIPTIONS`, `WATCH_ENABLED` | Subscription env vars |
| `PUBSUB_ENABLED`, `REALTIME_ENABLED` | Pub/sub env vars |

**Unsubscribe indicators:**

| Pattern | Description |
|---------|-------------|
| `--unsubscribe`, `--enable-unsubscribe` | Unsubscribe support |
| `--subscription-ttl`, `--max-subscriptions` | Subscription limits |
| `--subscription-timeout`, `--max-watchers` | Timeout/watcher limits |
| `SUBSCRIPTION_TTL`, `MAX_SUBSCRIPTIONS` | Subscription limit env vars |

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "bare-server": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}
```

**Findings:**
1. `No timeout configured for server 'bare-server'` (Medium) — Server can block the client indefinitely.
2. `No response size limit for server 'bare-server'` (Medium) — Server can return unbounded payloads.

```json
{
  "mcpServers": {
    "sse-server": {
      "url": "https://mcp.example.com/sse",
      "transport": "sse"
    }
  }
}
```

**Findings:**
1. `No timeout configured for server 'sse-server'` (Medium)
2. `No response size limit for server 'sse-server'` (Medium)
3. `Streaming server 'sse-server' has no cancellation mechanism` (Medium) — SSE transport without cancellation or stream-bounding.

```json
{
  "mcpServers": {
    "watcher": {
      "command": "node",
      "args": ["watcher-server.js", "--subscribe", "--watch"]
    }
  }
}
```

**Findings:**
1. `No timeout configured for server 'watcher'` (Medium)
2. `No response size limit for server 'watcher'` (Medium)
3. `Subscription without unsubscribe in server 'watcher'` (Medium) — Subscriptions enabled but no unsubscribe capability.

### Safe Configuration

```json
{
  "mcpServers": {
    "safe-server": {
      "command": "node",
      "args": ["server.js", "--timeout", "30000", "--max-response-size", "10485760"]
    }
  }
}
```

Timeout and response size limit configured — client is protected from indefinite blocking and memory exhaustion.

```json
{
  "mcpServers": {
    "safe-sse": {
      "url": "https://mcp.example.com/sse",
      "transport": "sse",
      "env": {
        "STREAM_TIMEOUT": "60000",
        "MAX_EVENTS": "1000",
        "MAX_RESPONSE_SIZE": "5242880",
        "REQUEST_TIMEOUT": "30000"
      }
    }
  }
}
```

Streaming server with timeout, event limit, and size limit — all DoS vectors mitigated.

```json
{
  "mcpServers": {
    "safe-watcher": {
      "command": "node",
      "args": [
        "watcher-server.js",
        "--subscribe",
        "--enable-unsubscribe",
        "--max-subscriptions", "100",
        "--timeout", "30000",
        "--max-response-size", "1048576"
      ]
    }
  }
}
```

Subscriptions with unsubscribe capability and subscription limits.

## Remediation

1. **Configure timeouts** — Set a request timeout on every MCP server (`--timeout`, `REQUEST_TIMEOUT`). 30 seconds is a reasonable default for most tools; increase for known long-running operations.
2. **Set response size limits** — Configure `MAX_RESPONSE_SIZE` or `--max-response-size` to prevent a single tool response from exhausting client memory. 10 MB is a reasonable upper bound.
3. **Bound streams** — For SSE, WebSocket, or streamable-http servers, configure `--enable-cancellation` and set a `STREAM_TIMEOUT` or `MAX_EVENTS` limit to prevent infinite streams.
4. **Manage subscriptions** — If the server supports resource subscriptions, always enable unsubscribe (`--enable-unsubscribe`) and set limits (`--max-subscriptions`, `--subscription-ttl`) to prevent resource leaks.
5. **Use circuit breakers** — Implement client-side circuit breakers that terminate connections after repeated timeouts or excessive data transfer.
6. **Monitor resource usage** — Track memory and connection counts for MCP servers to detect runaway resource consumption early.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-835: Loop with Unreachable Exit Condition (Infinite Loop)](https://cwe.mitre.org/data/definitions/835.html)
- [MCP Specification — Cancellation](https://modelcontextprotocol.io/specification/2025-03-26/basic/cancellation)
- [MCP Specification — Transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)
