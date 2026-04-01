# MCP-03: Prompt Injection via Tools

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-03 |
| **Name** | Prompt Injection via Tools |
| **Default Severity** | High |
| **OWASP Category** | [OWASP-MCP-03](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP servers that may be vulnerable to prompt injection through unsanitized tool inputs, dynamic templates, or user-controlled environment variables.

Prompt injection in the MCP context occurs when user-supplied data flows unvalidated into tool descriptions, arguments, or system prompts that influence AI model behavior. An attacker can craft malicious input that overrides the model's instructions, causing it to execute unintended tool calls, exfiltrate data, or bypass safety controls. Because MCP tools run with real system privileges, a successful injection can escalate from text manipulation to actual system compromise.

## What It Checks

### 1. Template Interpolation in Arguments (High)

Detects template syntax in server arguments that may process user input:

| Syntax | Template Engine |
|--------|----------------|
| `${...}` | Shell / JavaScript template literals |
| `$(...)` | Shell command substitution |
| `{{...}}` | Handlebars / Jinja2 / Mustache |
| `{%...%}` | Jinja2 control blocks |
| `<%= ... %>` | ERB (Ruby) |
| `<%- ... %>` | ERB (unescaped) |
| `#{...}` | Ruby string interpolation |

### 2. Dynamic Input Environment Variables (Medium)

Flags environment variable names that suggest user-controlled input is passed to the server:

- `USER_INPUT`
- `PROMPT`
- `QUERY`
- `MESSAGE`
- `USER_MESSAGE`
- `CHAT_INPUT`
- `REQUEST_BODY`
- `PAYLOAD`

### 3. Raw Standard Input (Medium)

Detects arguments that accept raw, unsanitized input from stdin:

- `--stdin`
- `-` (bare dash, stdin redirect)
- `/dev/stdin`
- `--interactive`
- `-i`

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "template-server": {
      "command": "node",
      "args": ["server.js", "--template", "${USER_INPUT}"]
    }
  }
}
```

**Finding:** `Template interpolation in server 'template-server' arguments` (High)
Shell interpolation syntax in arguments allows user input to be injected into command execution.

```json
{
  "mcpServers": {
    "dynamic-server": {
      "command": "node",
      "args": ["server.js"],
      "env": {
        "USER_INPUT": "What would you like to search?",
        "PROMPT": "You are a helpful assistant"
      }
    }
  }
}
```

**Finding:** `Dynamic input variable in server 'dynamic-server'` (Medium)
Environment variables suggest user-controlled input flows into the server.

```json
{
  "mcpServers": {
    "stdin-server": {
      "command": "node",
      "args": ["server.js", "--stdin"]
    }
  }
}
```

**Finding:** `Raw stdin input in server 'stdin-server'` (Medium)
The `--stdin` argument accepts raw input that may not be sanitized.

### Safe Configuration

```json
{
  "mcpServers": {
    "safe-server": {
      "command": "node",
      "args": ["server.js", "--port", "3000"],
      "env": {
        "NODE_ENV": "production",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

No template syntax, no dynamic input variables, no stdin arguments.

## Remediation

1. **Validate and sanitize all inputs** — Never pass raw user input to tool arguments or templates. Implement allow-lists for expected input patterns.
2. **Avoid template interpolation** — Do not use `${...}`, `{{...}}`, or other template syntax in server arguments. Pass static values and let the server validate input at runtime.
3. **Use structured input** — Replace raw stdin or free-text environment variables with structured, typed input mechanisms.
4. **Implement input boundaries** — Use MCP's tool input schemas to enforce type constraints and value ranges.
5. **Separate data from instructions** — Ensure user data cannot influence system prompts or tool descriptions. Use separate channels for user input and system configuration.
6. **Monitor tool invocations** — Log all tool calls and their arguments to detect injection attempts.

## References

- [OWASP MCP Top 10: MCP-03 Prompt Injection via Tools](https://owasp.org/www-project-model-context-protocol-top-10/)
- [OWASP Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [CWE-74: Improper Neutralization of Special Elements in Output](https://cwe.mitre.org/data/definitions/74.html)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [Simon Willison: Prompt Injection Explained](https://simonwillison.net/2023/Apr/14/worst-that-can-happen/)
