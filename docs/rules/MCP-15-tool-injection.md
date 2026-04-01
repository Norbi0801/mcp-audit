# MCP-15: Tool Command Injection

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-15 |
| **Name** | Tool Command Injection |
| **Default Severity** | **Critical** |
| **OWASP Category** | [OWASP-MCP-07](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP tools whose definitions indicate vulnerability to command injection, code injection, or SQL injection. Analyzes tool names, descriptions, and input schemas to identify tools that accept unsanitized user input destined for shell execution, code evaluation, or SQL queries.

Unlike MCP-07 (which checks the *server's own* command/args configuration), this rule inspects the *tools exposed by the server* to clients. A tool named `run_command` with a bare `string` parameter called `command` is an obvious injection vector regardless of how safely the server itself is launched.

## What It Checks

### 1. Dangerous Tool Names (Critical)

Flags tools whose names directly indicate command, code, or query execution capability:

| Tool Name Pattern | Category |
|-------------------|----------|
| `run_command`, `exec_command`, `execute_command` | Direct command execution |
| `shell_exec`, `shell_execute`, `run_shell`, `run_bash` | Shell execution |
| `run_script`, `exec_script`, `execute_script` | Script execution |
| `run_code`, `exec_code`, `execute_code` | Code execution |
| `eval_code`, `eval_expression`, `eval_script` | Code evaluation |
| `system_exec`, `system_command` | System-level execution |
| `os_exec`, `os_command` | Operating system execution |
| `spawn_process`, `popen`, `subprocess` | Process spawning |
| `run_sql`, `exec_sql`, `execute_sql`, `raw_query`, `raw_sql` | SQL execution |

Detection is case-insensitive and matches both exact names and substrings (e.g., `admin_run_command_v2`).

### 2. Description Suggests Command Execution (Critical)

Detects keywords in tool descriptions that indicate the tool executes system commands:

| Keyword | Meaning |
|---------|---------|
| `execute a command`, `run command` | Command execution |
| `shell command`, `bash command` | Shell execution |
| `system command`, `os command` | System-level execution |
| `subprocess`, `child process` | Process spawning |
| `command line`, `invoke command` | Command invocation |

### 3. Description Suggests Code Evaluation (Critical)

| Keyword | Meaning |
|---------|---------|
| `eval(`, `evaluate code` | Code evaluation |
| `execute code`, `run code` | Code execution |
| `execute javascript`, `run python` | Language-specific execution |
| `interpret code`, `dynamic execution` | Dynamic code execution |

### 4. Description Suggests SQL Execution (High)

| Keyword | Meaning |
|---------|---------|
| `execute sql`, `run sql` | SQL execution |
| `sql query`, `raw query`, `raw sql` | Query execution |
| `database query`, `db query` | Database query |
| `direct sql`, `arbitrary sql` | Unrestricted SQL access |

### 5. Dangerous Input Parameters

Analyzes `inputSchema` properties for parameters that indicate injection risk. Only `string`-typed parameters are checked, as they are the injection vectors.

#### 5a. Command Injection Parameters (Critical without validation, Medium with constraints)

| Parameter Name | Category |
|----------------|----------|
| `command`, `cmd` | Shell command input |
| `shell_command`, `shell_cmd`, `bash_command` | Shell command input |
| `exec`, `execute`, `program` | Execution input |
| `script`, `shell`, `run` | Script/shell input |
| `cmdline`, `command_line` | Command-line input |

#### 5b. SQL Injection Parameters (High without validation, Medium with constraints)

| Parameter Name | Category |
|----------------|----------|
| `query`, `sql`, `sql_query`, `sql_statement` | SQL query input |
| `raw_query`, `raw_sql` | Raw SQL input |
| `where_clause`, `where` | SQL WHERE clause |
| `statement`, `db_query` | Database query input |

#### 5c. Code Evaluation Parameters (Critical without validation, Medium with constraints)

| Parameter Name | Category |
|----------------|----------|
| `code`, `source_code`, `source` | Source code input |
| `expression`, `eval`, `eval_code` | Eval input |
| `js`, `javascript`, `python`, `python_code` | Language-specific code |
| `lua`, `lua_code`, `snippet` | Code snippet input |

#### 5d. Parameter Description Hints (High)

Even for generically-named parameters, their descriptions are checked for phrases like:
- "shell command", "command to execute", "passed to shell"
- "sql to execute", "query to execute", "query to run"
- "code to execute", "code to evaluate", "script to run"

### Input Validation Recognition

Severity is reduced from Critical/High to **Medium** when the parameter has any of these JSON Schema constraints:

| Constraint | Effect |
|------------|--------|
| `pattern` | Regex validation |
| `enum` | Allowlist of values |
| `const` | Single fixed value |
| `maxLength` | Length limit |
| `format` | Format validation (e.g., `uri`, `email`) |

While these constraints help, they may not fully prevent injection attacks. The finding is still reported at Medium severity to encourage review.

## Examples

### Vulnerable Tool Definitions

```json
{
  "mcpServers": {
    "dangerous-server": {
      "command": "node",
      "args": ["server.js"],
      "tools": [
        {
          "name": "run_command",
          "description": "Execute a shell command on the host system",
          "inputSchema": {
            "type": "object",
            "properties": {
              "command": {
                "type": "string",
                "description": "The shell command to execute"
              }
            }
          }
        }
      ]
    }
  }
}
```

**Findings:**
1. `Tool 'run_command' has dangerous name indicating direct command execution` (Critical)
2. `Tool 'run_command' description suggests command execution` (Critical)
3. `Tool 'run_command' has shell command input parameter 'command' without input validation` (Critical)
4. `Parameter 'command' description indicates injection risk` (High)

```json
{
  "mcpServers": {
    "db-server": {
      "command": "python",
      "args": ["-m", "db_mcp_server"],
      "tools": [
        {
          "name": "query_database",
          "description": "Run a SQL query against the production database",
          "inputSchema": {
            "type": "object",
            "properties": {
              "sql": { "type": "string" }
            }
          }
        }
      ]
    }
  }
}
```

**Findings:**
1. `Tool 'query_database' description suggests SQL execution` (High)
2. `Tool 'query_database' has SQL statement input parameter 'sql' without input validation` (High)

### Partially Mitigated (Constrained Parameters)

```json
{
  "tools": [
    {
      "name": "run_command",
      "description": "Run a predefined command",
      "inputSchema": {
        "type": "object",
        "properties": {
          "command": {
            "type": "string",
            "enum": ["ls", "pwd", "whoami"]
          }
        }
      }
    }
  ]
}
```

**Finding:** `Tool 'run_command' has shell command input parameter 'command' (has some constraints)` (**Medium**) -- enum constraint recognized but tool name still flagged.

### Safe Tool Definition

```json
{
  "tools": [
    {
      "name": "list_files",
      "description": "Lists files in a directory",
      "inputSchema": {
        "type": "object",
        "properties": {
          "directory": {
            "type": "string",
            "pattern": "^/[a-zA-Z0-9/_-]+$"
          },
          "recursive": { "type": "boolean" }
        }
      }
    }
  ]
}
```

No findings. Safe tool name, safe description, and parameters have pattern validation.

## Remediation

1. **Avoid exposing raw execution tools** -- Do not expose tools named `run_command`, `exec_code`, `run_sql`, etc. If command execution is needed, wrap it in a purpose-specific tool with a narrow interface.
2. **Use parameterized queries** -- Never pass raw SQL strings. Use parameterized queries or an ORM that handles escaping.
3. **Validate input schemas** -- Add `pattern`, `enum`, `maxLength`, or `format` constraints to all string parameters. Use an allowlist (`enum`) whenever possible.
4. **Sanitize shell metacharacters** -- If a tool must accept string input that reaches a shell, strip or reject `;`, `&&`, `||`, `|`, `` ` ``, `$(`, and other metacharacters.
5. **Sandbox execution** -- If code execution is required, use a sandboxed environment (container, WASM, VM) with no network or filesystem access.
6. **Minimize tool capabilities** -- Follow the principle of least privilege. A "file reader" tool should not accept arbitrary paths -- constrain to a specific directory.
7. **Document tool intent** -- Avoid descriptions that suggest unrestricted execution. "List files in /data" is safer than "Execute a command on the system."

## Difference from MCP-07

| Aspect | MCP-07 (Command Injection) | MCP-15 (Tool Command Injection) |
|--------|---------------------------|---------------------------------|
| **What it checks** | Server's own `command` and `args` config | Tools exposed to clients via MCP protocol |
| **Attack vector** | Misconfigured server launch | Client sends malicious input to a vulnerable tool |
| **Data source** | `McpServerConfig.command`, `args` | `McpServerConfig.tools[].name`, `description`, `inputSchema` |
| **Severity** | Critical (shell interpreter) | Critical (unsanitized exec/eval params) |

Both rules should pass for a fully secure MCP server configuration.

## References

- [OWASP MCP Top 10: MCP-07 Command Injection](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Eval Injection](https://cwe.mitre.org/data/definitions/95.html)
- [MCP Specification -- Tools](https://modelcontextprotocol.io/specification/2025-03-26/server/tools)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
