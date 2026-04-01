# MCP-07: Command Injection

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-07 |
| **Name** | Command Injection |
| **Default Severity** | **Critical** |
| **OWASP Category** | [OWASP-MCP-07](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP server configurations vulnerable to command injection through shell interpreters, metacharacters in arguments, and eval/exec patterns.

Command injection is among the most severe MCP vulnerabilities. When a server is configured to run through a shell interpreter (`sh -c`, `bash -c`), any input containing shell metacharacters can break out of the intended command and execute arbitrary code. Combined with MCP's system-level access, this enables full remote code execution — reading files, installing malware, establishing reverse shells, or pivoting to other systems on the network.

## What It Checks

### 1. Shell Interpreters as Command (Critical)

Flags configurations where the command is a shell interpreter rather than a specific runtime:

| Shell | Platform |
|-------|----------|
| `sh` | POSIX |
| `bash` | Linux/macOS |
| `zsh` | macOS |
| `fish` | Cross-platform |
| `csh`, `tcsh` | POSIX |
| `ksh` | POSIX |
| `dash` | Linux (Debian) |
| `cmd`, `cmd.exe` | Windows |
| `powershell`, `powershell.exe` | Windows |
| `pwsh` | Cross-platform PowerShell |

### 2. Shell Metacharacters in Arguments (High)

Detects characters that enable command chaining, piping, or substitution:

| Metacharacter | Function |
|---------------|----------|
| `;` | Command separator |
| `&&` | Command chaining (AND) |
| `\|\|` | Command chaining (OR) |
| `\|` | Pipe (output redirection) |
| `$(...)` | Command substitution |
| `` ` `` | Backtick command substitution |
| `>(...)` | Process substitution |
| `<(...)` | Process substitution |
| `>>` | Append redirection |

### 3. Eval/Exec Patterns (Critical in shell, High otherwise)

Detects dangerous code execution patterns in arguments:

| Pattern | Context |
|---------|---------|
| `eval ` | Shell eval |
| `eval(` | Eval expression |
| `exec(` | Exec expression |
| `exec ` | Exec command |
| `system(` | C/Ruby system() call |
| `os.system` | Python os.system() |
| `subprocess.call` | Python subprocess |
| `subprocess.run` | Python subprocess |
| `child_process` | Node.js child_process |
| `Runtime.exec` | Java Runtime.exec() |

### 4. Variable Expansion in Shell Commands (High)

When a shell is used with `-c`, detects `$VAR` or `${VAR}` expansion that could be exploited if variables contain attacker-controlled data.

## Examples

### Vulnerable Configurations

```json
{
  "mcpServers": {
    "shell-server": {
      "command": "sh",
      "args": ["-c", "node server.js"]
    }
  }
}
```

**Finding:** `Shell interpreter used as command in server 'shell-server'` (Critical)
Using `sh` as the command allows arbitrary command execution.

```json
{
  "mcpServers": {
    "eval-server": {
      "command": "sh",
      "args": ["-c", "eval $INPUT && node server.js"]
    }
  }
}
```

**Findings:**
1. `Shell interpreter used as command in server 'eval-server'` (Critical)
2. `shell eval in shell command of server 'eval-server'` (Critical) — `eval` executes arbitrary strings.
3. `Variable expansion in shell command of server 'eval-server'` (High) — `$INPUT` can be attacker-controlled.

```json
{
  "mcpServers": {
    "piped-server": {
      "command": "node",
      "args": ["server.js", "--cmd", "ls && rm -rf /"]
    }
  }
}
```

**Finding:** `Shell metacharacter in arguments of server 'piped-server'` (High)
Argument contains `&&` (command chaining) that could execute destructive commands.

```json
{
  "mcpServers": {
    "subst-server": {
      "command": "node",
      "args": ["server.js", "$(whoami)"]
    }
  }
}
```

**Finding:** `Shell metacharacter in arguments of server 'subst-server'` (High)
Command substitution `$(whoami)` will execute the `whoami` command.

### Safe Configuration

```json
{
  "mcpServers": {
    "safe-server": {
      "command": "node",
      "args": ["server.js", "--port", "3000"],
      "env": {
        "CONFIG_PATH": "/app/config.json"
      }
    }
  }
}
```

Direct runtime execution (`node`) with static arguments and no shell metacharacters.

## Remediation

1. **Use direct command execution** — Run `node`, `python`, or the specific binary directly instead of wrapping in `sh -c` or `bash -c`.
2. **Never use eval/exec** — Refactor to avoid `eval`, `exec`, `system()`, and similar dynamic execution patterns.
3. **Sanitize arguments** — Ensure no argument contains shell metacharacters (`;`, `&&`, `||`, `|`, `` ` ``, `$(`, etc.).
4. **Avoid variable expansion** — Do not use `$VAR` or `${VAR}` in shell commands. Pass configuration through environment variables that are read by the application, not expanded by the shell.
5. **Use arrays for arguments** — Pass arguments as separate array elements, not as a single string that gets shell-parsed.
6. **Validate at runtime** — Implement input validation in the MCP server to reject arguments containing shell metacharacters.

## References

- [OWASP MCP Top 10: MCP-07 Command Injection](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-78: Improper Neutralization of Special Elements in OS Command](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
- [CVE-2024-24576 — Rust std::process Command Injection on Windows](https://nvd.nist.gov/vuln/detail/CVE-2024-24576)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
