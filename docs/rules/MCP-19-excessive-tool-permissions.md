# MCP-19: Excessive Tool Permissions

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-19 |
| **Name** | Excessive Tool Permissions |
| **Default Severity** | **High** |
| **OWASP Category** | [OWASP-MCP-02](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP tools with overly broad permissions: descriptions suggesting unrestricted shell, file system, or network access; tools without input schemas; maximally permissive schemas; and single mega-tools that combine capabilities that should be split into smaller, purpose-specific tools.

The principle of least privilege demands that each tool should have the minimum scope necessary to fulfill its purpose. A tool that grants full shell access, reads any file, or makes arbitrary network requests is an outsized attack surface — one prompt injection or misconfigured LLM call can compromise the entire system.

Unlike MCP-02 (which checks server-level file paths) or MCP-16 (which checks schema validation quality), this rule focuses on the scope of power a tool is granted.

## What It Checks

### 1. Privileged Capability in Description (High)

Scans tool descriptions for keywords indicating overly broad permissions across four domains:

#### Shell Access

| Keyword | Description |
|---------|-------------|
| `full shell access`, `unrestricted shell` | Unrestricted shell |
| `arbitrary shell`, `any shell command`, `any command` | Arbitrary command execution |
| `full terminal access`, `unrestricted terminal` | Full terminal |
| `root shell`, `admin shell` | Privileged shell |
| `full bash access`, `unrestricted bash` | Full bash |
| `execute anything`, `run anything` | Unrestricted execution |
| `run any program`, `execute any program` | Arbitrary program execution |
| `full system access`, `unrestricted system access` | Full system access |

#### File System Access

| Keyword | Description |
|---------|-------------|
| `full file system`, `full filesystem`, `entire filesystem` | Full filesystem access |
| `unrestricted file`, `any file`, `all files` | Unrestricted file access |
| `full disk access`, `entire disk` | Full disk |
| `read any file`, `write any file`, `delete any file`, `modify any file` | Any file operations |
| `access any directory`, `access all directories`, `any directory` | Any directory access |
| `unrestricted path`, `unrestricted directory` | Unrestricted paths |
| `read and write anywhere`, `read/write anywhere` | Anywhere read/write |
| `arbitrary file`, `arbitrary path`, `arbitrary directory` | Arbitrary path access |

#### Network Access

| Keyword | Description |
|---------|-------------|
| `any url`, `any endpoint`, `any host`, `any server` | Any destination |
| `unrestricted network`, `unrestricted http`, `unrestricted url` | Unrestricted network |
| `arbitrary url`, `arbitrary endpoint`, `arbitrary host` | Arbitrary destinations |
| `full network access`, `full internet access` | Full network |
| `proxy all traffic`, `forward any request`, `open proxy` | Proxy/forwarding |
| `connect to any`, `fetch any`, `request any` | Unrestricted requests |
| `access any api`, `call any api` | Unrestricted API access |

#### Administrative Privileges

| Keyword | Description |
|---------|-------------|
| `admin access`, `admin privilege`, `administrator access` | Admin access |
| `root access`, `root privilege`, `superuser` | Root/superuser |
| `god mode`, `full access`, `full control`, `full permission` | Unrestricted access |
| `unrestricted access`, `unlimited access`, `no restrictions` | No restrictions |
| `bypass security`, `bypass permission`, `bypass access control` | Security bypass |
| `bypass authentication`, `bypass authorization` | Auth bypass |
| `override security`, `override permission` | Permission override |
| `elevated privilege`, `elevated access`, `privileged access` | Elevated privileges |

### 2. Schemaless Tool (High)

Flags tools with no `inputSchema` at all. A tool without a schema accepts completely unconstrained input — a permission boundary violation that allows any data to reach the handler.

### 3. Maximally Permissive Schema (High)

Flags schemas that exist but impose zero constraints:

| Condition | Risk |
|-----------|------|
| `additionalProperties: true` with no defined `properties` | Accepts any arbitrary structure |
| `additionalProperties: true` with no `required` fields | Schema exists but doesn't constrain anything |

These schemas give the appearance of validation without providing any actual security.

### 4. Mega-Tool / Lack of Granularity (High)

Detects tools that combine too many capabilities into a single tool:

#### 4a. Mega-Tool Names

| Tool Name | Concern |
|-----------|---------|
| `do_anything`, `do_everything`, `do_all` | Unrestricted capability |
| `universal_tool`, `universal` | Universal scope |
| `god_tool`, `god_mode` | Unrestricted capability |
| `super_tool`, `mega_tool`, `master_tool` | Excessive scope |
| `admin_tool`, `root_tool` | Administrative scope |
| `all_in_one`, `swiss_army`, `omnibus` | Combined capabilities |
| `catch_all`, `all_purpose`, `general_purpose` | Unrestricted scope |

#### 4b. Mega-Tool Description Keywords

| Keyword | Concern |
|---------|---------|
| `do anything`, `do everything`, `does everything` | Unrestricted scope |
| `all-in-one`, `swiss army`, `one tool to rule them all` | Combined tool |
| `replaces all other tools`, `everything you need` | Tool replacement |
| `can do anything`, `capable of anything`, `unlimited capabilit` | Unlimited claims |
| `single tool for all`, `multipurpose`, `multi-purpose tool for any` | Over-broad scope |

#### 4c. Multi-Domain Capability (High)

Flags a tool whose description spans 3 or more distinct capability domains:

| Domain | Indicator Keywords |
|--------|-------------------|
| File system | `read file`, `write file`, `delete file`, `list director`, `filesystem` |
| Shell/exec | `execute command`, `run command`, `shell command`, `subprocess` |
| Network | `http request`, `fetch url`, `send request`, `api call`, `download` |
| Database | `database`, `sql query`, `run query`, `execute query` |
| System | `system info`, `system config`, `environment variable`, `process management` |
| Auth/secrets | `manage credential`, `manage secret`, `manage token`, `manage password` |

A tool that matches keywords from 3+ domains is flagged as a mega-tool that should be split.

## Examples

### Vulnerable Tool Definitions

```json
{
  "tools": [
    {
      "name": "super_tool",
      "description": "Execute any command on the system with full shell access. Can read any file, write any file, and make HTTP requests to any URL.",
      "inputSchema": {
        "type": "object",
        "additionalProperties": true
      }
    }
  ]
}
```

**Findings:**
1. `Tool 'super_tool' grants shell access` (High) — Description indicates `full shell access`.
2. `Tool 'super_tool' grants unrestricted file system access` (High) — `read any file`, `write any file`.
3. `Tool 'super_tool' grants unrestricted network access` (High) — `any URL`.
4. `Tool 'super_tool' has maximally permissive schema` (High) — `additionalProperties: true` with no defined properties.
5. `Tool 'super_tool' is a mega-tool` (High) — Name matches `super_tool` pattern.
6. `Tool 'super_tool' spans multiple capability domains` (High) — Covers file-system, shell/exec, and network domains.

```json
{
  "tools": [
    {
      "name": "admin_panel",
      "description": "Administrator tool with root access and no restrictions. Bypasses all security controls."
    }
  ]
}
```

**Findings:**
1. `Tool 'admin_panel' grants admin/root privileges` (High) — `root access`, `no restrictions`.
2. `Tool 'admin_panel' grants admin/root privileges` (High) — `Bypasses all security controls`.
3. `Tool 'admin_panel' has no inputSchema` (High) — Schemaless tool.

```json
{
  "tools": [
    {
      "name": "do_everything",
      "description": "All-in-one tool. Reads files, executes commands, manages database, makes HTTP requests, and handles secrets.",
      "inputSchema": {
        "type": "object",
        "additionalProperties": true,
        "properties": {}
      }
    }
  ]
}
```

**Findings:**
1. `Tool 'do_everything' is a mega-tool` (High) — Name and description indicate excessive scope.
2. `Tool 'do_everything' spans multiple capability domains` (High) — Covers file-system, shell/exec, database, network, and auth/secrets domains (5 domains, threshold is 3).
3. `Tool 'do_everything' has maximally permissive schema` (High) — Empty properties with `additionalProperties: true`.

### Safe Tool Definition

```json
{
  "tools": [
    {
      "name": "list_project_files",
      "description": "Lists files in the project's /src directory",
      "inputSchema": {
        "type": "object",
        "properties": {
          "subdirectory": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9/_-]+$",
            "maxLength": 128
          }
        },
        "required": ["subdirectory"],
        "additionalProperties": false
      }
    },
    {
      "name": "run_tests",
      "description": "Runs the project's test suite with the specified filter",
      "inputSchema": {
        "type": "object",
        "properties": {
          "filter": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9_:]+$",
            "maxLength": 100
          }
        },
        "additionalProperties": false
      }
    }
  ]
}
```

Each tool has a narrow, well-defined purpose. Schemas are constrained with patterns, required fields, and `additionalProperties: false`. No unrestricted access claims.

## Remediation

1. **Follow the principle of least privilege** — Each tool should do exactly one thing with the minimum necessary permissions. Avoid "do everything" tools.
2. **Split mega-tools** — If a tool spans multiple capability domains (file I/O, shell, network, database), split it into separate, purpose-specific tools.
3. **Narrow descriptions** — Replace language like "any file", "any command", "any URL" with specific scopes: "files in /project/src", "predefined test commands", "the project's API endpoint".
4. **Always define `inputSchema`** — Every tool must have a schema that constrains its inputs. Never expose a schemaless tool.
5. **Constrain schemas** — Set `additionalProperties: false`, define all expected properties, and use `required` fields. Use `pattern`, `enum`, and `maxLength` on string parameters.
6. **Avoid admin/root tools** — Do not create tools that claim root access, admin privileges, or security bypass capabilities. If elevated access is needed, scope it narrowly.
7. **Use allowlists** — For tools that execute commands or access files, define explicit allowlists of permitted commands/paths rather than allowing arbitrary input.
8. **Audit regularly** — Periodically review all tool definitions for scope creep. Tools tend to accumulate capabilities over time.

## Difference from Related Rules

| Aspect | MCP-02 (Server Permissions) | MCP-16 (Input Validation) | MCP-19 (Tool Permissions) |
|--------|-----------------------------|---------------------------|---------------------------|
| **Scope** | Server-level file path access | Schema quality and constraints | Tool-level capability scope |
| **Focus** | What the server process can reach | How well inputs are validated | What the tool claims it can do |
| **Example** | Server has access to `/` | `path` param has no pattern | Description says "read any file" |

All three rules should pass for fully secure MCP tool definitions.

## References

- [OWASP MCP Top 10: MCP-02 Excessive Permissions](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)
- [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [MCP Specification — Tools](https://modelcontextprotocol.io/specification/2025-03-26/server/tools)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/concepts/security)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
