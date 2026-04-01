# MCP-16: Missing Input Validation

| Property | Value |
|----------|-------|
| **Rule ID** | MCP-16 |
| **Name** | Missing Input Validation |
| **Default Severity** | **High** |
| **OWASP Category** | [OWASP-MCP-04](https://owasp.org/www-project-model-context-protocol-top-10/) |

## Description

Detects MCP tools whose input schemas are missing, incomplete, or lack constraints such as required fields, string patterns, maxLength, enum restrictions, or object property limits — all of which leave tools vulnerable to path traversal, injection, and abuse.

Weak or absent input schemas allow arbitrary data to reach tool handlers. Without schema validation, an LLM (or a malicious prompt) can send path traversal sequences, injection payloads, oversized inputs, or unexpected parameters that bypass the tool's intended behavior. Input validation at the schema level is the first line of defense.

## What It Checks

### 1. No `inputSchema` (High)

Flags tools that do not define an `inputSchema` at all. Without a schema, the MCP client cannot validate parameters before sending them, allowing arbitrary data to reach the tool handler.

### 2. No `required` Fields (Medium)

Flags tools whose `inputSchema` has no `required` array. When all parameters are optional, callers can omit critical constraints, leading to unexpected behavior or security bypasses.

### 3. Unconstrained Strings (High/Medium)

Flags `string`-typed parameters that lack any of the following constraints:

| Constraint | Purpose |
|------------|---------|
| `pattern` | Regex validation (e.g., safe path characters) |
| `maxLength` | Length limit (prevents buffer overflows, DoS) |
| `enum` | Allowlist of valid values |
| `const` | Single fixed value |
| `format` | Format validation (e.g., `uri`, `email`, `date-time`) |

**Path-like parameters** (High) — parameters named `path`, `file`, `directory`, `src`, `dst`, etc. are flagged at High severity because they are prime path-traversal vectors:

| Parameter Names |
|----------------|
| `path`, `file_path`, `filepath`, `file`, `filename`, `file_name` |
| `dir`, `directory`, `dir_path`, `folder`, `folder_path` |
| `src`, `dst`, `source_path`, `dest_path`, `destination_path`, `target_path` |
| `working_dir`, `workdir`, `cwd`, `root`, `root_dir`, `base_dir`, `base_path` |
| `output_path`, `input_path`, `log_path`, `config_path`, `template_path` |
| `upload_path`, `download_path`, `target` |

**URL-like parameters** (High) — parameters named `url`, `uri`, `endpoint`, `href`, etc. need `format` or `pattern` constraints to prevent SSRF:

| Parameter Names |
|----------------|
| `url`, `uri`, `endpoint`, `href`, `link` |
| `webhook_url`, `callback_url`, `redirect_url`, `redirect_uri` |
| `base_url`, `api_url`, `server_url`, `image_url` |
| `source_url`, `target_url`, `download_url` |

### 4. Open Objects Without Bounds (Medium)

Flags schemas with `additionalProperties: true` (or absent, which defaults to true) and no `maxProperties` limit. This allows callers to inject arbitrary keys, potentially overriding internal properties or causing unexpected behavior.

### 5. Missing `enum` Where Expected (Medium)

Flags parameters whose names strongly suggest a finite set of valid values but lack an `enum` constraint:

| Parameter Name | Expected Values (examples) |
|---------------|---------------------------|
| `action` | read, write, delete |
| `mode` | sync, async, batch |
| `method` | GET, POST, PUT, DELETE |
| `format` | json, csv, xml |
| `encoding` | utf-8, ascii, base64 |
| `direction` | asc, desc, in, out |
| `level`, `log_level` | debug, info, warn, error |
| `status`, `state` | active, inactive, pending |
| `role` | admin, user, viewer |
| `protocol`, `transport` | http, https, ws |
| `environment`, `env` | dev, staging, production |
| `priority` | low, medium, high, critical |
| `sort_order`, `order` | asc, desc |
| `algorithm` | sha256, sha512, md5 |
| `category`, `kind`, `type`, `variant` | (domain-specific) |

### 6. Path-like Parameters Without Constraints (High)

A specialization of Check 3 — parameters with path-like names are flagged at higher severity because unconstrained paths are the primary vector for path-traversal attacks (`../../../etc/passwd`).

### 7. URL-like Parameters Without Constraints (High)

A specialization of Check 3 — parameters with URL-like names are flagged at higher severity because unconstrained URLs enable SSRF (Server-Side Request Forgery) attacks.

## Examples

### Vulnerable Tool Definitions

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Reads a file from the filesystem"
    }
  ]
}
```

**Finding:** `Tool 'read_file' in server 'X' has no inputSchema` (High) — Tool accepts arbitrary input without any schema validation.

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Reads a file from the filesystem",
      "inputSchema": {
        "type": "object",
        "properties": {
          "path": { "type": "string" },
          "encoding": { "type": "string" }
        }
      }
    }
  ]
}
```

**Findings:**
1. `Tool 'read_file' has no required fields` (Medium) — `path` and `encoding` are both optional.
2. `Path-like parameter 'path' is unconstrained` (High) — `path` has no `pattern` or `maxLength`, allowing `../../../etc/passwd`.
3. `Parameter 'encoding' should use enum constraint` (Medium) — A finite set of encodings should be enforced.

```json
{
  "tools": [
    {
      "name": "proxy",
      "inputSchema": {
        "type": "object",
        "additionalProperties": true,
        "properties": {
          "url": { "type": "string" },
          "action": { "type": "string" }
        },
        "required": ["url"]
      }
    }
  ]
}
```

**Findings:**
1. `URL-like parameter 'url' is unconstrained` (High) — SSRF risk.
2. `Parameter 'action' should use enum constraint` (Medium) — Finite set expected.
3. `Open object schema without maxProperties` (Medium) — Arbitrary keys can be injected.

### Safe Tool Definition

```json
{
  "tools": [
    {
      "name": "read_file",
      "description": "Reads a file from the project directory",
      "inputSchema": {
        "type": "object",
        "properties": {
          "path": {
            "type": "string",
            "pattern": "^[a-zA-Z0-9/_.-]+$",
            "maxLength": 256
          },
          "encoding": {
            "type": "string",
            "enum": ["utf-8", "ascii", "base64"]
          }
        },
        "required": ["path"],
        "additionalProperties": false
      }
    }
  ]
}
```

All parameters are constrained: `path` has a safe-character pattern and length limit, `encoding` uses an enum, `required` fields are declared, and `additionalProperties` is disabled.

## Remediation

1. **Always define `inputSchema`** — Every tool must have a JSON Schema that describes its expected input with explicit types.
2. **Declare `required` fields** — Mark all mandatory parameters as required to prevent omission of critical inputs.
3. **Constrain strings** — Add `pattern`, `maxLength`, `enum`, or `format` constraints to all string parameters. Use allowlist patterns (`^[a-zA-Z0-9/_.-]+$`) for paths.
4. **Use `enum` for finite sets** — Parameters like `mode`, `format`, `action`, `encoding`, and `level` should always use `enum` to restrict values.
5. **Disable `additionalProperties`** — Set `additionalProperties: false` to prevent callers from injecting unexpected parameters. If additional properties are needed, set `maxProperties`.
6. **Validate paths server-side** — Even with schema constraints, validate and normalize file paths on the server to prevent bypasses.
7. **Use `format` for URLs** — Set `"format": "uri"` on URL parameters and validate the scheme/host allowlist server-side to prevent SSRF.
8. **Set `maxItems` and `maxLength` on arrays/buffers** — Prevent denial-of-service through oversized inputs.

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-model-context-protocol-top-10/)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-1284: Improper Validation of Specified Quantity in Input](https://cwe.mitre.org/data/definitions/1284.html)
- [JSON Schema Specification — Validation](https://json-schema.org/draft/2020-12/json-schema-validation)
- [MCP Specification — Tools](https://modelcontextprotocol.io/specification/2025-03-26/server/tools)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
