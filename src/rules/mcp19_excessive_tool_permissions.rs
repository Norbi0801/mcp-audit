//! MCP-19: Excessive Tool Permissions
//!
//! Detects MCP tools that are granted overly broad capabilities, violating the
//! principle of least privilege. Unlike MCP-02 (which checks server-level file
//! paths) or MCP-16 (which checks schema validation quality), this rule focuses
//! on the *scope of power* a tool is granted: does the tool description suggest
//! unrestricted shell access, full file system traversal, or open network
//! access? Does the tool accept anything without constraints? Is a single
//! mega-tool used instead of fine-grained, purpose-specific tools?
//!
//! ## Checks
//!
//! 1. **Privileged capability in description** — tool description suggests
//!    shell access, unrestricted file system access, arbitrary network access,
//!    or administrative/root-level operations.
//! 2. **Schemaless tool** — tool has no `inputSchema` at all, meaning it
//!    accepts completely unconstrained input — a permission boundary violation.
//! 3. **Maximally permissive schema** — `additionalProperties: true` combined
//!    with no defined properties or no `required` fields: the schema exists but
//!    imposes zero constraints.
//! 4. **Mega-tool / lack of granularity** — a single tool whose name or
//!    description indicates it replaces many purpose-specific tools, violating
//!    the principle of least privilege through scope creep.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

// ── Check 1: Description patterns indicating overly broad permissions ───

/// Keywords in tool descriptions indicating unrestricted shell access.
const SHELL_ACCESS_KEYWORDS: &[&str] = &[
    "full shell access",
    "unrestricted shell",
    "arbitrary shell",
    "any shell command",
    "any command",
    "full terminal access",
    "unrestricted terminal",
    "any terminal command",
    "root shell",
    "admin shell",
    "full bash access",
    "unrestricted bash",
    "full command access",
    "unrestricted command",
    "execute anything",
    "run anything",
    "run any program",
    "execute any program",
    "full system access",
    "unrestricted system access",
];

/// Keywords in tool descriptions indicating unrestricted file system access.
const FILESYSTEM_ACCESS_KEYWORDS: &[&str] = &[
    "full file system",
    "full filesystem",
    "unrestricted file",
    "any file",
    "all files",
    "entire file system",
    "entire filesystem",
    "entire disk",
    "full disk access",
    "read any file",
    "write any file",
    "delete any file",
    "modify any file",
    "access any file",
    "access all files",
    "access any directory",
    "access all directories",
    "any path on",
    "any directory",
    "all directories",
    "unrestricted path",
    "unrestricted directory",
    "read and write anywhere",
    "read/write anywhere",
    "arbitrary file",
    "arbitrary path",
    "arbitrary directory",
];

/// Keywords in tool descriptions indicating unrestricted network access.
const NETWORK_ACCESS_KEYWORDS: &[&str] = &[
    "any url",
    "any endpoint",
    "any host",
    "any server",
    "any port",
    "any address",
    "any ip",
    "any domain",
    "unrestricted network",
    "unrestricted http",
    "unrestricted url",
    "unrestricted web",
    "arbitrary url",
    "arbitrary endpoint",
    "arbitrary host",
    "arbitrary network",
    "all network",
    "full network access",
    "full internet access",
    "proxy all traffic",
    "forward any request",
    "open proxy",
    "unrestricted proxy",
    "connect to any",
    "fetch any",
    "request any",
    "access any api",
    "call any api",
    "any remote",
    "any external",
];

/// Keywords in tool descriptions indicating administrative/root privileges.
const ADMIN_ACCESS_KEYWORDS: &[&str] = &[
    "admin access",
    "admin privilege",
    "administrator access",
    "root access",
    "root privilege",
    "superuser",
    "super user",
    "god mode",
    "full access",
    "full control",
    "full permission",
    "unrestricted access",
    "unrestricted permission",
    "unrestricted privilege",
    "unlimited access",
    "unlimited permission",
    "no restrictions",
    "no limitation",
    "bypass security",
    "bypass permission",
    "bypass access control",
    "bypass authentication",
    "bypass authorization",
    "override security",
    "override permission",
    "elevated privilege",
    "elevated access",
    "privileged access",
    "privileged operation",
];

// ── Check 4: Mega-tool patterns ─────────────────────────────────────────

/// Tool names that indicate a "do everything" tool.
const MEGA_TOOL_NAMES: &[(&str, &str)] = &[
    ("do_anything", "unrestricted capability"),
    ("do_everything", "unrestricted capability"),
    ("do_all", "unrestricted capability"),
    ("universal_tool", "universal scope"),
    ("universal", "universal scope"),
    ("god_tool", "unrestricted capability"),
    ("god_mode", "unrestricted capability"),
    ("super_tool", "excessive scope"),
    ("mega_tool", "excessive scope"),
    ("master_tool", "excessive scope"),
    ("admin_tool", "administrative scope"),
    ("root_tool", "root-level scope"),
    ("all_in_one", "combined capabilities"),
    ("swiss_army", "combined capabilities"),
    ("omnibus", "combined capabilities"),
    ("catch_all", "unrestricted scope"),
    ("all_purpose", "unrestricted scope"),
    ("general_purpose", "unrestricted scope"),
];

/// Keywords in descriptions indicating a tool combines too many capabilities.
const MEGA_TOOL_DESC_KEYWORDS: &[&str] = &[
    "do anything",
    "do everything",
    "all-in-one",
    "all in one",
    "swiss army",
    "swiss-army",
    "one tool to rule them all",
    "replaces all other tools",
    "everything you need",
    "all purpose",
    "all-purpose",
    "general purpose tool that can",
    "handles all",
    "does everything",
    "can do anything",
    "capable of anything",
    "unlimited capabilit",
    "universal tool",
    "single tool for all",
    "one tool for all",
    "multipurpose",
    "multi-purpose tool for any",
];

/// Minimum number of distinct capability domains in a single tool description
/// that indicates a mega-tool (e.g., "reads files, executes commands, and sends
/// HTTP requests" spans file, exec, and network domains).
const MEGA_TOOL_CAPABILITY_THRESHOLD: usize = 3;

/// Capability domain indicators. If a description matches keywords from
/// `MEGA_TOOL_CAPABILITY_THRESHOLD` or more distinct domains, the tool is
/// flagged as a mega-tool.
const CAPABILITY_DOMAINS: &[(&str, &[&str])] = &[
    (
        "file-system",
        &[
            "read file",
            "write file",
            "delete file",
            "list director",
            "create file",
            "modify file",
            "file system",
            "filesystem",
            "file access",
        ],
    ),
    (
        "shell/exec",
        &[
            "execute command",
            "run command",
            "shell command",
            "run script",
            "execute script",
            "subprocess",
            "spawn process",
            "command execution",
        ],
    ),
    (
        "network",
        &[
            "http request",
            "fetch url",
            "send request",
            "api call",
            "make request",
            "network request",
            "web request",
            "download",
            "upload",
        ],
    ),
    (
        "database",
        &[
            "database",
            "sql query",
            "run query",
            "execute query",
            "db access",
            "table operation",
        ],
    ),
    (
        "system",
        &[
            "system info",
            "system config",
            "environment variable",
            "process management",
            "service management",
            "system setting",
            "os operation",
        ],
    ),
    (
        "auth/secrets",
        &[
            "manage credential",
            "manage secret",
            "manage token",
            "manage key",
            "access credential",
            "access secret",
            "manage password",
            "manage certificate",
        ],
    ),
];

// ── Rule implementation ─────────────────────────────────────────────────

const RULE_ID: &str = "MCP-19";

pub struct ExcessiveToolPermissionsRule;

impl super::Rule for ExcessiveToolPermissionsRule {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn name(&self) -> &'static str {
        "Excessive Tool Permissions"
    }

    fn description(&self) -> &'static str {
        "Detects MCP tools with overly broad permissions: descriptions suggesting \
         unrestricted shell, file system, or network access; tools without input \
         schemas; maximally permissive schemas; and single mega-tools that combine \
         capabilities that should be split into smaller, purpose-specific tools."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-02"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let tools = match &server.tools {
            Some(t) if !t.is_empty() => t,
            _ => return findings,
        };

        for tool in tools {
            let desc_lower = tool.description.as_deref().unwrap_or("").to_lowercase();
            let tool_name_lower = tool.name.to_lowercase();

            // ── Check 1: Description suggests overly broad permissions ──
            self.check_privileged_description(&desc_lower, &tool.name, server_name, &mut findings);

            // ── Check 2: No inputSchema (accepts anything) ─────────────
            self.check_schemaless_tool(tool, server_name, &mut findings);

            // ── Check 3: Maximally permissive schema ───────────────────
            self.check_permissive_schema(tool, server_name, &mut findings);

            // ── Check 4a: Mega-tool name ───────────────────────────────
            self.check_mega_tool_name(&tool_name_lower, &tool.name, server_name, &mut findings);

            // ── Check 4b: Mega-tool description keywords ───────────────
            self.check_mega_tool_description(&desc_lower, &tool.name, server_name, &mut findings);

            // ── Check 4c: Multi-domain capability in single tool ───────
            self.check_multi_domain_tool(&desc_lower, &tool.name, server_name, &mut findings);
        }

        findings
    }
}

impl ExcessiveToolPermissionsRule {
    /// Check 1: Scan description for keywords indicating overly broad permissions.
    fn check_privileged_description(
        &self,
        desc_lower: &str,
        tool_name: &str,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        if desc_lower.is_empty() {
            return;
        }

        // Shell access.
        for keyword in SHELL_ACCESS_KEYWORDS {
            if desc_lower.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' grants shell access",
                        tool_name, server_name
                    ),
                    description: format!(
                        "Tool '{}' description indicates unrestricted shell access \
                         (matched: '{}').  A tool should never expose a full shell — \
                         replace with narrowly-scoped commands or a restricted allowlist.",
                        tool_name, keyword
                    ),
                });
                break;
            }
        }

        // File system access.
        for keyword in FILESYSTEM_ACCESS_KEYWORDS {
            if desc_lower.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' grants unrestricted file system access",
                        tool_name, server_name
                    ),
                    description: format!(
                        "Tool '{}' description indicates unrestricted file system access \
                         (matched: '{}').  Restrict access to a specific directory or \
                         use an allowlist of permitted paths.",
                        tool_name, keyword
                    ),
                });
                break;
            }
        }

        // Network access.
        for keyword in NETWORK_ACCESS_KEYWORDS {
            if desc_lower.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' grants unrestricted network access",
                        tool_name, server_name
                    ),
                    description: format!(
                        "Tool '{}' description indicates unrestricted network access \
                         (matched: '{}').  Limit allowed hosts, protocols, and ports \
                         with an explicit allowlist.",
                        tool_name, keyword
                    ),
                });
                break;
            }
        }

        // Admin/root access.
        for keyword in ADMIN_ACCESS_KEYWORDS {
            if desc_lower.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Critical,
                    title: format!(
                        "Tool '{}' in server '{}' claims administrative privileges",
                        tool_name, server_name
                    ),
                    description: format!(
                        "Tool '{}' description indicates administrative or root-level \
                         privileges (matched: '{}').  Never grant admin access through \
                         an MCP tool — apply role-based access control and minimal \
                         permissions.",
                        tool_name, keyword
                    ),
                });
                break;
            }
        }
    }

    /// Check 2: Flag tools that have no `inputSchema` at all.
    fn check_schemaless_tool(
        &self,
        tool: &crate::parser::McpToolDefinition,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        if tool.input_schema.is_none() {
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                title: format!(
                    "Tool '{}' in server '{}' has no inputSchema — accepts anything",
                    tool.name, server_name
                ),
                description: format!(
                    "Tool '{}' has no inputSchema, meaning the LLM can send \
                     arbitrary parameters with no constraints. This effectively \
                     grants the tool unlimited input permissions. Define an \
                     explicit schema with strict property types and required \
                     fields to enforce least-privilege.",
                    tool.name
                ),
            });
        }
    }

    /// Check 3: Flag schemas that are technically present but impose zero
    /// constraints (`additionalProperties: true` with no defined or required
    /// properties).
    fn check_permissive_schema(
        &self,
        tool: &crate::parser::McpToolDefinition,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        let schema = match &tool.input_schema {
            Some(s) if s.is_object() => s,
            _ => return,
        };

        let additional_props = schema.get("additionalProperties");
        let allows_additional = match additional_props {
            Some(v) => v.as_bool().unwrap_or(true), // non-bool → permissive
            None => true,                           // absent → implicitly true in JSON Schema
        };

        if !allows_additional {
            return; // Schema explicitly restricts additional properties.
        }

        let has_properties = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .is_some_and(|p| !p.is_empty());

        let has_required = schema
            .get("required")
            .and_then(|r| r.as_array())
            .is_some_and(|r| !r.is_empty());

        // Flag when additional props are allowed AND there are no defined
        // properties at all, OR no required fields.
        if !has_properties {
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                title: format!(
                    "Tool '{}' in server '{}' has maximally permissive schema",
                    tool.name, server_name
                ),
                description: format!(
                    "Tool '{}' schema allows additional properties but defines \
                     no properties of its own — callers can send any key-value \
                     pairs. Set \"additionalProperties\": false and define \
                     explicit properties with types and constraints.",
                    tool.name
                ),
            });
        } else if !has_required && additional_props == Some(&serde_json::json!(true)) {
            // Explicitly set additionalProperties: true WITH properties but NO
            // required fields — still overly broad.
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::Medium,
                title: format!(
                    "Tool '{}' in server '{}' has overly broad schema",
                    tool.name, server_name
                ),
                description: format!(
                    "Tool '{}' schema explicitly allows additional properties \
                     and has no required fields — all inputs are optional and \
                     arbitrary extra keys are accepted. Add a \"required\" array \
                     and set \"additionalProperties\": false.",
                    tool.name
                ),
            });
        }
    }

    /// Check 4a: Tool name indicates a "do everything" mega-tool.
    fn check_mega_tool_name(
        &self,
        tool_name_lower: &str,
        tool_name: &str,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        for (pattern, category) in MEGA_TOOL_NAMES {
            if tool_name_lower == *pattern || tool_name_lower.contains(pattern) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' appears to be a mega-tool ({})",
                        tool_name, server_name, category
                    ),
                    description: format!(
                        "Tool '{}' name suggests {} — a single tool that combines \
                         multiple capabilities. Split into smaller, purpose-specific \
                         tools that each follow the principle of least privilege.",
                        tool_name, category
                    ),
                });
                break;
            }
        }
    }

    /// Check 4b: Description indicates a mega-tool.
    fn check_mega_tool_description(
        &self,
        desc_lower: &str,
        tool_name: &str,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        if desc_lower.is_empty() {
            return;
        }

        for keyword in MEGA_TOOL_DESC_KEYWORDS {
            if desc_lower.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' description suggests a mega-tool",
                        tool_name, server_name
                    ),
                    description: format!(
                        "Tool '{}' description contains '{}', suggesting a single tool \
                         that replaces many specialized tools. This violates least-privilege \
                         — split into smaller tools with focused permissions.",
                        tool_name, keyword
                    ),
                });
                break;
            }
        }
    }

    /// Check 4c: Description covers too many distinct capability domains.
    fn check_multi_domain_tool(
        &self,
        desc_lower: &str,
        tool_name: &str,
        server_name: &str,
        findings: &mut Vec<ScanFinding>,
    ) {
        if desc_lower.is_empty() {
            return;
        }

        let mut matched_domains: Vec<&str> = Vec::new();

        for (domain, keywords) in CAPABILITY_DOMAINS {
            for keyword in *keywords {
                if desc_lower.contains(keyword) {
                    matched_domains.push(domain);
                    break;
                }
            }
        }

        if matched_domains.len() >= MEGA_TOOL_CAPABILITY_THRESHOLD {
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                title: format!(
                    "Tool '{}' in server '{}' spans {} capability domains",
                    tool_name,
                    server_name,
                    matched_domains.len()
                ),
                description: format!(
                    "Tool '{}' description covers {} distinct capability domains \
                     ({}). A single tool should not combine file system, shell, \
                     network, and database operations. Split into focused tools.",
                    tool_name,
                    matched_domains.len(),
                    matched_domains.join(", ")
                ),
            });
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::McpToolDefinition;
    use crate::rules::Rule;

    /// Helper: build a server config with the given tools.
    fn server_with_tools(tools: Vec<McpToolDefinition>) -> McpServerConfig {
        McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            tools: Some(tools),
            ..Default::default()
        }
    }

    /// Helper: build a tool definition.
    fn tool(
        name: &str,
        desc: Option<&str>,
        schema: Option<serde_json::Value>,
    ) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: desc.map(|d| d.to_string()),
            input_schema: schema,
        }
    }

    fn check_tools(tools: Vec<McpToolDefinition>) -> Vec<ScanFinding> {
        let rule = ExcessiveToolPermissionsRule;
        let server = server_with_tools(tools);
        rule.check("test-server", &server)
    }

    // ── Rule metadata ──────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = ExcessiveToolPermissionsRule;
        assert_eq!(rule.id(), "MCP-19");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-02");
        assert_eq!(rule.default_severity(), Severity::High);
        assert!(!rule.name().is_empty());
        assert!(!rule.description().is_empty());
    }

    // ── No tools → no findings ─────────────────────────────────────────

    #[test]
    fn no_tools_no_findings() {
        let rule = ExcessiveToolPermissionsRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            tools: None,
            ..Default::default()
        };
        let findings = rule.check("test-server", &server);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_tools_no_findings() {
        let findings = check_tools(vec![]);
        assert!(findings.is_empty());
    }

    // ── Check 1: Shell access keywords ─────────────────────────────────

    #[test]
    fn detects_shell_access_description() {
        let findings = check_tools(vec![tool(
            "exec",
            Some("Provides full shell access to the host system"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "cmd": { "type": "string" } },
                "required": ["cmd"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("shell access")),
            "Expected shell access finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_unrestricted_shell_description() {
        let findings = check_tools(vec![tool(
            "run",
            Some("Gives unrestricted shell to run anything"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "command": { "type": "string" } },
                "required": ["command"],
                "additionalProperties": false
            })),
        )]);
        assert!(findings.iter().any(|f| f.title.contains("shell access")));
    }

    // ── Check 1: File system access keywords ───────────────────────────

    #[test]
    fn detects_full_filesystem_access() {
        let findings = check_tools(vec![tool(
            "browse",
            Some("Browse the entire file system of the host"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("file system access")),
            "Expected filesystem finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_read_any_file() {
        let findings = check_tools(vec![tool(
            "file_reader",
            Some("Can read any file on the server"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
                "additionalProperties": false
            })),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("file system access")));
    }

    // ── Check 1: Network access keywords ───────────────────────────────

    #[test]
    fn detects_unrestricted_network_access() {
        let findings = check_tools(vec![tool(
            "fetch",
            Some("Fetch content from any url on the internet"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "url": { "type": "string" } },
                "required": ["url"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("network access")),
            "Expected network finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_open_proxy() {
        let findings = check_tools(vec![tool(
            "proxy",
            Some("Acts as an open proxy for HTTP requests"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "target": { "type": "string" } },
                "required": ["target"],
                "additionalProperties": false
            })),
        )]);
        assert!(findings.iter().any(|f| f.title.contains("network access")));
    }

    // ── Check 1: Admin access keywords ─────────────────────────────────

    #[test]
    fn detects_admin_access() {
        let findings = check_tools(vec![tool(
            "admin",
            Some("Provides full admin access to the platform"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "action": { "type": "string" } },
                "required": ["action"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("administrative privileges")),
            "Expected admin finding, got: {:?}",
            findings
        );
        // Admin access findings should be Critical.
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detects_bypass_security() {
        let findings = check_tools(vec![tool(
            "override",
            Some("Can bypass security checks for testing"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "check": { "type": "string" } },
                "required": ["check"],
                "additionalProperties": false
            })),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("administrative privileges")));
    }

    // ── Check 2: No inputSchema ────────────────────────────────────────

    #[test]
    fn detects_tool_without_schema() {
        let findings = check_tools(vec![tool(
            "process_data",
            Some("Process data"),
            None, // No schema at all.
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("no inputSchema")),
            "Expected schemaless finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn tool_with_schema_not_flagged_as_schemaless() {
        let findings = check_tools(vec![tool(
            "process_data",
            Some("Process some data"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "data": { "type": "string" } },
                "required": ["data"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            !findings.iter().any(|f| f.title.contains("no inputSchema")),
            "Tool with schema should not be flagged as schemaless"
        );
    }

    // ── Check 3: Maximally permissive schema ───────────────────────────

    #[test]
    fn detects_maximally_permissive_schema_no_properties() {
        let findings = check_tools(vec![tool(
            "handle",
            Some("Handle requests"),
            Some(serde_json::json!({
                "type": "object",
                "additionalProperties": true
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("maximally permissive")),
            "Expected permissive schema finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_maximally_permissive_schema_empty_properties() {
        let findings = check_tools(vec![tool(
            "handle",
            Some("Handle requests"),
            Some(serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": true
            })),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("maximally permissive")));
    }

    #[test]
    fn detects_broad_schema_additional_props_no_required() {
        let findings = check_tools(vec![tool(
            "query",
            Some("Query things"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "filter": { "type": "string" } },
                "additionalProperties": true
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("overly broad schema")),
            "Expected broad schema finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn strict_schema_not_flagged() {
        let findings = check_tools(vec![tool(
            "query",
            Some("Query items by ID"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("permissive") || f.title.contains("broad schema")),
            "Strict schema should not be flagged"
        );
    }

    // ── Check 4a: Mega-tool names ──────────────────────────────────────

    #[test]
    fn detects_mega_tool_name() {
        let findings = check_tools(vec![tool(
            "do_anything",
            Some("Execute any operation"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "action": { "type": "string" } },
                "required": ["action"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("mega-tool")),
            "Expected mega-tool finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_swiss_army_name() {
        let findings = check_tools(vec![tool(
            "swiss_army_tool",
            Some("A useful multi-tool"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "op": { "type": "string" } },
                "required": ["op"],
                "additionalProperties": false
            })),
        )]);
        assert!(findings.iter().any(|f| f.title.contains("mega-tool")));
    }

    #[test]
    fn normal_tool_name_not_flagged() {
        let findings = check_tools(vec![tool(
            "get_weather",
            Some("Get current weather for a city"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "city": { "type": "string" } },
                "required": ["city"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            !findings.iter().any(|f| f.title.contains("mega-tool")),
            "Normal tool name should not be flagged"
        );
    }

    // ── Check 4b: Mega-tool description keywords ───────────────────────

    #[test]
    fn detects_mega_tool_description() {
        let findings = check_tools(vec![tool(
            "super_exec",
            Some("An all-in-one tool that can do anything you need"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "input": { "type": "string" } },
                "required": ["input"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("mega-tool") || f.title.contains("suggests")),
            "Expected mega-tool desc finding, got: {:?}",
            findings
        );
    }

    // ── Check 4c: Multi-domain capability ──────────────────────────────

    #[test]
    fn detects_multi_domain_tool() {
        let findings = check_tools(vec![tool(
            "omnibus",
            Some(
                "This tool can read file, execute command, send request, \
                 and run query against the database",
            ),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "action": { "type": "string" } },
                "required": ["action"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("capability domains")),
            "Expected multi-domain finding, got: {:?}",
            findings
        );
    }

    #[test]
    fn single_domain_tool_not_flagged_as_multi() {
        let findings = check_tools(vec![tool(
            "file_ops",
            Some("Read file and write file in a specific directory"),
            Some(serde_json::json!({
                "type": "object",
                "properties": { "path": { "type": "string" } },
                "required": ["path"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("capability domains")),
            "Single-domain tool should not trigger multi-domain finding"
        );
    }

    // ── Safe tool: full check ──────────────────────────────────────────

    #[test]
    fn well_scoped_tool_produces_no_findings() {
        let findings = check_tools(vec![tool(
            "get_weather",
            Some("Returns current weather for a given city name"),
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "maxLength": 100
                    }
                },
                "required": ["city"],
                "additionalProperties": false
            })),
        )]);
        assert!(
            findings.is_empty(),
            "Well-scoped tool should have zero findings, got: {:?}",
            findings
        );
    }

    // ── Multiple tools: only flagged tools produce findings ────────────

    #[test]
    fn only_problematic_tools_flagged() {
        let findings = check_tools(vec![
            tool(
                "get_weather",
                Some("Returns weather for a city"),
                Some(serde_json::json!({
                    "type": "object",
                    "properties": { "city": { "type": "string" } },
                    "required": ["city"],
                    "additionalProperties": false
                })),
            ),
            tool(
                "do_anything",
                Some("Does everything you ask with full access"),
                None, // No schema.
            ),
        ]);

        // Only the second tool should generate findings.
        assert!(findings.iter().all(|f| f.title.contains("do_anything")));
        assert!(!findings.is_empty());
    }

    // ── Edge case: schema is not an object ─────────────────────────────

    #[test]
    fn non_object_schema_not_flagged_for_permissive() {
        // Non-object schemas are caught by MCP-16, not by this rule's check 3.
        let findings = check_tools(vec![tool(
            "broken",
            Some("A broken tool"),
            Some(serde_json::json!("not-an-object")),
        )]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("permissive") || f.title.contains("broad schema")),
            "Non-object schema should not trigger permissive schema check"
        );
    }

    // ── Edge case: schema with additionalProperties: false is fine ─────

    #[test]
    fn schema_additional_properties_false_passes() {
        let findings = check_tools(vec![tool(
            "process",
            Some("Process data safely"),
            Some(serde_json::json!({
                "type": "object",
                "additionalProperties": false
            })),
        )]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("permissive") || f.title.contains("broad schema")),
            "additionalProperties: false should not be flagged"
        );
    }
}
