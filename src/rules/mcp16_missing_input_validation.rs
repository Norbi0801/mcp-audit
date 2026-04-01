//! MCP-16: Missing Input Validation
//!
//! Detects MCP tools that lack proper input validation in their definitions.
//! Weak or absent input schemas allow arbitrary data to reach tool handlers,
//! enabling path-traversal, injection, denial-of-service, and data-exfiltration
//! attacks.
//!
//! ## Checks
//!
//! 1. **No `inputSchema`** — tool accepts unvalidated input.
//! 2. **No `required` fields** — every parameter is optional, callers can
//!    omit critical constraints.
//! 3. **Unconstrained strings** — `type: "string"` without `pattern`,
//!    `maxLength`, `enum`, `const`, or `format` is a path-traversal /
//!    injection risk.
//! 4. **Open objects** — `additionalProperties: true` (or absent) with no
//!    `maxProperties` lets callers inject arbitrary keys.
//! 5. **Missing `enum` where expected** — parameter names that strongly
//!    suggest a fixed set of values (e.g., `mode`, `format`, `action`) but
//!    lack an `enum` constraint.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

// ── Constants ───────────────────────────────────────────────────────────

/// Parameter names that strongly imply a finite set of allowed values and
/// should therefore carry an `enum` constraint.
const ENUM_CANDIDATE_NAMES: &[(&str, &str)] = &[
    ("action", "action type (e.g., read/write/delete)"),
    ("mode", "operation mode"),
    ("method", "HTTP/RPC method"),
    ("type", "resource type"),
    ("format", "output/input format"),
    ("encoding", "character encoding"),
    ("compression", "compression algorithm"),
    ("strategy", "processing strategy"),
    ("direction", "direction (e.g., asc/desc, in/out)"),
    ("level", "severity/log level"),
    ("status", "status value"),
    ("role", "user/system role"),
    ("protocol", "communication protocol"),
    ("transport", "transport type"),
    ("locale", "locale/language identifier"),
    ("region", "cloud/geographic region"),
    ("tier", "service/pricing tier"),
    ("priority", "priority level"),
    ("visibility", "visibility scope"),
    ("operation", "operation kind"),
    ("category", "content/item category"),
    ("kind", "resource kind"),
    ("variant", "variant identifier"),
    ("algorithm", "algorithm selection"),
    ("output_format", "output format"),
    ("input_format", "input format"),
    ("log_level", "log level"),
    ("sort_order", "sort order (asc/desc)"),
    ("sort_by", "sort field"),
    ("order", "ordering direction"),
    ("environment", "deployment environment"),
    ("env", "deployment environment"),
    ("stage", "pipeline stage"),
    ("state", "state value"),
];

/// Parameter names that suggest file-system paths and are especially
/// dangerous without `pattern` or `maxLength` constraints.
const PATH_LIKE_PARAM_NAMES: &[&str] = &[
    "path",
    "file_path",
    "filepath",
    "file",
    "filename",
    "file_name",
    "dir",
    "directory",
    "dir_path",
    "folder",
    "folder_path",
    "src",
    "dst",
    "source_path",
    "dest_path",
    "destination_path",
    "target_path",
    "target",
    "working_dir",
    "workdir",
    "cwd",
    "root",
    "root_dir",
    "base_dir",
    "base_path",
    "output_path",
    "input_path",
    "log_path",
    "config_path",
    "template_path",
    "upload_path",
    "download_path",
];

/// Parameter names that suggest URL/URI values and need format or pattern
/// constraints to prevent SSRF.
const URL_LIKE_PARAM_NAMES: &[&str] = &[
    "url",
    "uri",
    "endpoint",
    "href",
    "link",
    "webhook_url",
    "callback_url",
    "redirect_url",
    "redirect_uri",
    "base_url",
    "api_url",
    "server_url",
    "image_url",
    "source_url",
    "target_url",
    "download_url",
];

// ── Rule implementation ─────────────────────────────────────────────────

pub struct MissingInputValidationRule;

impl super::Rule for MissingInputValidationRule {
    fn id(&self) -> &'static str {
        "MCP-16"
    }

    fn name(&self) -> &'static str {
        "Missing Input Validation"
    }

    fn description(&self) -> &'static str {
        "Detects MCP tools whose input schemas are missing, incomplete, or \
         lack constraints such as required fields, string patterns, maxLength, \
         enum restrictions, or object property limits — all of which leave \
         tools vulnerable to path traversal, injection, and abuse."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-04"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let tools = match &server.tools {
            Some(t) if !t.is_empty() => t,
            _ => return findings,
        };

        for tool in tools {
            // ── Check 1: Tool has no inputSchema at all ────────────────
            let schema = match &tool.input_schema {
                Some(s) => s,
                None => {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Tool '{}' in server '{}' has no inputSchema",
                            tool.name, server_name
                        ),
                        description: format!(
                            "Tool '{}' does not define an inputSchema. Without a \
                             schema the MCP client cannot validate parameters before \
                             sending them, allowing arbitrary data to reach the tool \
                             handler. Define a JSON Schema with explicit types, \
                             required fields, and constraints.",
                            tool.name
                        ),
                    });
                    continue;
                }
            };

            // Treat non-object schemas (e.g., null, empty string) as absent.
            if !schema.is_object() {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' has invalid inputSchema (not an object)",
                        tool.name, server_name
                    ),
                    description: format!(
                        "Tool '{}' has an inputSchema that is not a JSON object. \
                         A valid inputSchema must be a JSON Schema object with \
                         \"type\", \"properties\", and \"required\" fields.",
                        tool.name
                    ),
                });
                continue;
            }

            // ── Check 1b: Schema is an empty object ────────────────────
            if schema.as_object().is_none_or(|o| o.is_empty()) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Tool '{}' in server '{}' has empty inputSchema",
                        tool.name, server_name
                    ),
                    description: format!(
                        "Tool '{}' defines an inputSchema that is an empty object \
                         ({{}}). This provides no validation whatsoever. Add \
                         \"type\": \"object\", \"properties\", and \"required\".",
                        tool.name
                    ),
                });
                continue;
            }

            let properties = schema.get("properties").and_then(|p| p.as_object());

            // ── Check 2: No required fields ────────────────────────────
            let required = schema.get("required").and_then(|r| r.as_array());
            let has_properties = properties.is_some_and(|p| !p.is_empty());

            if has_properties {
                match required {
                    None => {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Medium,
                            title: format!(
                                "Tool '{}' in server '{}' schema has no required fields",
                                tool.name, server_name
                            ),
                            description: format!(
                                "Tool '{}' defines properties but no \"required\" array. \
                                 All parameters are optional, so callers may omit \
                                 critical inputs. Add a \"required\" array listing \
                                 the parameters that must always be present.",
                                tool.name
                            ),
                        });
                    }
                    Some(arr) if arr.is_empty() => {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Medium,
                            title: format!(
                                "Tool '{}' in server '{}' schema has empty required array",
                                tool.name, server_name
                            ),
                            description: format!(
                                "Tool '{}' defines a \"required\" array that is empty. \
                                 All parameters are effectively optional. Populate the \
                                 array with the names of mandatory parameters.",
                                tool.name
                            ),
                        });
                    }
                    _ => {}
                }
            }

            // ── Check 3 & 5: Per-property checks ───────────────────────
            if let Some(props) = properties {
                for (param_name, param_schema) in props {
                    let param_lower = param_name.to_lowercase();
                    let param_type = param_schema
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");

                    // Check 3: Unconstrained string parameters.
                    if param_type == "string" && !has_string_constraints(param_schema) {
                        // Determine if this is a sensitive parameter type.
                        let is_path = PATH_LIKE_PARAM_NAMES.contains(&param_lower.as_str());
                        let is_url = URL_LIKE_PARAM_NAMES.contains(&param_lower.as_str());

                        let (severity, risk_detail) = if is_path {
                            (
                                Severity::High,
                                "path-like parameter without constraints is a \
                                 path traversal risk (e.g., ../../etc/passwd)",
                            )
                        } else if is_url {
                            (
                                Severity::High,
                                "URL parameter without constraints is a \
                                 server-side request forgery (SSRF) risk",
                            )
                        } else {
                            (
                                Severity::Medium,
                                "unconstrained string parameter can receive \
                                 arbitrarily long or malicious input",
                            )
                        };

                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity,
                            title: format!(
                                "Tool '{}' in server '{}' has unconstrained string \
                                 parameter '{}'",
                                tool.name, server_name, param_name
                            ),
                            description: format!(
                                "Parameter '{}' in tool '{}' is type \"string\" with \
                                 no pattern, maxLength, enum, const, or format \
                                 constraint — {}. Add at least a maxLength and, \
                                 where applicable, a pattern or enum.",
                                param_name, tool.name, risk_detail
                            ),
                        });
                    }

                    // Check 5: Missing enum for names that imply fixed values.
                    if param_type == "string" {
                        let has_enum = param_schema.get("enum").is_some()
                            || param_schema.get("const").is_some();

                        if !has_enum {
                            for (candidate, what) in ENUM_CANDIDATE_NAMES {
                                if param_lower == *candidate {
                                    findings.push(ScanFinding {
                                        rule_id: self.id().to_string(),
                                        severity: Severity::Medium,
                                        title: format!(
                                            "Tool '{}' in server '{}' parameter '{}' \
                                             should use enum constraint",
                                            tool.name, server_name, param_name
                                        ),
                                        description: format!(
                                            "Parameter '{}' in tool '{}' appears to \
                                             represent {} but does not define an \
                                             \"enum\" or \"const\" constraint. Without \
                                             an explicit set of allowed values, callers \
                                             can pass unexpected inputs. Add an \"enum\" \
                                             array listing valid options.",
                                            param_name, tool.name, what
                                        ),
                                    });
                                    break;
                                }
                            }
                        }
                    }

                    // Check 4 (nested): Object-typed parameter without
                    // additionalProperties: false.
                    if param_type == "object" {
                        check_open_object(
                            param_schema,
                            &tool.name,
                            Some(param_name),
                            server_name,
                            self.id(),
                            &mut findings,
                        );
                    }
                }
            }

            // ── Check 4: Top-level open object ─────────────────────────
            let top_type = schema.get("type").and_then(|t| t.as_str());
            if top_type == Some("object") {
                check_open_object(
                    schema,
                    &tool.name,
                    None,
                    server_name,
                    self.id(),
                    &mut findings,
                );
            }
        }

        findings
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Returns `true` if a string-typed JSON Schema property carries at least
/// one constraint that limits what values can be supplied.
fn has_string_constraints(schema: &serde_json::Value) -> bool {
    schema.get("pattern").is_some()
        || schema.get("enum").is_some()
        || schema.get("const").is_some()
        || schema.get("maxLength").is_some()
        || schema.get("format").is_some()
        || schema
            .get("minLength")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0
}

/// Emit a finding if an object schema allows arbitrary additional properties
/// without `maxProperties`.
///
/// In JSON Schema, `additionalProperties` defaults to `true` when absent,
/// so we flag schemas that either explicitly set it to `true` or omit it
/// entirely (unless `maxProperties` is present to cap the damage).
fn check_open_object(
    schema: &serde_json::Value,
    tool_name: &str,
    param_name: Option<&str>,
    server_name: &str,
    rule_id: &str,
    findings: &mut Vec<ScanFinding>,
) {
    let additional = schema.get("additionalProperties");
    let is_explicitly_false = additional.and_then(|v| v.as_bool()) == Some(false);
    // additionalProperties can also be a schema object (restricts keys to
    // that schema), which is acceptable as a constraint.
    let is_schema_object = additional.is_some_and(|v| v.is_object());

    if is_explicitly_false || is_schema_object {
        return; // Constrained.
    }

    // If additionalProperties is true or absent, check for maxProperties.
    let has_max = schema.get("maxProperties").is_some();
    if has_max {
        return; // Capped.
    }

    let location = match param_name {
        Some(p) => format!("parameter '{}'", p),
        None => "top-level schema".to_string(),
    };

    findings.push(ScanFinding {
        rule_id: rule_id.to_string(),
        severity: Severity::Medium,
        title: format!(
            "Tool '{}' in server '{}' {} accepts arbitrary additional properties",
            tool_name, server_name, location
        ),
        description: format!(
            "The {} of tool '{}' is an object schema that does not set \
             \"additionalProperties\": false and has no \"maxProperties\" \
             limit. Callers can inject arbitrary keys which may be \
             forwarded unsanitized to downstream systems. Set \
             \"additionalProperties\": false or add a \"maxProperties\" cap.",
            location, tool_name
        ),
    });
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::McpToolDefinition;
    use crate::rules::Rule;
    use serde_json::json;

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Create a server with the given tools and run the rule.
    fn check_tools(tools: Vec<McpToolDefinition>) -> Vec<ScanFinding> {
        let rule = MissingInputValidationRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            tools: Some(tools),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn tool(name: &str) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: None,
            input_schema: None,
        }
    }

    fn tool_with_schema(name: &str, schema: serde_json::Value) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: Some("A test tool".to_string()),
            input_schema: Some(schema),
        }
    }

    // ── Rule metadata ───────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = MissingInputValidationRule;
        assert_eq!(rule.id(), "MCP-16");
        assert_eq!(rule.name(), "Missing Input Validation");
        assert_eq!(rule.default_severity(), Severity::High);
        assert_eq!(rule.owasp_id(), "OWASP-MCP-04");
        assert!(!rule.description().is_empty());
    }

    // ── Check 1: No inputSchema ─────────────────────────────────────────

    #[test]
    fn detects_tool_without_input_schema() {
        let findings = check_tools(vec![tool("read_file")]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("no inputSchema")),
            "Should detect tool without inputSchema: {:?}",
            findings
        );
    }

    #[test]
    fn detects_multiple_tools_without_schema() {
        let findings = check_tools(vec![tool("read_file"), tool("write_file")]);
        let no_schema_count = findings
            .iter()
            .filter(|f| f.title.contains("no inputSchema"))
            .count();
        assert_eq!(no_schema_count, 2);
    }

    #[test]
    fn detects_invalid_schema_type() {
        let findings = check_tools(vec![McpToolDefinition {
            name: "bad_tool".into(),
            description: None,
            input_schema: Some(json!("not an object")),
        }]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("invalid inputSchema")));
    }

    #[test]
    fn detects_empty_schema_object() {
        let findings = check_tools(vec![tool_with_schema("empty_tool", json!({}))]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("empty inputSchema")));
    }

    #[test]
    fn detects_null_schema() {
        let findings = check_tools(vec![McpToolDefinition {
            name: "null_schema".into(),
            description: None,
            input_schema: Some(json!(null)),
        }]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("invalid inputSchema")
                    || f.title.contains("no inputSchema"))
        );
    }

    // ── Check 2: No required fields ─────────────────────────────────────

    #[test]
    fn detects_schema_without_required() {
        let findings = check_tools(vec![tool_with_schema(
            "fetch_data",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("no required fields")),
            "Should detect missing required array: {:?}",
            findings
        );
    }

    #[test]
    fn detects_empty_required_array() {
        let findings = check_tools(vec![tool_with_schema(
            "update_item",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string" }
                },
                "required": []
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("empty required array")));
    }

    #[test]
    fn passes_schema_with_required() {
        let findings = check_tools(vec![tool_with_schema(
            "get_item",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "maxLength": 64 }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        )]);
        let required_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("required"))
            .collect();
        assert!(
            required_findings.is_empty(),
            "Should not flag schema with required fields: {:?}",
            required_findings
        );
    }

    // ── Check 3: Unconstrained string parameters ────────────────────────

    #[test]
    fn detects_unconstrained_string() {
        let findings = check_tools(vec![tool_with_schema(
            "search",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("unconstrained string")));
    }

    #[test]
    fn detects_path_parameter_as_high_severity() {
        let findings = check_tools(vec![tool_with_schema(
            "read_file",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"],
                "additionalProperties": false
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::High
                && f.title.contains("unconstrained string")
                && f.title.contains("'path'")),
            "Path-like parameters should be High severity: {:?}",
            findings
        );
    }

    #[test]
    fn detects_file_path_parameter() {
        let findings = check_tools(vec![tool_with_schema(
            "save_doc",
            json!({
                "type": "object",
                "properties": {
                    "file_path": { "type": "string" }
                },
                "required": ["file_path"],
                "additionalProperties": false
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("'file_path'")));
    }

    #[test]
    fn detects_url_parameter_as_high_severity() {
        let findings = check_tools(vec![tool_with_schema(
            "fetch_page",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string" }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::High
                && f.title.contains("unconstrained string")
                && f.title.contains("'url'")),
            "URL parameters should be High severity: {:?}",
            findings
        );
    }

    #[test]
    fn passes_string_with_pattern() {
        let findings = check_tools(vec![tool_with_schema(
            "get_item",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "pattern": "^[a-zA-Z0-9_-]+$" }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string"))
            .collect();
        assert!(
            unconstrained.is_empty(),
            "String with pattern should pass: {:?}",
            unconstrained
        );
    }

    #[test]
    fn passes_string_with_max_length() {
        let findings = check_tools(vec![tool_with_schema(
            "search",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "maxLength": 200 }
                },
                "required": ["query"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    #[test]
    fn passes_string_with_enum() {
        let findings = check_tools(vec![tool_with_schema(
            "set_mode",
            json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string", "enum": ["fast", "safe"] }
                },
                "required": ["mode"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string") && f.title.contains("'mode'"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    #[test]
    fn passes_string_with_format() {
        let findings = check_tools(vec![tool_with_schema(
            "parse_date",
            json!({
                "type": "object",
                "properties": {
                    "date": { "type": "string", "format": "date-time" }
                },
                "required": ["date"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    #[test]
    fn passes_string_with_const() {
        let findings = check_tools(vec![tool_with_schema(
            "fixed_tool",
            json!({
                "type": "object",
                "properties": {
                    "version": { "type": "string", "const": "v1" }
                },
                "required": ["version"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    #[test]
    fn passes_string_with_positive_min_length() {
        let findings = check_tools(vec![tool_with_schema(
            "tool_x",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "minLength": 1 }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string") && f.title.contains("'name'"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    #[test]
    fn flags_string_with_zero_min_length() {
        let findings = check_tools(vec![tool_with_schema(
            "tool_y",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "minLength": 0 }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("unconstrained string") && f.title.contains("'name'")));
    }

    #[test]
    fn non_string_types_not_flagged_for_string_constraints() {
        let findings = check_tools(vec![tool_with_schema(
            "calc",
            json!({
                "type": "object",
                "properties": {
                    "count": { "type": "integer" },
                    "enabled": { "type": "boolean" }
                },
                "required": ["count"],
                "additionalProperties": false
            }),
        )]);
        let unconstrained: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("unconstrained string"))
            .collect();
        assert!(unconstrained.is_empty());
    }

    // ── Check 4: Open objects (additionalProperties) ────────────────────

    #[test]
    fn detects_top_level_open_object() {
        let findings = check_tools(vec![tool_with_schema(
            "open_tool",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "maxLength": 64 }
                },
                "required": ["id"]
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("arbitrary additional properties")
                    && f.title.contains("top-level schema")),
            "Should detect top-level open object: {:?}",
            findings
        );
    }

    #[test]
    fn detects_explicit_additional_properties_true() {
        let findings = check_tools(vec![tool_with_schema(
            "flexible_tool",
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "maxLength": 100 }
                },
                "required": ["name"],
                "additionalProperties": true
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("arbitrary additional properties")));
    }

    #[test]
    fn detects_nested_open_object() {
        let findings = check_tools(vec![tool_with_schema(
            "nested_tool",
            json!({
                "type": "object",
                "properties": {
                    "options": { "type": "object" }
                },
                "required": ["options"],
                "additionalProperties": false
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("arbitrary additional properties")
                    && f.title.contains("'options'")),
            "Should detect nested open object: {:?}",
            findings
        );
    }

    #[test]
    fn passes_additional_properties_false() {
        let findings = check_tools(vec![tool_with_schema(
            "strict_tool",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "maxLength": 64 }
                },
                "required": ["id"],
                "additionalProperties": false
            }),
        )]);
        let open_obj: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("arbitrary additional properties"))
            .collect();
        assert!(
            open_obj.is_empty(),
            "Should not flag strict schema: {:?}",
            open_obj
        );
    }

    #[test]
    fn passes_additional_properties_schema() {
        // additionalProperties can be a schema object that restricts
        // extra keys to a particular type — this is acceptable.
        let findings = check_tools(vec![tool_with_schema(
            "typed_extras",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "maxLength": 64 }
                },
                "required": ["id"],
                "additionalProperties": { "type": "string", "maxLength": 100 }
            }),
        )]);
        let open_obj: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("arbitrary additional properties"))
            .collect();
        assert!(open_obj.is_empty());
    }

    #[test]
    fn passes_open_object_with_max_properties() {
        let findings = check_tools(vec![tool_with_schema(
            "capped_tool",
            json!({
                "type": "object",
                "properties": {
                    "id": { "type": "string", "maxLength": 64 }
                },
                "required": ["id"],
                "maxProperties": 5
            }),
        )]);
        let open_obj: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("arbitrary additional properties"))
            .collect();
        assert!(open_obj.is_empty());
    }

    // ── Check 5: Missing enum constraints ───────────────────────────────

    #[test]
    fn detects_missing_enum_for_mode() {
        let findings = check_tools(vec![tool_with_schema(
            "process",
            json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string" }
                },
                "required": ["mode"],
                "additionalProperties": false
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("should use enum")),
            "Should flag 'mode' without enum: {:?}",
            findings
        );
    }

    #[test]
    fn detects_missing_enum_for_action() {
        let findings = check_tools(vec![tool_with_schema(
            "dispatcher",
            json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "maxLength": 50 }
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        )]);
        assert!(findings.iter().any(|f| f.title.contains("should use enum")));
    }

    #[test]
    fn detects_missing_enum_for_format() {
        let findings = check_tools(vec![tool_with_schema(
            "exporter",
            json!({
                "type": "object",
                "properties": {
                    "format": { "type": "string" }
                },
                "required": ["format"],
                "additionalProperties": false
            }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("should use enum") && f.title.contains("'format'")));
    }

    #[test]
    fn passes_enum_parameter_with_enum() {
        let findings = check_tools(vec![tool_with_schema(
            "select_mode",
            json!({
                "type": "object",
                "properties": {
                    "mode": { "type": "string", "enum": ["fast", "slow"] }
                },
                "required": ["mode"],
                "additionalProperties": false
            }),
        )]);
        let enum_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("should use enum"))
            .collect();
        assert!(
            enum_findings.is_empty(),
            "Mode with enum should pass: {:?}",
            enum_findings
        );
    }

    #[test]
    fn passes_enum_parameter_with_const() {
        let findings = check_tools(vec![tool_with_schema(
            "fixed_action",
            json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "const": "run" }
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        )]);
        let enum_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("should use enum"))
            .collect();
        assert!(enum_findings.is_empty());
    }

    #[test]
    fn non_enum_param_name_not_flagged() {
        let findings = check_tools(vec![tool_with_schema(
            "tool_x",
            json!({
                "type": "object",
                "properties": {
                    "description": { "type": "string", "maxLength": 500 }
                },
                "required": ["description"],
                "additionalProperties": false
            }),
        )]);
        let enum_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("should use enum"))
            .collect();
        assert!(enum_findings.is_empty());
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn no_findings_for_server_without_tools() {
        let rule = MissingInputValidationRule;
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
    fn no_findings_for_empty_tools_list() {
        let findings = check_tools(vec![]);
        assert!(findings.is_empty());
    }

    #[test]
    fn well_defined_tool_has_minimal_findings() {
        let findings = check_tools(vec![tool_with_schema(
            "well_defined",
            json!({
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "pattern": "^[a-f0-9-]{36}$",
                        "maxLength": 36
                    },
                    "count": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100
                    }
                },
                "required": ["id", "count"],
                "additionalProperties": false
            }),
        )]);
        assert!(
            findings.is_empty(),
            "Well-defined tool should have zero findings: {:?}",
            findings
        );
    }

    #[test]
    fn multiple_issues_on_single_tool() {
        // Tool with no required, unconstrained path, open object, and
        // missing enum — should produce multiple findings.
        let findings = check_tools(vec![tool_with_schema(
            "multi_bad",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "mode": { "type": "string" },
                    "options": { "type": "object" }
                }
            }),
        )]);
        assert!(
            findings.len() >= 4,
            "Should have at least 4 findings (no required, path, mode enum, \
             open object), got {}: {:?}",
            findings.len(),
            findings
        );
    }

    #[test]
    fn schema_with_only_type_no_properties() {
        // Schema like {"type": "object"} with no properties — should flag
        // open object at top level.
        let findings = check_tools(vec![tool_with_schema(
            "bare_object",
            json!({ "type": "object" }),
        )]);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("arbitrary additional properties")));
    }

    #[test]
    fn all_path_like_params_detected() {
        // Spot-check a few representative path-like param names.
        for param_name in &[
            "path",
            "file_path",
            "directory",
            "working_dir",
            "upload_path",
        ] {
            let mut props = serde_json::Map::new();
            props.insert(param_name.to_string(), json!({ "type": "string" }));
            let findings = check_tools(vec![tool_with_schema(
                "file_tool",
                json!({
                    "type": "object",
                    "properties": props,
                    "required": [param_name],
                    "additionalProperties": false
                }),
            )]);
            assert!(
                findings
                    .iter()
                    .any(|f| f.severity == Severity::High
                        && f.title.contains("unconstrained string")),
                "Path param '{}' should be High severity",
                param_name
            );
        }
    }

    #[test]
    fn all_url_like_params_detected() {
        for param_name in &["url", "endpoint", "redirect_url", "webhook_url"] {
            let mut props = serde_json::Map::new();
            props.insert(param_name.to_string(), json!({ "type": "string" }));
            let findings = check_tools(vec![tool_with_schema(
                "net_tool",
                json!({
                    "type": "object",
                    "properties": props,
                    "required": [param_name],
                    "additionalProperties": false
                }),
            )]);
            assert!(
                findings
                    .iter()
                    .any(|f| f.severity == Severity::High
                        && f.title.contains("unconstrained string")),
                "URL param '{}' should be High severity",
                param_name
            );
        }
    }

    #[test]
    fn enum_candidate_names_coverage() {
        // Spot-check a few enum candidate names.
        for param_name in &["action", "format", "level", "protocol", "environment"] {
            let mut props = serde_json::Map::new();
            props.insert(param_name.to_string(), json!({ "type": "string" }));
            let findings = check_tools(vec![tool_with_schema(
                "enum_check",
                json!({
                    "type": "object",
                    "properties": props,
                    "required": [param_name],
                    "additionalProperties": false
                }),
            )]);
            assert!(
                findings.iter().any(|f| f.title.contains("should use enum")),
                "Param '{}' should be flagged as enum candidate",
                param_name
            );
        }
    }
}
