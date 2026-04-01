//! MCP-15: Tool Command Injection
//!
//! Detects MCP tools whose definitions indicate vulnerability to command
//! injection, code injection, or SQL injection. Analyzes tool names,
//! descriptions, and input schemas to identify tools that accept unsanitized
//! user input destined for shell execution, code evaluation, or SQL queries.
//!
//! Unlike MCP-07 (which checks the *server's own* command/args configuration),
//! this rule inspects the *tools exposed by the server* to clients. A tool
//! named `run_command` with a bare `string` parameter called `command` is an
//! obvious injection vector regardless of how safely the server itself is
//! launched.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

// ── Detection patterns ──────────────────────────────────────────────────

/// Tool names that directly indicate command/code execution capability.
const DANGEROUS_TOOL_NAMES: &[(&str, &str)] = &[
    ("run_command", "direct command execution"),
    ("run_cmd", "direct command execution"),
    ("exec_command", "direct command execution"),
    ("exec_cmd", "direct command execution"),
    ("execute_command", "direct command execution"),
    ("execute_cmd", "direct command execution"),
    ("shell_exec", "shell execution"),
    ("shell_execute", "shell execution"),
    ("run_shell", "shell execution"),
    ("run_bash", "shell execution"),
    ("run_script", "script execution"),
    ("exec_script", "script execution"),
    ("execute_script", "script execution"),
    ("run_code", "code execution"),
    ("exec_code", "code execution"),
    ("execute_code", "code execution"),
    ("eval_code", "code evaluation"),
    ("eval_expression", "code evaluation"),
    ("eval_script", "code evaluation"),
    ("system_exec", "system-level execution"),
    ("system_command", "system-level execution"),
    ("os_exec", "operating system execution"),
    ("os_command", "operating system execution"),
    ("spawn_process", "process spawning"),
    ("popen", "process open"),
    ("subprocess", "subprocess execution"),
    ("run_sql", "direct SQL execution"),
    ("exec_sql", "direct SQL execution"),
    ("execute_sql", "direct SQL execution"),
    ("raw_query", "raw database query"),
    ("raw_sql", "raw SQL execution"),
];

/// Keywords in tool descriptions that indicate command/shell execution.
const DESCRIPTION_EXEC_KEYWORDS: &[(&str, &str)] = &[
    ("execute a command", "command execution"),
    ("execute command", "command execution"),
    ("execute a shell", "shell execution"),
    ("execute shell", "shell execution"),
    ("run a command", "command execution"),
    ("run command", "command execution"),
    ("run a shell", "shell execution"),
    ("run shell", "shell execution"),
    ("runs a command", "command execution"),
    ("runs a shell", "shell execution"),
    ("executes a command", "command execution"),
    ("executes a shell", "shell execution"),
    ("execute arbitrary", "arbitrary execution"),
    ("run arbitrary", "arbitrary execution"),
    ("system command", "system command execution"),
    ("shell command", "shell command execution"),
    ("bash command", "bash command execution"),
    ("os command", "OS command execution"),
    ("subprocess", "subprocess execution"),
    ("child_process", "child process execution"),
    ("child process", "child process execution"),
    ("spawn process", "process spawning"),
    ("command line", "command-line execution"),
    ("command-line", "command-line execution"),
    ("invoke command", "command invocation"),
    ("call system", "system call"),
];

/// Keywords in tool descriptions that indicate code evaluation.
const DESCRIPTION_EVAL_KEYWORDS: &[(&str, &str)] = &[
    ("eval(", "code evaluation"),
    ("evaluate code", "code evaluation"),
    ("evaluate expression", "expression evaluation"),
    ("execute code", "code execution"),
    ("execute javascript", "JavaScript execution"),
    ("execute python", "Python execution"),
    ("run javascript", "JavaScript execution"),
    ("run python", "Python execution"),
    ("run code", "code execution"),
    ("interpret code", "code interpretation"),
    ("dynamic execution", "dynamic code execution"),
    ("runtime execution", "runtime code execution"),
    ("compile and run", "compile-and-run"),
    ("exec(", "code execution"),
];

/// Keywords in tool descriptions that indicate SQL/database query execution.
const DESCRIPTION_SQL_KEYWORDS: &[(&str, &str)] = &[
    ("execute sql", "SQL execution"),
    ("execute a sql", "SQL execution"),
    ("run sql", "SQL execution"),
    ("run a sql", "SQL execution"),
    ("sql query", "SQL query"),
    ("raw query", "raw query execution"),
    ("raw sql", "raw SQL execution"),
    ("database query", "database query"),
    ("db query", "database query"),
    ("query the database", "database query"),
    ("query database", "database query"),
    ("direct sql", "direct SQL access"),
    ("arbitrary sql", "arbitrary SQL execution"),
    ("arbitrary query", "arbitrary query execution"),
];

/// Parameter names that strongly indicate shell/command injection risk.
const DANGEROUS_PARAM_NAMES: &[(&str, &str)] = &[
    ("command", "shell command input"),
    ("cmd", "shell command input"),
    ("shell_command", "shell command input"),
    ("shell_cmd", "shell command input"),
    ("bash_command", "bash command input"),
    ("exec", "execution input"),
    ("execute", "execution input"),
    ("script", "script input"),
    ("shell", "shell input"),
    ("program", "program input"),
    ("system_command", "system command input"),
    ("run", "run input"),
    ("cmdline", "command-line input"),
    ("command_line", "command-line input"),
];

/// Parameter names that indicate SQL injection risk.
const SQL_PARAM_NAMES: &[(&str, &str)] = &[
    ("query", "SQL query input"),
    ("sql", "SQL statement input"),
    ("sql_query", "SQL query input"),
    ("sql_statement", "SQL statement input"),
    ("raw_query", "raw SQL query input"),
    ("raw_sql", "raw SQL input"),
    ("where_clause", "SQL WHERE clause"),
    ("where", "SQL WHERE clause"),
    ("filter_expression", "filter expression"),
    ("statement", "statement input"),
    ("db_query", "database query input"),
];

/// Parameter names that indicate code evaluation risk.
const EVAL_PARAM_NAMES: &[(&str, &str)] = &[
    ("code", "code evaluation input"),
    ("source_code", "source code input"),
    ("source", "source code input"),
    ("expression", "expression evaluation input"),
    ("eval", "eval input"),
    ("eval_code", "eval code input"),
    ("js", "JavaScript code input"),
    ("javascript", "JavaScript code input"),
    ("python", "Python code input"),
    ("python_code", "Python code input"),
    ("lua", "Lua code input"),
    ("lua_code", "Lua code input"),
    ("snippet", "code snippet input"),
];

// ── Rule implementation ─────────────────────────────────────────────────

pub struct ToolInjectionRule;

impl super::Rule for ToolInjectionRule {
    fn id(&self) -> &'static str {
        "MCP-15"
    }

    fn name(&self) -> &'static str {
        "Tool Command Injection"
    }

    fn description(&self) -> &'static str {
        "Detects MCP tools vulnerable to command injection, code injection, \
         or SQL injection by analyzing tool names, descriptions, and input \
         schemas for dangerous execution patterns and unsanitized parameters."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-07"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let tools = match &server.tools {
            Some(t) if !t.is_empty() => t,
            _ => return findings,
        };

        for tool in tools {
            let tool_name_lower = tool.name.to_lowercase();
            let desc_lower = tool.description.as_deref().unwrap_or("").to_lowercase();

            // ── Check 1: Dangerous tool name ────────────────────────────
            for (pattern, category) in DANGEROUS_TOOL_NAMES {
                if tool_name_lower == *pattern || tool_name_lower.contains(pattern) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Tool '{}' in server '{}' has dangerous name indicating {}",
                            tool.name, server_name, category
                        ),
                        description: format!(
                            "Tool '{}' name contains '{}' which indicates {}. \
                             Tools that execute commands, code, or queries on behalf of \
                             users are prime injection targets. Restrict tool capabilities \
                             or implement strict input validation.",
                            tool.name, pattern, category
                        ),
                    });
                    break; // One name finding per tool.
                }
            }

            let desc_ctx = DescCheckCtx {
                tool_name: &tool.name,
                server_name,
                rule_id: self.id(),
            };

            // ── Check 2: Description suggests command execution ─────────
            check_description_keywords(
                &desc_lower,
                DESCRIPTION_EXEC_KEYWORDS,
                &desc_ctx,
                Severity::Critical,
                "command execution",
                &mut findings,
            );

            // ── Check 3: Description suggests code evaluation ───────────
            check_description_keywords(
                &desc_lower,
                DESCRIPTION_EVAL_KEYWORDS,
                &desc_ctx,
                Severity::Critical,
                "code evaluation",
                &mut findings,
            );

            // ── Check 4: Description suggests SQL execution ─────────────
            check_description_keywords(
                &desc_lower,
                DESCRIPTION_SQL_KEYWORDS,
                &desc_ctx,
                Severity::High,
                "SQL execution",
                &mut findings,
            );

            // ── Check 5: Dangerous input parameters ─────────────────────
            if let Some(schema) = &tool.input_schema {
                let properties = schema.get("properties").and_then(|p| p.as_object());

                if let Some(props) = properties {
                    for (param_name, param_schema) in props {
                        let param_lower = param_name.to_lowercase();
                        let param_type = param_schema
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("");

                        // Only check string parameters — they are the
                        // injection vectors.
                        if param_type != "string" {
                            continue;
                        }

                        let has_sanitization = has_input_constraints(param_schema);

                        // 5a: Command injection parameters.
                        for (dangerous_name, category) in DANGEROUS_PARAM_NAMES {
                            if param_lower == *dangerous_name {
                                let severity = if has_sanitization {
                                    Severity::Medium
                                } else {
                                    Severity::Critical
                                };

                                findings.push(ScanFinding {
                                    rule_id: self.id().to_string(),
                                    severity,
                                    title: format!(
                                        "Tool '{}' in server '{}' has {} parameter '{}'{}",
                                        tool.name,
                                        server_name,
                                        category,
                                        param_name,
                                        if has_sanitization {
                                            " (has some constraints)"
                                        } else {
                                            " without input validation"
                                        }
                                    ),
                                    description: format!(
                                        "Tool '{}' accepts a string parameter '{}' ({}) \
                                         {}. This parameter could be used to inject \
                                         shell commands if passed to a system call. \
                                         Add pattern validation, enum constraints, or \
                                         maxLength limits to the inputSchema.",
                                        tool.name,
                                        param_name,
                                        category,
                                        if has_sanitization {
                                            "with basic constraints that may be insufficient"
                                        } else {
                                            "with no input validation in the schema"
                                        }
                                    ),
                                });
                                break;
                            }
                        }

                        // 5b: SQL injection parameters.
                        for (sql_name, category) in SQL_PARAM_NAMES {
                            if param_lower == *sql_name {
                                let severity = if has_sanitization {
                                    Severity::Medium
                                } else {
                                    Severity::High
                                };

                                findings.push(ScanFinding {
                                    rule_id: self.id().to_string(),
                                    severity,
                                    title: format!(
                                        "Tool '{}' in server '{}' has {} parameter '{}'{}",
                                        tool.name,
                                        server_name,
                                        category,
                                        param_name,
                                        if has_sanitization {
                                            " (has some constraints)"
                                        } else {
                                            " without input validation"
                                        }
                                    ),
                                    description: format!(
                                        "Tool '{}' accepts a string parameter '{}' ({}) \
                                         {}. Unsanitized query parameters are a classic \
                                         SQL injection vector. Use parameterized queries \
                                         and add schema validation.",
                                        tool.name,
                                        param_name,
                                        category,
                                        if has_sanitization {
                                            "with constraints that may not prevent injection"
                                        } else {
                                            "with no input validation"
                                        }
                                    ),
                                });
                                break;
                            }
                        }

                        // 5c: Code eval parameters.
                        for (eval_name, category) in EVAL_PARAM_NAMES {
                            if param_lower == *eval_name {
                                let severity = if has_sanitization {
                                    Severity::Medium
                                } else {
                                    Severity::Critical
                                };

                                findings.push(ScanFinding {
                                    rule_id: self.id().to_string(),
                                    severity,
                                    title: format!(
                                        "Tool '{}' in server '{}' has {} parameter '{}'{}",
                                        tool.name,
                                        server_name,
                                        category,
                                        param_name,
                                        if has_sanitization {
                                            " (has some constraints)"
                                        } else {
                                            " without input validation"
                                        }
                                    ),
                                    description: format!(
                                        "Tool '{}' accepts a string parameter '{}' ({}) \
                                         {}. Code evaluation parameters allow arbitrary \
                                         code execution if not properly sandboxed. \
                                         Add strict validation or use an allowlist.",
                                        tool.name,
                                        param_name,
                                        category,
                                        if has_sanitization {
                                            "with constraints that may be insufficient for code"
                                        } else {
                                            "with no input validation"
                                        }
                                    ),
                                });
                                break;
                            }
                        }

                        // 5d: Parameter description hints at injection risk.
                        let param_desc = param_schema
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_lowercase();

                        if !param_desc.is_empty() && !has_sanitization {
                            check_param_description_injection(
                                &param_desc,
                                &tool.name,
                                param_name,
                                server_name,
                                self.id(),
                                &mut findings,
                            );
                        }
                    }
                }
            }
        }

        findings
    }
}

// ── Helper functions ────────────────────────────────────────────────────

/// Context passed to description keyword checks to avoid excessive params.
struct DescCheckCtx<'a> {
    tool_name: &'a str,
    server_name: &'a str,
    rule_id: &'a str,
}

/// Check if a tool description contains any of the given keywords and emit
/// at most one finding per keyword category.
fn check_description_keywords(
    desc_lower: &str,
    keywords: &[(&str, &str)],
    ctx: &DescCheckCtx<'_>,
    severity: Severity,
    risk_category: &str,
    findings: &mut Vec<ScanFinding>,
) {
    for (keyword, explanation) in keywords {
        if desc_lower.contains(keyword) {
            findings.push(ScanFinding {
                rule_id: ctx.rule_id.to_string(),
                severity,
                title: format!(
                    "Tool '{}' in server '{}' description suggests {}",
                    ctx.tool_name, ctx.server_name, risk_category
                ),
                description: format!(
                    "Tool '{}' description contains '{}' ({}). \
                     Tools that perform {} are high-risk injection targets. \
                     Ensure all inputs are validated and sanitized before use.",
                    ctx.tool_name, keyword, explanation, risk_category
                ),
            });
            return; // One finding per category.
        }
    }
}

/// Check if a JSON Schema property has any input constraints that would
/// limit injection attacks: `pattern`, `enum`, `const`, `maxLength`, or
/// `format`.
fn has_input_constraints(schema: &serde_json::Value) -> bool {
    schema.get("pattern").is_some()
        || schema.get("enum").is_some()
        || schema.get("const").is_some()
        || schema.get("maxLength").is_some()
        || schema.get("format").is_some()
}

/// Check parameter descriptions for injection-indicating phrases.
fn check_param_description_injection(
    param_desc: &str,
    tool_name: &str,
    param_name: &str,
    server_name: &str,
    rule_id: &str,
    findings: &mut Vec<ScanFinding>,
) {
    const PARAM_DESC_EXEC_HINTS: &[&str] = &[
        "shell command",
        "system command",
        "command to execute",
        "command to run",
        "bash command",
        "execute on the system",
        "passed to shell",
        "passed to exec",
        "passed to system",
        "run on the server",
        "sql to execute",
        "query to execute",
        "query to run",
        "code to execute",
        "code to evaluate",
        "code to run",
        "script to execute",
        "script to run",
    ];

    for hint in PARAM_DESC_EXEC_HINTS {
        if param_desc.contains(hint) {
            findings.push(ScanFinding {
                rule_id: rule_id.to_string(),
                severity: Severity::High,
                title: format!(
                    "Parameter '{}' of tool '{}' in server '{}' description indicates injection risk",
                    param_name, tool_name, server_name
                ),
                description: format!(
                    "Parameter '{}' description contains '{}' which suggests the \
                     value is passed to an execution context without sanitization. \
                     Add input validation (pattern, enum, maxLength) to the \
                     inputSchema to mitigate injection attacks.",
                    param_name, hint
                ),
            });
            return; // One finding per parameter.
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::McpToolDefinition;
    use crate::rules::Rule;
    use serde_json::json;

    /// Helper: create a server config with the given tools and run the rule.
    fn check_tools(tools: Vec<McpToolDefinition>) -> Vec<ScanFinding> {
        let rule = ToolInjectionRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            tools: Some(tools),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    /// Helper: create a tool definition with just a name.
    fn tool(name: &str) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: None,
            input_schema: None,
        }
    }

    /// Helper: create a tool with name and description.
    fn tool_with_desc(name: &str, desc: &str) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: Some(desc.to_string()),
            input_schema: None,
        }
    }

    /// Helper: create a tool with name, description, and input schema.
    fn tool_with_schema(name: &str, desc: &str, schema: serde_json::Value) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: Some(desc.to_string()),
            input_schema: Some(schema),
        }
    }

    // ── Rule metadata ───────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = ToolInjectionRule;
        assert_eq!(rule.id(), "MCP-15");
        assert_eq!(rule.name(), "Tool Command Injection");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-07");
        assert_eq!(rule.default_severity(), Severity::Critical);
    }

    // ── Check 1: Dangerous tool names ───────────────────────────────────

    #[test]
    fn detects_run_command_tool_name() {
        let findings = check_tools(vec![tool("run_command")]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("dangerous name")),
            "Should detect 'run_command' as dangerous tool name"
        );
    }

    #[test]
    fn detects_exec_code_tool_name() {
        let findings = check_tools(vec![tool("exec_code")]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("dangerous name") && f.title.contains("code execution")),
            "Should detect 'exec_code' as code execution tool"
        );
    }

    #[test]
    fn detects_shell_exec_tool_name() {
        let findings = check_tools(vec![tool("shell_exec")]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("shell execution")),
            "Should detect 'shell_exec' as shell execution tool"
        );
    }

    #[test]
    fn detects_raw_query_tool_name() {
        let findings = check_tools(vec![tool("raw_query")]);
        assert!(
            findings.iter().any(|f| f.title.contains("dangerous name")),
            "Should detect 'raw_query' as dangerous tool name"
        );
    }

    #[test]
    fn detects_run_sql_tool_name() {
        let findings = check_tools(vec![tool("run_sql")]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("dangerous name")),
            "Should detect 'run_sql' as dangerous tool name"
        );
    }

    #[test]
    fn detects_eval_code_tool_name() {
        let findings = check_tools(vec![tool("eval_code")]);
        assert!(
            findings.iter().any(|f| f.title.contains("code evaluation")),
            "Should detect 'eval_code' as code evaluation tool"
        );
    }

    #[test]
    fn detects_subprocess_tool_name() {
        let findings = check_tools(vec![tool("subprocess")]);
        assert!(
            findings.iter().any(|f| f.title.contains("dangerous name")),
            "Should detect 'subprocess' as dangerous tool name"
        );
    }

    #[test]
    fn detects_spawn_process_tool_name() {
        let findings = check_tools(vec![tool("spawn_process")]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("process spawning")),
            "Should detect 'spawn_process' as process spawning tool"
        );
    }

    #[test]
    fn detects_dangerous_name_in_compound_name() {
        let findings = check_tools(vec![tool("admin_run_command_v2")]);
        assert!(
            findings.iter().any(|f| f.title.contains("dangerous name")),
            "Should detect 'run_command' within longer tool name"
        );
    }

    #[test]
    fn safe_tool_name_no_findings() {
        let findings = check_tools(vec![tool("list_files")]);
        assert!(
            !findings.iter().any(|f| f.title.contains("dangerous name")),
            "Safe tool name should not trigger name detection"
        );
    }

    // ── Check 2: Description suggests command execution ─────────────────

    #[test]
    fn detects_execute_command_description() {
        let findings = check_tools(vec![tool_with_desc(
            "my_tool",
            "Execute a command on the host system",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("command execution")),
            "Should detect 'execute a command' in description"
        );
    }

    #[test]
    fn detects_run_shell_description() {
        let findings = check_tools(vec![tool_with_desc(
            "runner",
            "Run a shell script on the server",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("command execution")),
            "Should detect 'run a shell' in description"
        );
    }

    #[test]
    fn detects_subprocess_description() {
        let findings = check_tools(vec![tool_with_desc(
            "process_runner",
            "Launches a subprocess to execute the given program",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("command execution")),
            "Should detect 'subprocess' in description"
        );
    }

    // ── Check 3: Description suggests code evaluation ───────────────────

    #[test]
    fn detects_execute_code_description() {
        let findings = check_tools(vec![tool_with_desc(
            "code_runner",
            "Execute code provided by the user in a sandboxed environment",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("code evaluation")),
            "Should detect 'execute code' in description"
        );
    }

    #[test]
    fn detects_eval_expression_description() {
        let findings = check_tools(vec![tool_with_desc(
            "calculator",
            "Evaluate expression using eval() for dynamic computation",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("code evaluation")),
            "Should detect 'eval(' in description"
        );
    }

    #[test]
    fn detects_run_python_description() {
        let findings = check_tools(vec![tool_with_desc(
            "python_tool",
            "Run Python code from the prompt",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("code evaluation")),
            "Should detect 'run python' in description"
        );
    }

    // ── Check 4: Description suggests SQL execution ─────────────────────

    #[test]
    fn detects_sql_query_description() {
        let findings = check_tools(vec![tool_with_desc(
            "db_tool",
            "Run a SQL query against the production database",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("SQL execution")),
            "Should detect 'sql query' in description"
        );
    }

    #[test]
    fn detects_raw_query_description() {
        let findings = check_tools(vec![tool_with_desc(
            "query_tool",
            "Execute a raw query on the database backend",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("SQL execution")),
            "Should detect 'raw query' in description"
        );
    }

    #[test]
    fn detects_database_query_description() {
        let findings = check_tools(vec![tool_with_desc(
            "analytics",
            "Query the database for analytics data",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("SQL execution")),
            "Should detect 'query the database' in description"
        );
    }

    // ── Check 5a: Dangerous command parameters ──────────────────────────

    #[test]
    fn detects_command_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "command": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical
                && f.title.contains("command")
                && f.title.contains("without input validation")),
            "Should detect unsanitized 'command' parameter as Critical"
        );
    }

    #[test]
    fn detects_cmd_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "cmd": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("cmd")),
            "Should detect unsanitized 'cmd' parameter"
        );
    }

    #[test]
    fn detects_script_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "script_runner",
            "Runs scripts",
            json!({
                "type": "object",
                "properties": {
                    "script": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("script")),
            "Should detect unsanitized 'script' parameter"
        );
    }

    #[test]
    fn command_param_with_pattern_is_medium() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_-]+$"
                    }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Medium
                && f.title.contains("has some constraints")),
            "Constrained 'command' parameter should be Medium severity"
        );
    }

    #[test]
    fn command_param_with_enum_is_medium() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": ["ls", "pwd", "whoami"]
                    }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Medium),
            "Enum-constrained 'command' should be Medium severity"
        );
    }

    #[test]
    fn command_param_with_max_length_is_medium() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "maxLength": 10
                    }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Medium),
            "maxLength-constrained 'command' should be Medium severity"
        );
    }

    // ── Check 5b: SQL injection parameters ──────────────────────────────

    #[test]
    fn detects_query_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "db_tool",
            "Database access",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::High
                && f.title.contains("query")
                && f.title.contains("without input validation")),
            "Should detect unsanitized 'query' parameter as High"
        );
    }

    #[test]
    fn detects_sql_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "admin_tool",
            "Admin DB access",
            json!({
                "type": "object",
                "properties": {
                    "sql": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("SQL statement input")),
            "Should detect unsanitized 'sql' parameter"
        );
    }

    #[test]
    fn detects_where_clause_param() {
        let findings = check_tools(vec![tool_with_schema(
            "filter_tool",
            "Filter records",
            json!({
                "type": "object",
                "properties": {
                    "where_clause": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("SQL WHERE clause")),
            "Should detect 'where_clause' parameter"
        );
    }

    #[test]
    fn query_param_with_pattern_is_medium() {
        let findings = check_tools(vec![tool_with_schema(
            "db_tool",
            "Database access",
            json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "pattern": "^SELECT"
                    }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Medium && f.title.contains("query")),
            "Pattern-constrained 'query' should be Medium"
        );
    }

    // ── Check 5c: Code eval parameters ──────────────────────────────────

    #[test]
    fn detects_code_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "repl",
            "Interactive code execution",
            json!({
                "type": "object",
                "properties": {
                    "code": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical
                && f.title.contains("code")
                && f.title.contains("code evaluation input")),
            "Should detect unsanitized 'code' parameter as Critical"
        );
    }

    #[test]
    fn detects_expression_param_without_validation() {
        let findings = check_tools(vec![tool_with_schema(
            "evaluator",
            "Expression evaluator",
            json!({
                "type": "object",
                "properties": {
                    "expression": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("expression evaluation")),
            "Should detect 'expression' parameter"
        );
    }

    #[test]
    fn detects_python_code_param() {
        let findings = check_tools(vec![tool_with_schema(
            "py_runner",
            "Python runner",
            json!({
                "type": "object",
                "properties": {
                    "python_code": { "type": "string" }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Python code input")),
            "Should detect 'python_code' parameter"
        );
    }

    // ── Check 5d: Parameter description hints ───────────────────────────

    #[test]
    fn detects_param_description_shell_command() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A utility tool",
            json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "The shell command to execute on the target host"
                    }
                }
            }),
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("injection risk") && f.title.contains("input")),
            "Should detect 'shell command' in parameter description"
        );
    }

    #[test]
    fn detects_param_description_sql_to_execute() {
        let findings = check_tools(vec![tool_with_schema(
            "db_admin",
            "Database admin",
            json!({
                "type": "object",
                "properties": {
                    "stmt": {
                        "type": "string",
                        "description": "SQL to execute against the database"
                    }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("injection risk")),
            "Should detect 'sql to execute' in parameter description"
        );
    }

    #[test]
    fn detects_param_description_code_to_evaluate() {
        let findings = check_tools(vec![tool_with_schema(
            "sandbox",
            "Code sandbox",
            json!({
                "type": "object",
                "properties": {
                    "payload": {
                        "type": "string",
                        "description": "Code to evaluate in the sandbox"
                    }
                }
            }),
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("injection risk")),
            "Should detect 'code to evaluate' in parameter description"
        );
    }

    #[test]
    fn param_description_with_constraints_no_hint_finding() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "The shell command to execute",
                        "pattern": "^[a-zA-Z]+$"
                    }
                }
            }),
        )]);
        assert!(
            !findings.iter().any(|f| f.title.contains("injection risk")),
            "Constrained param should not trigger description-based hint finding"
        );
    }

    // ── Non-string parameters are ignored ───────────────────────────────

    #[test]
    fn integer_command_param_ignored() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "command": { "type": "integer" }
                }
            }),
        )]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("shell command input")),
            "Non-string 'command' parameter should not trigger"
        );
    }

    #[test]
    fn boolean_query_param_ignored() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "boolean" }
                }
            }),
        )]);
        assert!(
            !findings.iter().any(|f| f.title.contains("SQL query input")),
            "Non-string 'query' parameter should not trigger"
        );
    }

    // ── No tools → no findings ──────────────────────────────────────────

    #[test]
    fn no_tools_no_findings() {
        let rule = ToolInjectionRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            ..Default::default()
        };
        let findings = rule.check("test-server", &server);
        assert!(
            findings.is_empty(),
            "Server without tools should have no findings"
        );
    }

    #[test]
    fn empty_tools_list_no_findings() {
        let findings = check_tools(vec![]);
        assert!(
            findings.is_empty(),
            "Empty tools list should have no findings"
        );
    }

    // ── Safe tools ──────────────────────────────────────────────────────

    #[test]
    fn safe_tool_no_findings() {
        let findings = check_tools(vec![tool_with_schema(
            "list_files",
            "Lists files in a directory",
            json!({
                "type": "object",
                "properties": {
                    "directory": {
                        "type": "string",
                        "pattern": "^/[a-zA-Z0-9/_-]+$"
                    },
                    "recursive": { "type": "boolean" }
                }
            }),
        )]);
        assert!(
            findings.is_empty(),
            "Safe tool with constrained inputs should have no findings"
        );
    }

    #[test]
    fn safe_tool_with_enum_no_findings() {
        let findings = check_tools(vec![tool_with_schema(
            "get_status",
            "Get system status",
            json!({
                "type": "object",
                "properties": {
                    "component": {
                        "type": "string",
                        "enum": ["cpu", "memory", "disk"]
                    }
                }
            }),
        )]);
        assert!(
            findings.is_empty(),
            "Tool with enum-constrained params should have no findings"
        );
    }

    // ── Multiple tools ──────────────────────────────────────────────────

    #[test]
    fn detects_multiple_dangerous_tools() {
        let findings = check_tools(vec![
            tool("run_command"),
            tool_with_desc("code_eval", "Execute code in a sandbox"),
            tool_with_schema(
                "db_query",
                "Database query",
                json!({
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string" }
                    }
                }),
            ),
        ]);
        // Should have findings from all three tools.
        assert!(
            findings.len() >= 3,
            "Should detect issues in all dangerous tools, got {} findings",
            findings.len()
        );
    }

    // ── Compound scenario: name + description + params ──────────────────

    #[test]
    fn compound_scenario_all_checks_fire() {
        let findings = check_tools(vec![tool_with_schema(
            "execute_command",
            "Execute a shell command on the system",
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the target host"
                    }
                }
            }),
        )]);

        // Should fire: dangerous name + description exec + dangerous param + param description.
        assert!(
            findings.len() >= 3,
            "Compound scenario should fire multiple checks, got {} findings",
            findings.len()
        );

        assert!(findings.iter().any(|f| f.title.contains("dangerous name")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("command execution")));
        assert!(findings
            .iter()
            .any(|f| f.title.contains("shell command input")));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn tool_with_no_description_no_panic() {
        let findings = check_tools(vec![tool("safe_tool")]);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn tool_with_empty_schema_no_panic() {
        let findings = check_tools(vec![tool_with_schema("tool1", "A tool", json!({}))]);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn tool_with_no_properties_no_panic() {
        let findings = check_tools(vec![tool_with_schema(
            "tool1",
            "A tool",
            json!({ "type": "object" }),
        )]);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn tool_with_null_schema_no_panic() {
        let findings = check_tools(vec![McpToolDefinition {
            name: "tool1".into(),
            description: Some("A tool".into()),
            input_schema: Some(serde_json::Value::Null),
        }]);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn case_insensitive_tool_name_detection() {
        let findings = check_tools(vec![tool("RUN_COMMAND")]);
        assert!(
            findings.iter().any(|f| f.title.contains("dangerous name")),
            "Tool name detection should be case-insensitive"
        );
    }

    #[test]
    fn case_insensitive_description_detection() {
        let findings = check_tools(vec![tool_with_desc(
            "my_tool",
            "EXECUTE A COMMAND on the system",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("command execution")),
            "Description detection should be case-insensitive"
        );
    }
}
