//! MCP-03: Prompt Injection via Tools
//!
//! Detects MCP server configurations that may be vulnerable to prompt
//! injection attacks through tool descriptions or arguments.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Environment variable names that suggest dynamic/user-controlled input.
const DYNAMIC_INPUT_VARS: &[&str] = &[
    "USER_INPUT",
    "PROMPT",
    "QUERY",
    "MESSAGE",
    "USER_MESSAGE",
    "CHAT_INPUT",
    "REQUEST_BODY",
    "PAYLOAD",
];

/// Command arguments that indicate template/dynamic processing.
const TEMPLATE_INDICATORS: &[&str] = &["${", "$(", "{{", "{%", "<%= ", "<%- ", "#{"];

pub struct PromptInjectionRule;

impl super::Rule for PromptInjectionRule {
    fn id(&self) -> &'static str {
        "MCP-03"
    }

    fn name(&self) -> &'static str {
        "Prompt Injection via Tools"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers that may be vulnerable to prompt injection \
         through unsanitized tool inputs, dynamic templates, or \
         user-controlled environment variables."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-03"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let args_str = server.args_string();

        // Check for template interpolation in arguments.
        for indicator in TEMPLATE_INDICATORS {
            if args_str.contains(indicator) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Template interpolation in server '{}' arguments",
                        server_name
                    ),
                    description: format!(
                        "Server arguments contain template syntax '{}' which may \
                         allow prompt injection if user input is interpolated. \
                         Ensure all inputs are properly sanitized.",
                        indicator
                    ),
                });
                break; // One finding per template type is enough.
            }
        }

        // Check for environment variables that suggest dynamic input.
        if let Some(env) = &server.env {
            for var_name in env.keys() {
                let upper = var_name.to_uppercase();
                if DYNAMIC_INPUT_VARS.iter().any(|d| upper.contains(d)) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!("Dynamic input variable in server '{}'", server_name),
                        description: format!(
                            "Environment variable '{}' suggests user-controlled input \
                             is passed to the server. Ensure proper input validation \
                             and sanitization to prevent prompt injection.",
                            var_name
                        ),
                    });
                }
            }
        }

        // Check for stdin/pipe patterns that accept raw input.
        if let Some(args) = &server.args {
            let stdin_indicators = ["--stdin", "-", "/dev/stdin", "--interactive", "-i"];
            for arg in args {
                if stdin_indicators.contains(&arg.as_str()) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!("Raw stdin input in server '{}'", server_name),
                        description: format!(
                            "Server argument '{}' indicates raw standard input, \
                             which may allow unsanitized content to reach the server.",
                            arg
                        ),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    fn check_with_env(args: &[&str], env: HashMap<String, String>) -> Vec<ScanFinding> {
        let rule = PromptInjectionRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_args(args: &[&str]) -> Vec<ScanFinding> {
        check_with_env(args, HashMap::new())
    }

    #[test]
    fn detects_shell_interpolation() {
        let findings = check_args(&["--config", "${USER_INPUT}"]);
        assert!(findings.iter().any(|f| f.title.contains("Template")));
    }

    #[test]
    fn detects_template_syntax() {
        let findings = check_args(&["--template", "Hello {{name}}"]);
        assert!(findings.iter().any(|f| f.title.contains("Template")));
    }

    #[test]
    fn detects_dynamic_input_env() {
        let mut env = HashMap::new();
        env.insert("USER_INPUT".into(), "test".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(findings.iter().any(|f| f.title.contains("Dynamic input")));
    }

    #[test]
    fn detects_stdin_arg() {
        let findings = check_args(&["--stdin"]);
        assert!(findings.iter().any(|f| f.title.contains("stdin")));
    }

    #[test]
    fn safe_config_passes() {
        let findings = check_args(&["server.js", "--port", "3000"]);
        assert!(findings.is_empty(), "Safe config should have no findings");
    }

    #[test]
    fn rule_metadata() {
        let rule = PromptInjectionRule;
        assert_eq!(rule.id(), "MCP-03");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-03");
    }
}
