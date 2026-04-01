//! MCP-10: Unauthorized Access / Authentication Bypass
//!
//! Detects MCP servers with missing or weakened authentication, including
//! HTTP endpoints without auth headers, disabled auth flags, and
//! development-mode configurations.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Environment variable patterns that indicate auth is disabled.
const AUTH_DISABLED_PATTERNS: &[(&str, &[&str])] = &[
    ("AUTH_DISABLED", &["true", "1", "yes"]),
    ("DISABLE_AUTH", &["true", "1", "yes"]),
    ("NO_AUTH", &["true", "1", "yes"]),
    ("SKIP_AUTH", &["true", "1", "yes"]),
    ("AUTH_ENABLED", &["false", "0", "no"]),
    ("REQUIRE_AUTH", &["false", "0", "no"]),
    ("AUTH_REQUIRED", &["false", "0", "no"]),
    ("SKIP_VERIFICATION", &["true", "1", "yes"]),
    ("VERIFY_TOKEN", &["false", "0", "no"]),
    ("INSECURE", &["true", "1", "yes"]),
];

/// Environment variable patterns suggesting development/debug mode.
const DEV_MODE_PATTERNS: &[(&str, &[&str])] = &[
    ("NODE_ENV", &["development", "dev", "test"]),
    ("ENVIRONMENT", &["development", "dev", "test", "staging"]),
    ("ENV", &["development", "dev", "test"]),
    ("DEBUG_MODE", &["true", "1", "yes"]),
    ("DEV_MODE", &["true", "1", "yes"]),
    ("DEVELOPMENT", &["true", "1", "yes"]),
];

/// Arguments that weaken or bypass auth.
const AUTH_BYPASS_ARGS: &[(&str, &str)] = &[
    ("--no-auth", "disables authentication"),
    ("--disable-auth", "disables authentication"),
    ("--skip-auth", "skips authentication"),
    ("--insecure", "disables security checks"),
    ("--allow-anonymous", "allows unauthenticated access"),
    ("--no-verify", "disables verification"),
    ("--no-ssl-verify", "disables SSL certificate verification"),
    ("--skip-ssl", "skips SSL verification"),
    ("--dev", "enables development mode"),
    ("--development", "enables development mode"),
    ("--unsafe", "enables unsafe mode"),
];

pub struct UnauthorizedAccessRule;

impl super::Rule for UnauthorizedAccessRule {
    fn id(&self) -> &'static str {
        "MCP-10"
    }

    fn name(&self) -> &'static str {
        "Unauthorized Access"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers with missing or weakened authentication, \
         disabled auth configurations, and development mode settings \
         that bypass security controls."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-10"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let args = server.args.as_deref().unwrap_or(&[]);

        // Check for auth-bypass arguments.
        for (flag, description) in AUTH_BYPASS_ARGS {
            if args.iter().any(|a| a == flag) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Authentication bypass flag in server '{}'", server_name),
                    description: format!(
                        "Server uses '{}' which {}. Remove this flag and \
                         configure proper authentication.",
                        flag, description
                    ),
                });
            }
        }

        // Check environment variables for auth disabled patterns.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let key_upper = key.to_uppercase();
                let value_lower = value.to_lowercase();

                // Check auth disabled patterns.
                for (pattern_key, pattern_values) in AUTH_DISABLED_PATTERNS {
                    if key_upper == *pattern_key && pattern_values.contains(&value_lower.as_str()) {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Critical,
                            title: format!("Authentication disabled in server '{}'", server_name),
                            description: format!(
                                "Environment variable '{}={}' explicitly disables \
                                 authentication. This allows unauthorized access to \
                                 the MCP server. Enable authentication and configure \
                                 proper credentials.",
                                key, value
                            ),
                        });
                    }
                }

                // Check dev mode patterns.
                for (pattern_key, pattern_values) in DEV_MODE_PATTERNS {
                    if key_upper == *pattern_key && pattern_values.contains(&value_lower.as_str()) {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Medium,
                            title: format!("Development mode enabled in server '{}'", server_name),
                            description: format!(
                                "Environment variable '{}={}' indicates the server \
                                 is running in development mode. Development mode \
                                 often disables security features. Use production \
                                 settings in non-development environments.",
                                key, value
                            ),
                        });
                    }
                }
            }
        }

        // Check HTTP servers for missing authentication.
        if server.is_http() {
            // HTTP MCP servers should have some form of auth configured.
            let has_auth_header = server.env.as_ref().is_some_and(|env| {
                env.keys().any(|k| {
                    let upper = k.to_uppercase();
                    upper.contains("AUTH")
                        || upper.contains("TOKEN")
                        || upper.contains("API_KEY")
                        || upper.contains("BEARER")
                        || upper.contains("SECRET")
                })
            });

            let has_auth_arg = args.iter().any(|a| {
                a.contains("--auth")
                    || a.contains("--token")
                    || a.contains("--api-key")
                    || a.contains("--bearer")
            });

            if !has_auth_header && !has_auth_arg {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("No authentication for HTTP server '{}'", server_name),
                    description: format!(
                        "HTTP-based MCP server '{}' has no apparent authentication \
                         configuration (no auth-related environment variables or \
                         arguments). Configure authentication to prevent \
                         unauthorized access.",
                        server_name
                    ),
                });
            }
        }

        // Check for privilege escalation indicators.
        if let Some(cmd) = &server.command {
            if cmd == "sudo" || cmd == "doas" || cmd == "su" {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Critical,
                    title: format!("Privilege escalation command in server '{}'", server_name),
                    description: format!(
                        "Server uses '{}' to run with elevated privileges. MCP \
                         servers should run with minimal required permissions. \
                         Remove privilege escalation and configure proper access \
                         controls.",
                        cmd
                    ),
                });
            }
        }

        // Check for --privileged or capability flags (Docker).
        let privilege_flags = ["--privileged", "--cap-add", "--security-opt"];
        for flag in &privilege_flags {
            if args.iter().any(|a| a.starts_with(flag)) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Container privilege escalation in server '{}'", server_name),
                    description: format!(
                        "Server uses the '{}' flag which grants elevated container \
                         privileges. Run with minimal capabilities and use \
                         --security-opt=no-new-privileges.",
                        flag
                    ),
                });
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

    fn check_cmd_env(cmd: &str, args: &[&str], env: HashMap<String, String>) -> Vec<ScanFinding> {
        let rule = UnauthorizedAccessRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_args(cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        check_cmd_env(cmd, args, HashMap::new())
    }

    fn check_url_env(url: &str, env: HashMap<String, String>) -> Vec<ScanFinding> {
        let rule = UnauthorizedAccessRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    #[test]
    fn detects_no_auth_flag() {
        let findings = check_args("node", &["server.js", "--no-auth"]);
        assert!(
            findings.iter().any(|f| f.title.contains("bypass")),
            "Should detect --no-auth flag"
        );
    }

    #[test]
    fn detects_auth_disabled_env() {
        let mut env = HashMap::new();
        env.insert("AUTH_DISABLED".into(), "true".into());
        let findings = check_cmd_env("node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("disabled") && f.severity == Severity::Critical),
            "Should detect AUTH_DISABLED=true as critical"
        );
    }

    #[test]
    fn detects_dev_mode() {
        let mut env = HashMap::new();
        env.insert("NODE_ENV".into(), "development".into());
        let findings = check_cmd_env("node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Development mode")),
            "Should detect development mode"
        );
    }

    #[test]
    fn detects_http_without_auth() {
        let findings = check_url_env("https://api.example.com/mcp", HashMap::new());
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "Should detect HTTP server without auth"
        );
    }

    #[test]
    fn http_with_auth_env_passes() {
        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".into(), "some-token".into());
        let findings = check_url_env("https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with auth env should pass"
        );
    }

    #[test]
    fn detects_sudo() {
        let findings = check_args("sudo", &["node", "server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Privilege escalation")),
            "Should detect sudo usage"
        );
    }

    #[test]
    fn detects_privileged_flag() {
        let findings = check_args("docker", &["run", "--privileged", "mcp-server"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Container privilege")),
            "Should detect --privileged flag"
        );
    }

    #[test]
    fn production_config_passes() {
        let mut env = HashMap::new();
        env.insert("NODE_ENV".into(), "production".into());
        env.insert("AUTH_TOKEN".into(), "real-token".into());
        let findings = check_cmd_env("node", &["server.js"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Development") || f.title.contains("disabled")),
            "Production config with auth should not flag dev/auth issues"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = UnauthorizedAccessRule;
        assert_eq!(rule.id(), "MCP-10");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-10");
        assert_eq!(rule.default_severity(), Severity::High);
    }
}
