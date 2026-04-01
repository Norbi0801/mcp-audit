//! MCP-09: Insufficient Logging & Monitoring
//!
//! Detects MCP server configurations that lack proper logging, monitoring,
//! or audit trail capabilities.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Environment variables that indicate logging is configured.
const LOGGING_ENV_VARS: &[&str] = &[
    "LOG_LEVEL",
    "LOG_FILE",
    "LOG_DIR",
    "LOG_PATH",
    "LOGGING",
    "DEBUG",
    "VERBOSE",
    "TRACE",
    "RUST_LOG",
    "NODE_DEBUG",
    "SENTRY_DSN",
    "DATADOG_API_KEY",
    "NEW_RELIC_LICENSE_KEY",
    "SPLUNK_TOKEN",
    "ELASTIC_APM_SERVER_URL",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_SERVICE_NAME",
    "AUDIT_LOG",
];

/// Arguments that indicate logging configuration.
const LOGGING_ARGS: &[&str] = &[
    "--log",
    "--log-level",
    "--log-file",
    "--log-dir",
    "--verbose",
    "-v",
    "-vv",
    "-vvv",
    "--debug",
    "--trace",
    "--audit",
    "--audit-log",
];

/// Flags that explicitly disable logging.
const DISABLE_LOGGING_FLAGS: &[&str] = &[
    "--no-log",
    "--no-logging",
    "--quiet",
    "-q",
    "--silent",
    "--no-audit",
    "--disable-logging",
    "--disable-audit",
];

/// Environment values that explicitly disable logging.
const DISABLE_LOGGING_VALUES: &[(&str, &str)] = &[
    ("LOG_LEVEL", "off"),
    ("LOG_LEVEL", "none"),
    ("LOG_LEVEL", "silent"),
    ("LOGGING", "false"),
    ("LOGGING", "0"),
    ("LOGGING", "off"),
    ("AUDIT_LOG", "false"),
    ("AUDIT_LOG", "0"),
    ("AUDIT_LOG", "off"),
    ("DEBUG", "false"),
    ("DEBUG", "0"),
];

pub struct InsufficientLoggingRule;

impl super::Rule for InsufficientLoggingRule {
    fn id(&self) -> &'static str {
        "MCP-09"
    }

    fn name(&self) -> &'static str {
        "Insufficient Logging & Monitoring"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers without logging configuration, with logging \
         explicitly disabled, or lacking audit trail capabilities."
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-09"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let args = server.args.as_deref().unwrap_or(&[]);

        // Check for explicitly disabled logging.
        for flag in DISABLE_LOGGING_FLAGS {
            if args.iter().any(|a| a == flag) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Logging explicitly disabled in server '{}'", server_name),
                    description: format!(
                        "Server uses the '{}' flag which disables logging. Without \
                         logs, security incidents cannot be detected or investigated. \
                         Enable logging with an appropriate log level.",
                        flag
                    ),
                });
            }
        }

        // Check environment for disabled logging.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let key_upper = key.to_uppercase();
                let value_lower = value.to_lowercase();
                for (disable_key, disable_val) in DISABLE_LOGGING_VALUES {
                    if key_upper == *disable_key && value_lower == *disable_val {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::High,
                            title: format!(
                                "Logging disabled via environment in server '{}'",
                                server_name
                            ),
                            description: format!(
                                "Environment variable '{}={}' disables logging. \
                                 Enable logging for security audit trail.",
                                key, value
                            ),
                        });
                    }
                }
            }
        }

        // Check for lack of any logging configuration.
        let has_logging_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                LOGGING_ENV_VARS.iter().any(|lv| upper.contains(lv))
            })
        });

        let has_logging_args = args
            .iter()
            .any(|a| LOGGING_ARGS.iter().any(|la| a.starts_with(la)));

        if !has_logging_env && !has_logging_args {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Low,
                title: format!("No logging configuration in server '{}'", server_name),
                description: "Server has no apparent logging configuration. Consider \
                     adding LOG_LEVEL, --log-file, or a monitoring service \
                     (Sentry, Datadog, OpenTelemetry) for security visibility."
                    .to_string(),
            });
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
        let rule = InsufficientLoggingRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_args_only(args: &[&str]) -> Vec<ScanFinding> {
        check_with_env(args, HashMap::new())
    }

    #[test]
    fn detects_disabled_logging_flag() {
        let findings = check_args_only(&["server.js", "--silent"]);
        assert!(
            findings.iter().any(|f| f.title.contains("disabled")),
            "Should detect --silent flag"
        );
    }

    #[test]
    fn detects_disabled_logging_env() {
        let mut env = HashMap::new();
        env.insert("LOG_LEVEL".into(), "off".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            findings.iter().any(|f| f.title.contains("disabled")),
            "Should detect LOG_LEVEL=off"
        );
    }

    #[test]
    fn detects_no_logging_config() {
        let findings = check_args_only(&["server.js", "--port", "3000"]);
        assert!(
            findings.iter().any(|f| f.title.contains("No logging")),
            "Should detect missing logging configuration"
        );
    }

    #[test]
    fn logging_env_var_passes() {
        let mut env = HashMap::new();
        env.insert("LOG_LEVEL".into(), "info".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("No logging")),
            "Server with LOG_LEVEL should not get no-logging warning"
        );
    }

    #[test]
    fn logging_arg_passes() {
        let findings = check_args_only(&["server.js", "--log-level", "info"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("No logging")),
            "Server with --log-level should not get no-logging warning"
        );
    }

    #[test]
    fn monitoring_service_passes() {
        let mut env = HashMap::new();
        env.insert("SENTRY_DSN".into(), "https://key@sentry.io/123".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("No logging")),
            "Server with Sentry should not get no-logging warning"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = InsufficientLoggingRule;
        assert_eq!(rule.id(), "MCP-09");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-09");
        assert_eq!(rule.default_severity(), Severity::Medium);
    }
}
