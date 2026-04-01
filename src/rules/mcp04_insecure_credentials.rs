//! MCP-04: Insecure Credentials / Token Exposure
//!
//! Detects hardcoded API keys, tokens, passwords, and other secrets in MCP
//! server configuration environment variables and arguments.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Well-known secret prefixes that indicate hardcoded credentials.
const SECRET_PREFIXES: &[(&str, &str)] = &[
    ("sk-", "OpenAI API key"),
    ("sk-proj-", "OpenAI project key"),
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth token"),
    ("ghu_", "GitHub user-to-server token"),
    ("ghs_", "GitHub server-to-server token"),
    ("ghr_", "GitHub refresh token"),
    ("glpat-", "GitLab personal access token"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("xoxs-", "Slack session token"),
    ("xoxa-", "Slack app token"),
    ("AKIA", "AWS access key ID"),
    ("ABIA", "AWS STS token"),
    ("ACCA", "AWS account ID"),
    ("eyJ", "JWT or base64-encoded token"),
    ("Bearer ", "Bearer authentication token"),
    ("Basic ", "Basic authentication header"),
    ("npm_", "npm access token"),
    ("pypi-", "PyPI API token"),
    ("SG.", "SendGrid API key"),
    ("xkeysib-", "Brevo/Sendinblue API key"),
    ("sq0atp-", "Square access token"),
    ("sk_live_", "Stripe live key"),
    ("sk_test_", "Stripe test key"),
    ("pk_live_", "Stripe public live key"),
    ("rk_live_", "Stripe restricted live key"),
    ("whsec_", "Stripe webhook secret"),
    ("AGE-SECRET-KEY-", "age encryption key"),
];

/// Environment variable name patterns that typically hold secrets.
const SECRET_ENV_PATTERNS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "AUTH_TOKEN",
    "CLIENT_SECRET",
    "CREDENTIALS",
    "DATABASE_URL",
    "CONNECTION_STRING",
    "CONN_STR",
];

/// Values that are clearly not real secrets (placeholders, references).
const SAFE_VALUE_PATTERNS: &[&str] = &[
    "your-",
    "xxx",
    "CHANGE_ME",
    "TODO",
    "FIXME",
    "placeholder",
    "<your",
    "${",
    "$(",
    "process.env",
    "os.environ",
    "env:",
];

pub struct InsecureCredentialsRule;

impl super::Rule for InsecureCredentialsRule {
    fn id(&self) -> &'static str {
        "MCP-04"
    }

    fn name(&self) -> &'static str {
        "Insecure Credentials"
    }

    fn description(&self) -> &'static str {
        "Detects hardcoded API keys, tokens, passwords, and other secrets \
         in MCP server environment variables and command arguments."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-04"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        // Check environment variables for hardcoded secrets.
        if let Some(env) = &server.env {
            for (key, value) in env {
                if is_placeholder(value) {
                    continue;
                }

                // Check if the value matches a known secret prefix.
                for (prefix, description) in SECRET_PREFIXES {
                    if value.starts_with(prefix) {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Critical,
                            title: format!("Hardcoded {} in server '{}'", description, server_name),
                            description: format!(
                                "Environment variable '{}' contains what appears to be \
                                 a hardcoded {} (starts with '{}'). Move secrets to a \
                                 secure vault, use environment variable references, or \
                                 use a secrets manager.",
                                key, description, prefix
                            ),
                        });
                        break;
                    }
                }

                // Check if env var name suggests a secret with a non-trivial value.
                let key_upper = key.to_uppercase();
                let looks_like_secret_key =
                    SECRET_ENV_PATTERNS.iter().any(|p| key_upper.contains(p));

                if looks_like_secret_key && value.len() >= 8 && !is_placeholder(value) {
                    // Avoid duplicate if we already flagged via prefix.
                    let already_flagged = SECRET_PREFIXES
                        .iter()
                        .any(|(prefix, _)| value.starts_with(prefix));
                    if !already_flagged {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::High,
                            title: format!(
                                "Potential hardcoded secret in server '{}'",
                                server_name
                            ),
                            description: format!(
                                "Environment variable '{}' has a name suggesting it \
                                 holds a secret and contains a non-trivial value \
                                 ({} characters). Use environment variable references \
                                 or a secrets manager instead of hardcoding values.",
                                key,
                                value.len()
                            ),
                        });
                    }
                }
            }
        }

        // Check command arguments for leaked tokens.
        if let Some(args) = &server.args {
            for arg in args {
                if is_placeholder(arg) {
                    continue;
                }
                for (prefix, description) in SECRET_PREFIXES {
                    if arg.contains(prefix) && arg.len() > prefix.len() + 4 {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Critical,
                            title: format!(
                                "{} exposed in command arguments of server '{}'",
                                description, server_name
                            ),
                            description: format!(
                                "Command argument contains what appears to be a {} \
                                 (contains '{}'). Secrets in command arguments are \
                                 visible in process listings. Pass via environment \
                                 variables instead.",
                                description, prefix
                            ),
                        });
                        break;
                    }
                }
            }
        }

        findings
    }
}

/// Check if a value looks like a placeholder rather than a real secret.
fn is_placeholder(value: &str) -> bool {
    let lower = value.to_lowercase();
    SAFE_VALUE_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
        || value.is_empty()
        || value.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn check_env(env: Vec<(&str, &str)>) -> Vec<ScanFinding> {
        let rule = InsecureCredentialsRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            env: Some(
                env.into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_args(args: Vec<&str>) -> Vec<ScanFinding> {
        let rule = InsecureCredentialsRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(args.into_iter().map(String::from).collect()),
            env: None,
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    #[test]
    fn detects_openai_key() {
        let findings = check_env(vec![(
            "OPENAI_API_KEY",
            "sk-abc123def456ghi789jkl012mno345",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("OpenAI")),
            "Should detect OpenAI API key"
        );
    }

    #[test]
    fn detects_github_token() {
        let findings = check_env(vec![(
            "GITHUB_TOKEN",
            "ghp_1234567890abcdefghijklmnopqrstuv",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("GitHub")),
            "Should detect GitHub token"
        );
    }

    #[test]
    fn detects_aws_key() {
        let findings = check_env(vec![("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")]);
        assert!(
            findings.iter().any(|f| f.title.contains("AWS")),
            "Should detect AWS access key"
        );
    }

    #[test]
    fn detects_slack_token() {
        let findings = check_env(vec![("SLACK_TOKEN", "xoxb-1234-5678-abcdefghijkl")]);
        assert!(
            findings.iter().any(|f| f.title.contains("Slack")),
            "Should detect Slack token"
        );
    }

    #[test]
    fn detects_secret_in_args() {
        let findings = check_args(vec!["--token", "ghp_1234567890abcdefghijklmnopqrstuv"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("command arguments")),
            "Should detect token in command arguments"
        );
    }

    #[test]
    fn ignores_placeholder_values() {
        let findings = check_env(vec![
            ("API_KEY", "your-api-key-here"),
            ("SECRET", "CHANGE_ME"),
            ("TOKEN", "xxx"),
        ]);
        assert!(
            findings.is_empty(),
            "Placeholder values should not be flagged: {:?}",
            findings
        );
    }

    #[test]
    fn detects_generic_secret_by_name() {
        let findings = check_env(vec![(
            "MY_SECRET_TOKEN",
            "a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5",
        )]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("secret") || f.title.contains("Potential")),
            "Should flag env var with secret-like name and non-trivial value"
        );
    }

    #[test]
    fn safe_env_passes() {
        let findings = check_env(vec![
            ("NODE_ENV", "production"),
            ("PORT", "3000"),
            ("DEBUG", "false"),
        ]);
        assert!(
            findings.is_empty(),
            "Non-secret env vars should not be flagged"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = InsecureCredentialsRule;
        assert_eq!(rule.id(), "MCP-04");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-04");
        assert_eq!(rule.default_severity(), Severity::Critical);
    }
}
