//! MCP-17: Data Leakage
//!
//! Detects MCP servers that risk leaking sensitive data through tool outputs,
//! resource responses, and logging. Checks for:
//!
//! - Tools whose descriptions indicate they return env vars, secrets, or API keys
//! - Resources that expose credential files (.env, .git/config, id_rsa, etc.)
//! - Tool outputs that are not sanitized (PII, secrets in plain text)
//! - Missing output redaction on tools handling sensitive data
//! - Server configurations that may log sensitive data
//! - Environment variables passed to server that could be echoed back in output

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Rule identifier constant, used in impl methods without requiring trait import.
const RULE_ID: &str = "MCP-17";

// ── Detection constants ──────────────────────────────────────────────────

/// Tool names that directly indicate they return sensitive data.
const SENSITIVE_OUTPUT_TOOL_NAMES: &[(&str, &str)] = &[
    ("get_env", "returns environment variables"),
    ("get_environment", "returns environment variables"),
    ("list_env", "lists environment variables"),
    ("list_environment", "lists environment variables"),
    ("read_env", "reads environment variables"),
    ("dump_env", "dumps environment variables"),
    ("env_vars", "returns environment variables"),
    ("environment_variables", "returns environment variables"),
    ("printenv", "prints environment variables"),
    ("get_secrets", "returns secrets"),
    ("list_secrets", "lists secrets"),
    ("read_secrets", "reads secrets"),
    ("dump_secrets", "dumps secrets"),
    ("get_credentials", "returns credentials"),
    ("list_credentials", "lists credentials"),
    ("read_credentials", "reads credentials"),
    ("dump_credentials", "dumps credentials"),
    ("get_api_keys", "returns API keys"),
    ("list_api_keys", "lists API keys"),
    ("get_tokens", "returns tokens"),
    ("list_tokens", "lists tokens"),
    ("get_config", "returns configuration (may contain secrets)"),
    ("dump_config", "dumps configuration (may contain secrets)"),
    ("show_config", "shows configuration (may contain secrets)"),
    ("get_password", "returns passwords"),
    ("get_passwords", "returns passwords"),
    ("read_private_key", "reads private key material"),
    ("get_private_key", "returns private key material"),
    ("dump_database", "dumps database contents"),
    ("export_database", "exports database contents"),
    (
        "get_connection_string",
        "returns database connection strings",
    ),
    ("whoami", "returns identity information"),
    ("get_identity", "returns identity information"),
    ("get_user_data", "returns user data (PII)"),
    ("export_users", "exports user data (PII)"),
    ("dump_users", "dumps user data (PII)"),
    ("list_users", "lists user data (PII)"),
];

/// Keywords in tool descriptions indicating the tool returns sensitive data.
const LEAKAGE_DESCRIPTION_KEYWORDS: &[(&str, &str)] = &[
    ("return environment variable", "leaks environment variables"),
    (
        "returns environment variable",
        "leaks environment variables",
    ),
    ("return env var", "leaks environment variables"),
    ("returns env var", "leaks environment variables"),
    ("return all env", "leaks environment variables"),
    ("returns all env", "leaks environment variables"),
    ("output secret", "leaks secrets in output"),
    ("returns secret", "leaks secrets in output"),
    ("return secret", "leaks secrets in output"),
    ("return api key", "leaks API keys"),
    ("returns api key", "leaks API keys"),
    ("output api key", "leaks API keys"),
    ("return token", "leaks tokens"),
    ("returns token", "leaks tokens"),
    ("output token", "leaks tokens"),
    ("return password", "leaks passwords"),
    ("returns password", "leaks passwords"),
    ("return credential", "leaks credentials"),
    ("returns credential", "leaks credentials"),
    ("display credential", "leaks credentials"),
    ("return private key", "leaks private keys"),
    ("returns private key", "leaks private keys"),
    ("show private key", "leaks private keys"),
    ("output private key", "leaks private keys"),
    ("dump all", "unfiltered data dump"),
    ("dump everything", "unfiltered data dump"),
    ("raw output", "unsanitized raw output"),
    ("unfiltered output", "unsanitized output"),
    ("without redact", "missing redaction"),
    ("without mask", "missing redaction"),
    ("no redact", "missing redaction"),
    ("no sanitiz", "missing sanitization"),
    ("no filter", "missing output filtering"),
    ("plain text secret", "secrets in plain text"),
    ("plaintext secret", "secrets in plain text"),
    ("plain text password", "passwords in plain text"),
    ("plaintext password", "passwords in plain text"),
    ("include secret", "includes secrets in output"),
    ("includes secret", "includes secrets in output"),
    ("include credential", "includes credentials in output"),
    ("includes credential", "includes credentials in output"),
    ("personal data", "returns PII/personal data"),
    ("personally identifiable", "returns PII"),
    ("social security", "returns SSN"),
    ("credit card", "returns credit card data"),
    ("bank account", "returns bank account data"),
];

/// Resource URI patterns that expose credential/secret files.
const SENSITIVE_RESOURCE_URIS: &[(&str, &str)] = &[
    (".env", "environment file (contains secrets)"),
    (".env.local", "local environment file"),
    (".env.production", "production environment file"),
    (".env.staging", "staging environment file"),
    (".env.development", "development environment file"),
    (".git/config", "Git config (may contain credentials)"),
    (".git/credentials", "Git stored credentials"),
    ("id_rsa", "SSH RSA private key"),
    ("id_ed25519", "SSH Ed25519 private key"),
    ("id_ecdsa", "SSH ECDSA private key"),
    ("id_dsa", "SSH DSA private key"),
    (".pem", "PEM certificate/key file"),
    (".key", "private key file"),
    (".p12", "PKCS#12 certificate bundle"),
    (".pfx", "PKCS#12 certificate bundle"),
    (".keystore", "key store file"),
    (".jks", "Java key store"),
    (".npmrc", "npm config (may contain auth tokens)"),
    (".pypirc", "PyPI credentials"),
    (".netrc", "network authentication credentials"),
    (".pgpass", "PostgreSQL password file"),
    (".my.cnf", "MySQL config (may contain passwords)"),
    ("credentials.json", "application credentials"),
    ("credentials.yaml", "application credentials"),
    ("service-account.json", "service account key"),
    ("secrets.json", "application secrets"),
    ("secrets.yaml", "application secrets"),
    ("secrets.yml", "application secrets"),
    (".aws/credentials", "AWS credentials"),
    (".aws/config", "AWS configuration"),
    (".docker/config.json", "Docker registry credentials"),
    (".kube/config", "Kubernetes configuration"),
    ("kubeconfig", "Kubernetes configuration"),
    ("htpasswd", "HTTP authentication passwords"),
    ("shadow", "system password hashes"),
    ("vault-token", "HashiCorp Vault token"),
    ("token.json", "OAuth/API token file"),
    ("auth.json", "authentication credentials"),
];

/// Server argument patterns that indicate verbose/debug output (leak risk).
const VERBOSE_OUTPUT_PATTERNS: &[(&str, &str)] = &[
    ("--verbose", "verbose output may include sensitive data"),
    ("-vvv", "maximum verbosity may dump secrets"),
    ("--debug", "debug mode may output secrets and tokens"),
    (
        "--log-level=debug",
        "debug logging may include sensitive data",
    ),
    (
        "--log-level=trace",
        "trace logging may include sensitive data",
    ),
    (
        "--log-level debug",
        "debug logging may include sensitive data",
    ),
    (
        "--log-level trace",
        "trace logging may include sensitive data",
    ),
    (
        "LOG_LEVEL=debug",
        "debug logging may include sensitive data",
    ),
    (
        "LOG_LEVEL=trace",
        "trace logging may include sensitive data",
    ),
    ("DEBUG=*", "debug wildcard logs everything"),
    ("DEBUG=true", "debug mode may output sensitive data"),
    (
        "--dump-headers",
        "dumps HTTP headers (may contain auth tokens)",
    ),
    (
        "--show-headers",
        "shows HTTP headers (may contain auth tokens)",
    ),
    ("--print-env", "prints environment variables"),
    ("--dump-env", "dumps environment variables"),
    ("--expose-secrets", "explicitly exposes secrets"),
    ("--no-redact", "disables secret redaction"),
    ("--no-mask", "disables data masking"),
    ("--raw-output", "disables output sanitization"),
    ("--include-secrets", "includes secrets in output"),
];

/// Environment variable names that, when passed to a server, risk leakage.
/// These are secrets that a server could inadvertently echo back.
const PASSTHROUGH_SECRET_ENV_PATTERNS: &[&str] = &[
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SECRET_KEY",
    "API_KEY",
    "APIKEY",
    "AUTH_TOKEN",
    "CLIENT_SECRET",
    "MASTER_KEY",
    "ENCRYPTION_KEY",
    "SIGNING_KEY",
    "JWT_SECRET",
    "SESSION_SECRET",
    "COOKIE_SECRET",
];

/// Safe value patterns indicating env refs, not actual secrets.
const SAFE_VALUE_PATTERNS: &[&str] = &[
    "${",
    "$(",
    "process.env",
    "os.environ",
    "env:",
    "your-",
    "xxx",
    "CHANGE_ME",
    "TODO",
    "FIXME",
    "placeholder",
    "<your",
];

pub struct DataLeakageRule;

impl super::Rule for DataLeakageRule {
    fn id(&self) -> &'static str {
        RULE_ID
    }

    fn name(&self) -> &'static str {
        "Data Leakage"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers that risk leaking sensitive data through tool \
         outputs, resource responses, or logging. Checks for tools that return \
         environment variables, secrets, or API keys; resources that expose \
         credential files; missing output redaction; and debug/verbose modes \
         that may dump sensitive data."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-17"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        self.check_tool_names_for_leakage(server_name, server, &mut findings);
        self.check_tool_descriptions_for_leakage(server_name, server, &mut findings);
        self.check_resource_uris_for_credentials(server_name, server, &mut findings);
        self.check_verbose_debug_output(server_name, server, &mut findings);
        self.check_secret_env_passthrough(server_name, server, &mut findings);

        findings
    }
}

impl DataLeakageRule {
    /// Check tool names for patterns indicating they return sensitive data.
    fn check_tool_names_for_leakage(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let tools = match &server.tools {
            Some(t) => t,
            None => return,
        };

        for tool in tools {
            let name_lower = tool.name.to_lowercase();

            for (pattern, description) in SENSITIVE_OUTPUT_TOOL_NAMES {
                if name_lower == *pattern || name_lower.contains(pattern) {
                    findings.push(ScanFinding {
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Tool '{}' in server '{}' may leak sensitive data",
                            tool.name, server_name
                        ),
                        description: format!(
                            "Tool '{}' has a name indicating it {} in its output. \
                             Tool outputs are sent to the LLM context and may be \
                             visible to the user or forwarded to other services. \
                             Ensure this tool redacts secrets, masks credentials, \
                             and never returns raw sensitive data.",
                            tool.name, description
                        ),
                    });
                    break;
                }
            }
        }
    }

    /// Check tool descriptions for keywords indicating sensitive data in output.
    fn check_tool_descriptions_for_leakage(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let tools = match &server.tools {
            Some(t) => t,
            None => return,
        };

        for tool in tools {
            let desc = match &tool.description {
                Some(d) => d,
                None => continue,
            };

            let desc_lower = desc.to_lowercase();

            for (keyword, risk) in LEAKAGE_DESCRIPTION_KEYWORDS {
                if desc_lower.contains(keyword) {
                    findings.push(ScanFinding {
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Tool '{}' in server '{}' description indicates data leakage risk",
                            tool.name, server_name
                        ),
                        description: format!(
                            "Tool '{}' description contains '{}', indicating it {}. \
                             MCP tool outputs are visible in the conversation context. \
                             Implement output redaction, mask sensitive values, and \
                             never return raw secrets, tokens, or PII.",
                            tool.name, keyword, risk
                        ),
                    });
                    break;
                }
            }
        }
    }

    /// Check if server args or tool descriptions reference sensitive resource URIs.
    fn check_resource_uris_for_credentials(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let args = server.args.as_deref().unwrap_or(&[]);

        // Check if arguments reference credential file patterns as resources.
        for arg in args {
            for (pattern, description) in SENSITIVE_RESOURCE_URIS {
                if arg_exposes_resource(arg, pattern) {
                    findings.push(ScanFinding {
                        rule_id: RULE_ID.to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Server '{}' may expose {} as a resource",
                            server_name, description
                        ),
                        description: format!(
                            "Server argument '{}' references a sensitive resource pattern \
                             '{}' ({}). If this server serves files or resources, it could \
                             leak credential data through the MCP protocol. Exclude \
                             sensitive files from resource listings and implement \
                             access controls.",
                            arg, pattern, description
                        ),
                    });
                    break;
                }
            }
        }

        // Also check tool descriptions for resource URI leakage hints.
        if let Some(tools) = &server.tools {
            for tool in tools {
                if let Some(desc) = &tool.description {
                    let desc_lower = desc.to_lowercase();
                    for (pattern, description) in SENSITIVE_RESOURCE_URIS {
                        if desc_lower.contains(pattern) {
                            findings.push(ScanFinding {
                                rule_id: RULE_ID.to_string(),
                                severity: Severity::High,
                                title: format!(
                                    "Tool '{}' in server '{}' may expose {}",
                                    tool.name, server_name, description
                                ),
                                description: format!(
                                    "Tool '{}' description references '{}' ({}). \
                                     This tool may serve sensitive credential files \
                                     through the MCP protocol. Implement file-type \
                                     filtering to prevent credential leakage.",
                                    tool.name, pattern, description
                                ),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Check for verbose/debug flags that may cause the server to log or output secrets.
    fn check_verbose_debug_output(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_str = server.args_string();

        // Check args for verbose/debug patterns.
        for (pattern, risk) in VERBOSE_OUTPUT_PATTERNS {
            let matched = args.iter().any(|a| {
                let a_lower = a.to_lowercase();
                a_lower == pattern.to_lowercase() || a_lower.contains(&pattern.to_lowercase())
            });

            if matched {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::High,
                    title: format!("Verbose/debug output enabled in server '{}'", server_name),
                    description: format!(
                        "Server argument matches pattern '{}': {}. \
                         Debug and verbose modes often include secrets, tokens, \
                         and credentials in log output. These may leak through \
                         MCP tool responses or server-side logs. Disable debug \
                         mode in production or ensure output redaction is active.",
                        pattern, risk
                    ),
                });
                break; // One finding per server for debug mode is sufficient.
            }
        }

        // Check environment variables for debug/verbose settings.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let combined = format!("{}={}", key, value).to_lowercase();

                for (pattern, risk) in VERBOSE_OUTPUT_PATTERNS {
                    if combined.contains(&pattern.to_lowercase()) {
                        findings.push(ScanFinding {
                            rule_id: RULE_ID.to_string(),
                            severity: Severity::High,
                            title: format!(
                                "Debug logging enabled via env var in server '{}'",
                                server_name
                            ),
                            description: format!(
                                "Environment variable '{}={}' matches debug pattern '{}': {}. \
                                 Debug logging in MCP servers may output secrets, tokens, \
                                 and request/response payloads containing sensitive data.",
                                key, value, pattern, risk
                            ),
                        });
                        // Only report one env-based debug finding per server.
                        return;
                    }
                }
            }
        }

        // Check for combined debug patterns in full args string.
        let args_lower = args_str.to_lowercase();
        if args_lower.contains("--expose-secrets")
            || args_lower.contains("--no-redact")
            || args_lower.contains("--no-mask")
            || args_lower.contains("--include-secrets")
        {
            // Only add if we haven't already found it.
            let already_found = findings
                .iter()
                .any(|f| f.rule_id == RULE_ID && f.title.contains("Verbose/debug"));
            if !already_found {
                findings.push(ScanFinding {
                    rule_id: RULE_ID.to_string(),
                    severity: Severity::Critical,
                    title: format!(
                        "Secret redaction explicitly disabled in server '{}'",
                        server_name
                    ),
                    description: format!(
                        "Server '{}' has flags that explicitly disable secret redaction \
                         or masking (e.g., --no-redact, --expose-secrets). This means \
                         all sensitive data will be returned in plain text through MCP \
                         tool outputs. Remove these flags immediately.",
                        server_name
                    ),
                });
            }
        }
    }

    /// Check if secret env vars are passed through to the server and could be echoed.
    fn check_secret_env_passthrough(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let env = match &server.env {
            Some(e) => e,
            None => return,
        };

        let mut secret_count = 0;
        let mut secret_examples = Vec::new();

        for (key, value) in env {
            if is_safe_value(value) {
                continue;
            }

            let key_upper = key.to_uppercase();
            let is_secret = PASSTHROUGH_SECRET_ENV_PATTERNS
                .iter()
                .any(|p| key_upper.contains(p));

            if is_secret && value.len() >= 8 {
                secret_count += 1;
                if secret_examples.len() < 3 {
                    secret_examples.push(key.clone());
                }
            }
        }

        // A large number of secret env vars increases the leakage surface.
        if secret_count >= 3 {
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::High,
                title: format!(
                    "Multiple secrets passed to server '{}' increase leakage risk",
                    server_name
                ),
                description: format!(
                    "Server has {} environment variables with secret-like names \
                     (e.g., {}). Each secret passed to the server is a potential \
                     leakage vector — if any tool returns process environment, \
                     debug output, or error messages containing env vars, all \
                     these secrets could be exposed. Minimize the number of \
                     secrets passed and ensure the server never echoes them.",
                    secret_count,
                    secret_examples.join(", ")
                ),
            });
        }

        // Check if a known debug/verbose tool is combined with secrets.
        if secret_count > 0 && has_debug_tools(server) {
            findings.push(ScanFinding {
                rule_id: RULE_ID.to_string(),
                severity: Severity::Critical,
                title: format!(
                    "Debug tools combined with secrets in server '{}'",
                    server_name
                ),
                description: format!(
                    "Server '{}' has both secret environment variables and debug/diagnostic \
                     tools. Debug tools commonly output environment variables and internal \
                     state, creating a direct path for secret leakage through MCP outputs.",
                    server_name
                ),
            });
        }
    }
}

/// Check if a server argument exposes a resource matching a sensitive pattern.
///
/// Matches both exact filenames and path suffixes (e.g., "/home/user/.env").
fn arg_exposes_resource(arg: &str, pattern: &str) -> bool {
    let normalized = arg.replace('\\', "/");

    // Exact match.
    if normalized == pattern {
        return true;
    }

    // File ends with the pattern (path/to/.env, /root/.ssh/id_rsa).
    if normalized.ends_with(pattern) {
        // Make sure it's a proper path boundary (preceded by / or start of string).
        let prefix_len = normalized.len() - pattern.len();
        if prefix_len == 0 {
            return true;
        }
        let prefix_char = normalized.as_bytes()[prefix_len - 1];
        if prefix_char == b'/' || prefix_char == b'\\' {
            return true;
        }
    }

    // Check if the arg contains the pattern as a path segment.
    if normalized.contains(&format!("/{}", pattern)) {
        return true;
    }

    false
}

/// Check if a value is a safe placeholder (not a real secret).
fn is_safe_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    SAFE_VALUE_PATTERNS
        .iter()
        .any(|p| lower.contains(&p.to_lowercase()))
        || value.is_empty()
        || value.chars().all(|c| c == '*' || c == 'x' || c == 'X')
}

/// Check if the server has tools that look like debug/diagnostic tools.
fn has_debug_tools(server: &McpServerConfig) -> bool {
    if let Some(tools) = &server.tools {
        let debug_names = [
            "debug",
            "diagnostics",
            "inspect",
            "dump",
            "get_env",
            "printenv",
            "system_info",
            "server_info",
            "health_check_verbose",
        ];

        return tools.iter().any(|t| {
            let name_lower = t.name.to_lowercase();
            debug_names.iter().any(|d| name_lower.contains(d))
        });
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::McpToolDefinition;
    use crate::rules::Rule;
    use std::collections::HashMap;

    fn make_server_with_tools(tools: Vec<McpToolDefinition>) -> McpServerConfig {
        McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            tools: Some(tools),
            ..Default::default()
        }
    }

    fn make_tool(name: &str, description: Option<&str>) -> McpToolDefinition {
        McpToolDefinition {
            name: name.to_string(),
            description: description.map(String::from),
            input_schema: None,
        }
    }

    fn check_server(server: &McpServerConfig) -> Vec<ScanFinding> {
        let rule = DataLeakageRule;
        rule.check("test-server", server)
    }

    fn check_args(args: &[&str]) -> Vec<ScanFinding> {
        let rule = DataLeakageRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_env(env: Vec<(&str, &str)>) -> Vec<ScanFinding> {
        let rule = DataLeakageRule;
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

    // ── Tool name detection tests ──────────────────────────────────

    #[test]
    fn detects_get_env_tool() {
        let server = make_server_with_tools(vec![make_tool("get_env", Some("Get env vars"))]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("get_env")),
            "Should detect get_env tool as data leakage risk: {:?}",
            findings
        );
    }

    #[test]
    fn detects_dump_secrets_tool() {
        let server =
            make_server_with_tools(vec![make_tool("dump_secrets", Some("Dump all secrets"))]);
        let findings = check_server(&server);
        assert!(
            findings.iter().any(|f| f.title.contains("dump_secrets")),
            "Should detect dump_secrets tool"
        );
    }

    #[test]
    fn detects_get_credentials_tool() {
        let server = make_server_with_tools(vec![make_tool(
            "get_credentials",
            Some("Retrieve stored credentials"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings.iter().any(|f| f.title.contains("get_credentials")),
            "Should detect get_credentials tool"
        );
    }

    #[test]
    fn detects_export_users_tool() {
        let server =
            make_server_with_tools(vec![make_tool("export_users", Some("Export user data"))]);
        let findings = check_server(&server);
        assert!(
            findings.iter().any(|f| f.title.contains("export_users")),
            "Should detect export_users tool"
        );
    }

    // ── Tool description detection tests ────────────────────────────

    #[test]
    fn detects_description_returning_env_vars() {
        let server = make_server_with_tools(vec![make_tool(
            "config_reader",
            Some("Returns environment variables from the server process"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("description indicates data leakage")),
            "Should detect leakage risk in description: {:?}",
            findings
        );
    }

    #[test]
    fn detects_description_returning_secrets() {
        let server = make_server_with_tools(vec![make_tool(
            "vault_reader",
            Some("Returns secret values from the vault"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("description indicates")),
            "Should detect 'returns secret' in description"
        );
    }

    #[test]
    fn detects_description_no_redaction() {
        let server = make_server_with_tools(vec![make_tool(
            "data_fetcher",
            Some("Fetches data without redaction applied"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("without redact")),
            "Should detect 'without redact' in description"
        );
    }

    #[test]
    fn detects_description_pii() {
        let server = make_server_with_tools(vec![make_tool(
            "user_lookup",
            Some("Returns personally identifiable information for a user"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("personally identifiable")),
            "Should detect PII leakage in description"
        );
    }

    #[test]
    fn detects_description_credit_card() {
        let server = make_server_with_tools(vec![make_tool(
            "payment_info",
            Some("Returns the credit card number on file"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("credit card")),
            "Should detect credit card leakage risk"
        );
    }

    // ── Resource URI tests ──────────────────────────────────────────

    #[test]
    fn detects_env_file_in_args() {
        let findings = check_args(&["-y", "server-files", "/app/.env"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("environment file")),
            "Should detect .env file exposure: {:?}",
            findings
        );
    }

    #[test]
    fn detects_ssh_key_in_args() {
        let findings = check_args(&["-y", "server-fs", "/home/user/.ssh/id_rsa"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("SSH RSA private key")),
            "Should detect SSH key exposure: {:?}",
            findings
        );
    }

    #[test]
    fn detects_git_config_in_args() {
        let findings = check_args(&["-y", "server-files", "/repo/.git/config"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Git config")),
            "Should detect .git/config exposure: {:?}",
            findings
        );
    }

    #[test]
    fn detects_aws_credentials_in_args() {
        let findings = check_args(&["-y", "server-files", "/home/user/.aws/credentials"]);
        assert!(
            findings.iter().any(|f| f.title.contains("AWS credentials")),
            "Should detect AWS credentials exposure: {:?}",
            findings
        );
    }

    #[test]
    fn detects_credentials_json_in_args() {
        let findings = check_args(&["-y", "server-files", "/app/credentials.json"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("application credentials")),
            "Should detect credentials.json exposure: {:?}",
            findings
        );
    }

    #[test]
    fn detects_sensitive_uri_in_tool_description() {
        let server = make_server_with_tools(vec![make_tool(
            "read_file",
            Some("Reads any file including .env and credentials.json"),
        )]);
        let findings = check_server(&server);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("read_file")),
            "Should detect sensitive URI reference in tool description: {:?}",
            findings
        );
    }

    // ── Verbose/debug output tests ──────────────────────────────────

    #[test]
    fn detects_debug_flag() {
        let findings = check_args(&["-y", "server-pkg", "--debug"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Verbose/debug")),
            "Should detect --debug flag: {:?}",
            findings
        );
    }

    #[test]
    fn detects_verbose_flag() {
        let findings = check_args(&["-y", "server-pkg", "--verbose"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Verbose/debug")),
            "Should detect --verbose flag"
        );
    }

    #[test]
    fn detects_trace_log_level() {
        let findings = check_args(&["-y", "server-pkg", "--log-level=trace"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Verbose/debug")),
            "Should detect trace log level"
        );
    }

    #[test]
    fn detects_no_redact_flag() {
        let findings = check_args(&["-y", "server-pkg", "--no-redact"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Verbose/debug") || f.title.contains("redaction")),
            "Should detect --no-redact flag: {:?}",
            findings
        );
    }

    #[test]
    fn detects_debug_env_var() {
        let findings = check_env(vec![("DEBUG", "true")]);
        assert!(
            findings.iter().any(|f| f.title.contains("Debug logging")),
            "Should detect DEBUG=true env var: {:?}",
            findings
        );
    }

    #[test]
    fn detects_log_level_debug_env() {
        let findings = check_env(vec![("LOG_LEVEL", "debug")]);
        assert!(
            findings.iter().any(|f| f.title.contains("Debug logging")),
            "Should detect LOG_LEVEL=debug env var: {:?}",
            findings
        );
    }

    // ── Secret env passthrough tests ──────────────────────────────────

    #[test]
    fn detects_multiple_secrets_passthrough() {
        let findings = check_env(vec![
            ("API_KEY", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"),
            ("SECRET_KEY", "s3cr3t_v4lu3_that_1s_l0ng_en0ugh"),
            ("AUTH_TOKEN", "t0k3n_v4lu3_that_1s_long_enough"),
            ("DATABASE_PASSWORD", "p4ssw0rd_v4lu3_long_enough"),
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Multiple secrets")),
            "Should detect multiple secret env vars as leakage risk: {:?}",
            findings
        );
    }

    #[test]
    fn ignores_safe_env_values() {
        let findings = check_env(vec![
            ("API_KEY", "${API_KEY}"),
            ("SECRET", "your-secret-here"),
            ("TOKEN", "CHANGE_ME"),
        ]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Multiple secrets")),
            "Should not flag placeholder env values"
        );
    }

    #[test]
    fn detects_debug_tools_with_secrets() {
        let rule = DataLeakageRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(vec!["server.js".into()]),
            env: Some(HashMap::from([(
                "API_KEY".into(),
                "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6".into(),
            )])),
            tools: Some(vec![make_tool(
                "debug_info",
                Some("Show debug information"),
            )]),
            ..Default::default()
        };
        let findings = rule.check("test-server", &server);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Debug tools combined with secrets")),
            "Should detect debug tools + secrets combo: {:?}",
            findings
        );
    }

    // ── Safe configuration tests ────────────────────────────────────

    #[test]
    fn safe_server_passes() {
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/home/user/projects".into(),
            ]),
            env: Some(HashMap::from([
                ("NODE_ENV".into(), "production".into()),
                ("PORT".into(), "3000".into()),
            ])),
            tools: Some(vec![
                make_tool("read_file", Some("Read a file from the allowed directory")),
                make_tool("list_files", Some("List files in the allowed directory")),
            ]),
            ..Default::default()
        };
        let findings = check_server(&server);
        assert!(
            findings.is_empty(),
            "Safe server should not produce findings: {:?}",
            findings
        );
    }

    #[test]
    fn safe_tools_pass() {
        let server = make_server_with_tools(vec![
            make_tool("search", Some("Search documents by keyword")),
            make_tool("create_item", Some("Create a new item")),
            make_tool("get_status", Some("Get server status")),
        ]);
        let findings = check_server(&server);
        assert!(
            findings.is_empty(),
            "Safe tools should not produce findings: {:?}",
            findings
        );
    }

    #[test]
    fn server_without_tools_passes() {
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec!["-y".into(), "safe-server".into()]),
            ..Default::default()
        };
        let findings = check_server(&server);
        assert!(
            findings.is_empty(),
            "Server without tools should not produce findings: {:?}",
            findings
        );
    }

    #[test]
    fn normal_env_vars_pass() {
        let findings = check_env(vec![
            ("NODE_ENV", "production"),
            ("PORT", "3000"),
            ("HOST", "localhost"),
            ("DEBUG", "false"),
        ]);
        assert!(
            findings.is_empty(),
            "Normal env vars should not be flagged: {:?}",
            findings
        );
    }

    // ── Helper function tests ────────────────────────────────────────

    #[test]
    fn arg_exposes_resource_exact_match() {
        assert!(arg_exposes_resource(".env", ".env"));
        assert!(arg_exposes_resource("id_rsa", "id_rsa"));
    }

    #[test]
    fn arg_exposes_resource_path_suffix() {
        assert!(arg_exposes_resource("/app/.env", ".env"));
        assert!(arg_exposes_resource("/home/user/.ssh/id_rsa", "id_rsa"));
        assert!(arg_exposes_resource("/project/.git/config", ".git/config"));
    }

    #[test]
    fn arg_exposes_resource_no_false_positives() {
        assert!(!arg_exposes_resource("/app/production.env.bak", ".env"));
        assert!(!arg_exposes_resource("/app/my_env", ".env"));
        assert!(!arg_exposes_resource("/app/notid_rsa", "id_rsa"));
    }

    #[test]
    fn arg_exposes_resource_windows_paths() {
        assert!(arg_exposes_resource("C:\\Users\\user\\.env", ".env"));
        assert!(arg_exposes_resource("C:\\Users\\.ssh\\id_rsa", "id_rsa"));
    }

    #[test]
    fn is_safe_value_detects_placeholders() {
        assert!(is_safe_value("${API_KEY}"));
        assert!(is_safe_value("your-api-key-here"));
        assert!(is_safe_value("CHANGE_ME"));
        assert!(is_safe_value("xxx"));
        assert!(is_safe_value(""));
        assert!(is_safe_value("****"));
    }

    #[test]
    fn is_safe_value_rejects_real_secrets() {
        assert!(!is_safe_value("a1b2c3d4e5f6g7h8i9j0"));
        assert!(!is_safe_value("sk-proj-abc123def456"));
        assert!(!is_safe_value("ghp_1234567890abcdef"));
    }

    // ── Metadata tests ──────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = DataLeakageRule;
        assert_eq!(rule.id(), "MCP-17");
        assert_eq!(rule.name(), "Data Leakage");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-17");
        assert_eq!(rule.default_severity(), Severity::Critical);
    }
}
