//! MCP-14: Insecure Transport
//!
//! Detects insecure transport configurations on HTTP-based MCP servers:
//! plain HTTP without TLS, disabled TLS certificate verification,
//! missing authentication on HTTP endpoints, absent rate limiting,
//! and overly permissive CORS configuration (wildcard origin).

use super::Rule;
use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

// ── TLS verification disabled ───────────────────────────────────────────

/// Environment variables that disable TLS certificate verification.
/// Each entry is (env_key, disabling_value, description).
const TLS_DISABLED_ENV: &[(&str, &str, &str)] = &[
    (
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "0",
        "Node.js TLS certificate verification disabled",
    ),
    (
        "PYTHONHTTPSVERIFY",
        "0",
        "Python HTTPS certificate verification disabled",
    ),
    (
        "SSL_VERIFY",
        "false",
        "SSL certificate verification disabled",
    ),
    (
        "VERIFY_SSL",
        "false",
        "SSL certificate verification disabled",
    ),
    (
        "TLS_VERIFY",
        "false",
        "TLS certificate verification disabled",
    ),
    (
        "VERIFY_TLS",
        "false",
        "TLS certificate verification disabled",
    ),
    (
        "SSL_CERT_VERIFY",
        "false",
        "SSL certificate verification disabled",
    ),
    (
        "REQUESTS_CA_BUNDLE",
        "",
        "Python requests CA bundle cleared — disables certificate verification",
    ),
    (
        "CURL_CA_BUNDLE",
        "",
        "cURL CA bundle cleared — disables certificate verification",
    ),
    ("GIT_SSL_NO_VERIFY", "true", "Git SSL verification disabled"),
    ("SSL_NO_VERIFY", "true", "SSL verification disabled"),
    ("DISABLE_TLS", "true", "TLS explicitly disabled"),
    ("NO_TLS", "true", "TLS explicitly disabled"),
    (
        "INSECURE_SKIP_VERIFY",
        "true",
        "TLS verification skip enabled (Go-style)",
    ),
];

/// Command-line arguments that disable TLS verification.
const TLS_DISABLED_ARGS: &[(&str, &str)] = &[
    ("--no-tls-verify", "disables TLS certificate verification"),
    ("--no-ssl-verify", "disables SSL certificate verification"),
    (
        "--no-check-certificate",
        "disables certificate verification",
    ),
    ("--insecure-skip-tls-verify", "skips TLS verification"),
    ("--disable-tls", "disables TLS"),
    ("--no-tls", "disables TLS"),
    ("--ssl=false", "disables SSL"),
    ("--tls=false", "disables TLS"),
    ("--skip-ssl-validation", "skips SSL validation"),
    ("--skip-tls-verify", "skips TLS verification"),
    ("--allow-insecure", "allows insecure connections"),
];

/// Short flags that disable TLS (exact match only).
const TLS_DISABLED_SHORT_FLAGS: &[(&str, &str)] =
    &[("-k", "disables certificate verification (curl-style)")];

// ── Rate limiting detection ─────────────────────────────────────────────

/// Environment variables that indicate rate limiting is configured.
const RATE_LIMIT_ENV_VARS: &[&str] = &[
    "RATE_LIMIT",
    "RATE_LIMITING",
    "RATELIMIT",
    "MAX_REQUESTS",
    "REQUESTS_PER_SECOND",
    "REQUESTS_PER_MINUTE",
    "REQ_PER_SEC",
    "REQ_PER_MIN",
    "RPS_LIMIT",
    "RPM_LIMIT",
    "THROTTLE",
    "THROTTLE_LIMIT",
    "MAX_RPS",
    "MAX_RPM",
    "API_RATE_LIMIT",
    "RATE_LIMIT_MAX",
    "RATE_LIMIT_WINDOW",
    "CONCURRENT_LIMIT",
    "MAX_CONCURRENT",
    "BURST_LIMIT",
    "MAX_BURST",
];

/// Command-line arguments that indicate rate limiting is configured.
const RATE_LIMIT_ARGS: &[&str] = &[
    "--rate-limit",
    "--ratelimit",
    "--max-requests",
    "--requests-per-second",
    "--requests-per-minute",
    "--throttle",
    "--max-rps",
    "--max-rpm",
    "--burst-limit",
    "--max-burst",
    "--concurrent-limit",
    "--max-concurrent",
    "--rate-limit-max",
    "--rate-limit-window",
];

// ── CORS detection ──────────────────────────────────────────────────────

/// Environment variable name patterns that indicate CORS origin configuration.
const CORS_ENV_PATTERNS: &[&str] = &[
    "CORS_ORIGIN",
    "CORS_ORIGINS",
    "CORS_ALLOWED_ORIGINS",
    "CORS_ALLOW_ORIGIN",
    "ACCESS_CONTROL_ALLOW_ORIGIN",
    "ALLOWED_ORIGINS",
    "ALLOW_ORIGIN",
    "CORS",
];

/// Command-line argument prefixes that indicate CORS origin configuration.
const CORS_ARG_PREFIXES: &[&str] = &[
    "--cors-origin",
    "--cors-origins",
    "--cors-allowed-origins",
    "--cors-allow-origin",
    "--allowed-origins",
    "--cors",
];

// ── Authentication detection (transport-level) ──────────────────────────

/// Environment variable name patterns that indicate transport-level auth.
const TRANSPORT_AUTH_ENV_PATTERNS: &[&str] = &[
    "AUTH",
    "TOKEN",
    "API_KEY",
    "APIKEY",
    "BEARER",
    "SECRET",
    "AUTHORIZATION",
    "ACCESS_KEY",
    "CREDENTIAL",
    "PASSWORD",
    "PASSPHRASE",
];

/// Command-line argument patterns indicating auth is configured.
const TRANSPORT_AUTH_ARGS: &[&str] = &[
    "--auth",
    "--token",
    "--api-key",
    "--apikey",
    "--bearer",
    "--authorization",
    "--access-key",
    "--credential",
    "--password",
    "--secret",
    "--header",
];

// ── Local address patterns (excluded from remote checks) ────────────────

/// Patterns that indicate a local/loopback address.
const LOCAL_PATTERNS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "0.0.0.0"];

pub struct InsecureTransportRule;

impl Rule for InsecureTransportRule {
    fn id(&self) -> &'static str {
        "MCP-14"
    }

    fn name(&self) -> &'static str {
        "Insecure Transport"
    }

    fn description(&self) -> &'static str {
        "Detects insecure transport configurations on HTTP-based MCP servers: \
         plain HTTP without TLS encryption, disabled TLS certificate verification, \
         missing authentication on HTTP endpoints, absent rate limiting, and \
         overly permissive CORS configuration (Access-Control-Allow-Origin: *)."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-14"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        self.check_plain_http(server_name, server, &mut findings);
        self.check_tls_disabled(server_name, server, &mut findings);
        self.check_cors_wildcard(server_name, server, &mut findings);

        // The following checks only apply to HTTP-based servers.
        if server.is_http() {
            self.check_missing_auth(server_name, server, &mut findings);
            self.check_missing_rate_limiting(server_name, server, &mut findings);
        }

        findings
    }
}

impl InsecureTransportRule {
    /// Check 1: Plain HTTP (no TLS) on remote MCP servers.
    ///
    /// Detects URLs using `http://` instead of `https://` for non-local endpoints.
    fn check_plain_http(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        if let Some(url) = &server.url {
            let url_lower = url.to_lowercase();

            if url_lower.starts_with("http://") && !is_local_address(&url_lower) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Plain HTTP transport without TLS in server '{}'",
                        server_name
                    ),
                    description: format!(
                        "Server URL '{}' uses unencrypted HTTP. All remote MCP server \
                         connections must use HTTPS to prevent eavesdropping, credential \
                         theft, and man-in-the-middle attacks on tool invocations. \
                         Change the URL scheme to https://.",
                        url
                    ),
                });
            }
        }
    }

    /// Check 2: TLS certificate verification explicitly disabled.
    ///
    /// Detects environment variables and command-line arguments that disable
    /// TLS/SSL certificate verification, allowing MITM attacks even when HTTPS
    /// is used.
    fn check_tls_disabled(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        // Check environment variables.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let key_upper = key.to_uppercase();
                let value_lower = value.to_lowercase();

                for (env_key, env_value, description) in TLS_DISABLED_ENV {
                    if key_upper == *env_key && value_lower == *env_value {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::High,
                            title: format!("TLS verification disabled in server '{}'", server_name),
                            description: format!(
                                "Environment variable '{}={}' — {}. \
                                 Disabling certificate verification allows \
                                 man-in-the-middle attacks even over HTTPS. \
                                 Remove this variable and use proper CA certificates.",
                                key, value, description
                            ),
                        });
                        break;
                    }
                }
            }
        }

        // Check command-line arguments.
        let args = server.args.as_deref().unwrap_or(&[]);
        for arg in args {
            let arg_lower = arg.to_lowercase();

            // Check long-form flags.
            for (flag, description) in TLS_DISABLED_ARGS {
                if arg_lower == *flag || arg_lower.starts_with(&format!("{}=", flag)) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "TLS verification disabled via argument in server '{}'",
                            server_name
                        ),
                        description: format!(
                            "Argument '{}' {}. Disabling TLS verification allows \
                             man-in-the-middle attacks. Remove this flag and use \
                             proper CA certificates.",
                            arg, description
                        ),
                    });
                    break;
                }
            }

            // Check short flags (exact match).
            for (flag, description) in TLS_DISABLED_SHORT_FLAGS {
                if arg_lower == *flag {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "TLS verification disabled via argument in server '{}'",
                            server_name
                        ),
                        description: format!(
                            "Argument '{}' {}. Disabling TLS verification allows \
                             man-in-the-middle attacks. Remove this flag and use \
                             proper CA certificates.",
                            arg, description
                        ),
                    });
                    break;
                }
            }
        }
    }

    /// Check 3: No authentication configured on HTTP endpoint.
    ///
    /// HTTP-based MCP servers that lack any form of authentication (tokens,
    /// API keys, headers) are accessible to anyone who can reach the endpoint.
    fn check_missing_auth(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let has_auth_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                TRANSPORT_AUTH_ENV_PATTERNS
                    .iter()
                    .any(|pat| upper.contains(pat))
            })
        });

        let args = server.args.as_deref().unwrap_or(&[]);
        let has_auth_arg = args.iter().any(|a| {
            let lower = a.to_lowercase();
            TRANSPORT_AUTH_ARGS.iter().any(|pat| lower.starts_with(pat))
        });

        // Check if the URL itself contains authentication (e.g., basic auth in URL).
        let has_url_auth = server.url.as_ref().is_some_and(|url| {
            // Check for basic auth: http://user:pass@host
            url.contains('@') && url.contains("://")
        });

        if !has_auth_env && !has_auth_arg && !has_url_auth {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::High,
                title: format!(
                    "No authentication on HTTP transport for server '{}'",
                    server_name
                ),
                description: format!(
                    "HTTP-based MCP server '{}' has no authentication configuration \
                     (no auth tokens, API keys, or authorization headers in environment \
                     variables or arguments). Without authentication, any client that \
                     can reach the endpoint can invoke tools and access resources. \
                     Configure authentication via an API key, bearer token, or other \
                     credential mechanism.",
                    server_name
                ),
            });
        }
    }

    /// Check 4: No rate limiting on HTTP endpoint.
    ///
    /// HTTP-based MCP servers without rate limiting are vulnerable to abuse,
    /// resource exhaustion, and brute-force attacks.
    fn check_missing_rate_limiting(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let has_rate_limit_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                RATE_LIMIT_ENV_VARS.iter().any(|rv| upper.contains(rv))
            })
        });

        let args = server.args.as_deref().unwrap_or(&[]);
        let has_rate_limit_arg = args.iter().any(|a| {
            let lower = a.to_lowercase();
            RATE_LIMIT_ARGS.iter().any(|ra| lower.starts_with(ra))
        });

        if !has_rate_limit_env && !has_rate_limit_arg {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!(
                    "No rate limiting on HTTP transport for server '{}'",
                    server_name
                ),
                description: format!(
                    "HTTP-based MCP server '{}' has no rate limiting configuration. \
                     Without rate limiting, the endpoint is vulnerable to abuse, \
                     resource exhaustion, and brute-force attacks against any \
                     authentication mechanism. Configure rate limiting via \
                     environment variables (e.g., RATE_LIMIT, MAX_REQUESTS) or \
                     command-line arguments (e.g., --rate-limit, --max-rps).",
                    server_name
                ),
            });
        }
    }

    /// Check 5: CORS wildcard configuration (Access-Control-Allow-Origin: *).
    ///
    /// A wildcard CORS origin allows any website to make cross-origin requests
    /// to the MCP server, enabling browser-based attacks.
    fn check_cors_wildcard(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        // Check environment variables for CORS wildcard.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let key_upper = key.to_uppercase();
                let value_trimmed = value.trim();

                let is_cors_key = CORS_ENV_PATTERNS.iter().any(|pat| key_upper.contains(pat));

                if is_cors_key && value_trimmed == "*" {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("CORS wildcard origin in server '{}'", server_name),
                        description: format!(
                            "Environment variable '{}=*' sets Access-Control-Allow-Origin \
                             to wildcard. This allows any website to make cross-origin \
                             requests to the MCP server, enabling browser-based CSRF and \
                             data exfiltration attacks. Restrict CORS to specific trusted \
                             origins.",
                            key
                        ),
                    });
                    return; // One CORS finding is enough.
                }
            }
        }

        // Check command-line arguments for CORS wildcard.
        let args = server.args.as_deref().unwrap_or(&[]);
        for (i, arg) in args.iter().enumerate() {
            let arg_lower = arg.to_lowercase();

            let is_cors_arg = CORS_ARG_PREFIXES
                .iter()
                .any(|prefix| arg_lower.starts_with(prefix));

            if !is_cors_arg {
                continue;
            }

            // Check for --cors-origin=* (inline value).
            if let Some((_key, value)) = arg.split_once('=') {
                if value.trim() == "*" {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("CORS wildcard origin in server '{}'", server_name),
                        description: format!(
                            "Argument '{}' sets CORS origin to wildcard (*). This allows \
                             any website to make cross-origin requests to the MCP server. \
                             Restrict CORS to specific trusted origins.",
                            arg
                        ),
                    });
                    return;
                }
            }

            // Check for --cors-origin * (next arg is value).
            if let Some(next_arg) = args.get(i + 1) {
                if next_arg.trim() == "*" {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("CORS wildcard origin in server '{}'", server_name),
                        description: format!(
                            "Arguments '{} *' set CORS origin to wildcard. This allows \
                             any website to make cross-origin requests to the MCP server. \
                             Restrict CORS to specific trusted origins.",
                            arg
                        ),
                    });
                    return;
                }
            }
        }
    }
}

/// Returns true if the URL points to a local/loopback address.
fn is_local_address(url_lower: &str) -> bool {
    LOCAL_PATTERNS.iter().any(|pat| url_lower.contains(pat))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    // ── Helper functions ────────────────────────────────────────────────

    fn check_url(name: &str, url: &str) -> Vec<ScanFinding> {
        let rule = InsecureTransportRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_url_with_env(name: &str, url: &str, env: HashMap<String, String>) -> Vec<ScanFinding> {
        let rule = InsecureTransportRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            env: Some(env),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_url_with_args(name: &str, url: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = InsecureTransportRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_cmd_with_env(
        cmd: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Vec<ScanFinding> {
        let rule = InsecureTransportRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_cmd_args(cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        check_cmd_with_env(cmd, args, HashMap::new())
    }

    // ── Rule metadata ───────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = InsecureTransportRule;
        assert_eq!(rule.id(), "MCP-14");
        assert_eq!(rule.name(), "Insecure Transport");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-14");
        assert_eq!(rule.default_severity(), Severity::High);
        assert!(!rule.description().is_empty());
    }

    // ── Check 1: Plain HTTP without TLS ─────────────────────────────────

    #[test]
    fn detects_plain_http_remote() {
        let findings = check_url("remote-api", "http://api.example.com/mcp");
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Plain HTTP") && f.severity == Severity::High),
            "Should detect plain HTTP on remote server"
        );
    }

    #[test]
    fn allows_http_localhost() {
        let findings = check_url("local", "http://localhost:8080/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should allow HTTP on localhost"
        );
    }

    #[test]
    fn allows_http_127_0_0_1() {
        let findings = check_url("local", "http://127.0.0.1:3000/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should allow HTTP on 127.0.0.1"
        );
    }

    #[test]
    fn allows_http_ipv6_loopback() {
        let findings = check_url("local", "http://[::1]:3000/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should allow HTTP on IPv6 loopback"
        );
    }

    #[test]
    fn allows_https_remote() {
        let findings = check_url("remote", "https://api.example.com/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should not flag HTTPS connections"
        );
    }

    #[test]
    fn detects_http_with_port() {
        let findings = check_url("remote", "http://mcp.company.com:8080/api");
        assert!(
            findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should detect plain HTTP even with non-standard port"
        );
    }

    // ── Check 2: TLS verification disabled ──────────────────────────────

    #[test]
    fn detects_node_tls_reject_unauthorized() {
        let mut env = HashMap::new();
        env.insert("NODE_TLS_REJECT_UNAUTHORIZED".into(), "0".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect NODE_TLS_REJECT_UNAUTHORIZED=0"
        );
    }

    #[test]
    fn detects_ssl_verify_false() {
        let mut env = HashMap::new();
        env.insert("SSL_VERIFY".into(), "false".into());
        let findings = check_cmd_with_env("python", &["server.py"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect SSL_VERIFY=false"
        );
    }

    #[test]
    fn detects_python_https_verify_disabled() {
        let mut env = HashMap::new();
        env.insert("PYTHONHTTPSVERIFY".into(), "0".into());
        let findings = check_cmd_with_env("python", &["server.py"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect PYTHONHTTPSVERIFY=0"
        );
    }

    #[test]
    fn detects_insecure_skip_verify() {
        let mut env = HashMap::new();
        env.insert("INSECURE_SKIP_VERIFY".into(), "true".into());
        let findings = check_cmd_with_env("server", &[], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect INSECURE_SKIP_VERIFY=true"
        );
    }

    #[test]
    fn ssl_verify_true_passes() {
        let mut env = HashMap::new();
        env.insert("SSL_VERIFY".into(), "true".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "SSL_VERIFY=true should not flag"
        );
    }

    #[test]
    fn detects_no_tls_verify_arg() {
        let findings = check_cmd_args("node", &["server.js", "--no-tls-verify"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect --no-tls-verify argument"
        );
    }

    #[test]
    fn detects_no_ssl_verify_arg() {
        let findings = check_cmd_args("node", &["server.js", "--no-ssl-verify"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect --no-ssl-verify argument"
        );
    }

    #[test]
    fn detects_insecure_skip_tls_verify_arg() {
        let findings = check_cmd_args("kubectl", &["--insecure-skip-tls-verify", "proxy"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect --insecure-skip-tls-verify argument"
        );
    }

    #[test]
    fn detects_curl_k_flag() {
        let findings = check_cmd_args("curl", &["-k", "https://api.example.com"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect -k (curl insecure) flag"
        );
    }

    #[test]
    fn detects_ssl_false_arg() {
        let findings = check_cmd_args("node", &["server.js", "--ssl=false"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect --ssl=false argument"
        );
    }

    // ── Check 3: No authentication on HTTP endpoint ─────────────────────

    #[test]
    fn detects_http_without_auth() {
        let findings = check_url("remote-api", "https://api.example.com/mcp");
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "Should detect HTTP server without auth configuration"
        );
    }

    #[test]
    fn http_with_auth_token_env_passes() {
        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".into(), "my-secret-token".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with AUTH_TOKEN should not flag missing auth"
        );
    }

    #[test]
    fn http_with_api_key_env_passes() {
        let mut env = HashMap::new();
        env.insert("MCP_API_KEY".into(), "key-123".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with API_KEY env should not flag missing auth"
        );
    }

    #[test]
    fn http_with_bearer_arg_passes() {
        let findings = check_url_with_args(
            "remote-api",
            "https://api.example.com/mcp",
            &["--bearer", "token-abc"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with --bearer arg should not flag missing auth"
        );
    }

    #[test]
    fn http_with_auth_arg_passes() {
        let findings = check_url_with_args(
            "remote-api",
            "https://api.example.com/mcp",
            &["--auth", "user:pass"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with --auth arg should not flag missing auth"
        );
    }

    #[test]
    fn http_with_url_basic_auth_passes() {
        let findings = check_url("remote-api", "https://user:pass@api.example.com/mcp");
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "HTTP server with basic auth in URL should not flag missing auth"
        );
    }

    #[test]
    fn stdio_server_no_auth_not_flagged() {
        let findings = check_cmd_args("npx", &["-y", "@modelcontextprotocol/server-filesystem"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No authentication")),
            "Stdio servers should not be checked for HTTP auth"
        );
    }

    // ── Check 4: No rate limiting ───────────────────────────────────────

    #[test]
    fn detects_missing_rate_limiting() {
        let findings = check_url("remote-api", "https://api.example.com/mcp");
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "Should detect HTTP server without rate limiting"
        );
    }

    #[test]
    fn rate_limit_env_passes() {
        let mut env = HashMap::new();
        env.insert("RATE_LIMIT".into(), "100".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "HTTP server with RATE_LIMIT env should not flag rate limiting"
        );
    }

    #[test]
    fn max_requests_env_passes() {
        let mut env = HashMap::new();
        env.insert("MAX_REQUESTS".into(), "1000".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "HTTP server with MAX_REQUESTS env should not flag rate limiting"
        );
    }

    #[test]
    fn rate_limit_arg_passes() {
        let findings = check_url_with_args(
            "remote-api",
            "https://api.example.com/mcp",
            &["--rate-limit", "100"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "HTTP server with --rate-limit arg should not flag rate limiting"
        );
    }

    #[test]
    fn max_rps_arg_passes() {
        let findings = check_url_with_args(
            "remote-api",
            "https://api.example.com/mcp",
            &["--max-rps", "50"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "HTTP server with --max-rps arg should not flag rate limiting"
        );
    }

    #[test]
    fn throttle_env_passes() {
        let mut env = HashMap::new();
        env.insert("THROTTLE_LIMIT".into(), "10".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "HTTP server with THROTTLE_LIMIT env should not flag rate limiting"
        );
    }

    #[test]
    fn stdio_server_no_rate_limit_not_flagged() {
        let findings = check_cmd_args("npx", &["-y", "some-server"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No rate limiting")),
            "Stdio servers should not be checked for rate limiting"
        );
    }

    // ── Check 5: CORS wildcard ──────────────────────────────────────────

    #[test]
    fn detects_cors_wildcard_env() {
        let mut env = HashMap::new();
        env.insert("CORS_ORIGIN".into(), "*".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("CORS wildcard") && f.severity == Severity::High),
            "Should detect CORS_ORIGIN=* as high severity"
        );
    }

    #[test]
    fn detects_cors_allowed_origins_wildcard() {
        let mut env = HashMap::new();
        env.insert("CORS_ALLOWED_ORIGINS".into(), "*".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Should detect CORS_ALLOWED_ORIGINS=*"
        );
    }

    #[test]
    fn detects_access_control_allow_origin_wildcard() {
        let mut env = HashMap::new();
        env.insert("ACCESS_CONTROL_ALLOW_ORIGIN".into(), "*".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Should detect ACCESS_CONTROL_ALLOW_ORIGIN=*"
        );
    }

    #[test]
    fn cors_specific_origin_passes() {
        let mut env = HashMap::new();
        env.insert("CORS_ORIGIN".into(), "https://app.example.com".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Specific CORS origin should not flag"
        );
    }

    #[test]
    fn detects_cors_wildcard_inline_arg() {
        let findings = check_cmd_args("node", &["server.js", "--cors-origin=*"]);
        assert!(
            findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Should detect --cors-origin=* argument"
        );
    }

    #[test]
    fn detects_cors_wildcard_separate_arg() {
        let findings = check_cmd_args("node", &["server.js", "--cors-origin", "*"]);
        assert!(
            findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Should detect --cors-origin * (separate args)"
        );
    }

    #[test]
    fn cors_specific_origin_arg_passes() {
        let findings = check_cmd_args("node", &["server.js", "--cors-origin=https://trusted.com"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Specific CORS origin in arg should not flag"
        );
    }

    #[test]
    fn detects_cors_env_on_http_server() {
        let mut env = HashMap::new();
        env.insert("CORS_ORIGIN".into(), "*".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            findings.iter().any(|f| f.title.contains("CORS wildcard")),
            "Should detect CORS wildcard on HTTP server"
        );
    }

    // ── Combined scenarios ──────────────────────────────────────────────

    #[test]
    fn secure_http_server_minimal_findings() {
        let mut env = HashMap::new();
        env.insert("AUTH_TOKEN".into(), "my-token".into());
        env.insert("RATE_LIMIT".into(), "100".into());
        env.insert("CORS_ORIGIN".into(), "https://app.example.com".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            findings.is_empty(),
            "Fully secured HTTPS server should have no transport findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn insecure_http_server_multiple_findings() {
        let findings = check_url("remote-api", "http://api.example.com/mcp");
        // Should have: plain HTTP, no auth, no rate limiting.
        let has_plain_http = findings.iter().any(|f| f.title.contains("Plain HTTP"));
        let has_no_auth = findings
            .iter()
            .any(|f| f.title.contains("No authentication"));
        let has_no_rate = findings
            .iter()
            .any(|f| f.title.contains("No rate limiting"));
        assert!(has_plain_http, "Should detect plain HTTP");
        assert!(has_no_auth, "Should detect missing auth");
        assert!(has_no_rate, "Should detect missing rate limiting");
    }

    #[test]
    fn tls_disabled_env_on_https_server() {
        let mut env = HashMap::new();
        env.insert("NODE_TLS_REJECT_UNAUTHORIZED".into(), "0".into());
        env.insert("AUTH_TOKEN".into(), "token".into());
        env.insert("RATE_LIMIT".into(), "100".into());
        let findings = check_url_with_env("remote-api", "https://api.example.com/mcp", env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("TLS verification disabled")),
            "Should detect TLS verification disabled even on HTTPS server"
        );
    }

    #[test]
    fn cors_wildcard_with_tls_disabled() {
        let mut env = HashMap::new();
        env.insert("NODE_TLS_REJECT_UNAUTHORIZED".into(), "0".into());
        env.insert("CORS_ORIGIN".into(), "*".into());
        let findings = check_cmd_with_env("node", &["server.js"], env);
        let has_tls = findings
            .iter()
            .any(|f| f.title.contains("TLS verification disabled"));
        let has_cors = findings.iter().any(|f| f.title.contains("CORS wildcard"));
        assert!(has_tls, "Should detect TLS verification disabled");
        assert!(has_cors, "Should detect CORS wildcard");
    }

    #[test]
    fn all_high_severity_findings_for_critical_issues() {
        let findings = check_url("remote-api", "http://api.example.com/mcp");
        for f in &findings {
            if f.title.contains("Plain HTTP") || f.title.contains("No authentication") {
                assert_eq!(
                    f.severity,
                    Severity::High,
                    "Plain HTTP and missing auth should be High severity"
                );
            }
        }
    }

    #[test]
    fn rate_limiting_finding_is_medium_severity() {
        let findings = check_url("remote-api", "https://api.example.com/mcp");
        let rate_finding = findings
            .iter()
            .find(|f| f.title.contains("No rate limiting"));
        assert!(rate_finding.is_some(), "Should find rate limiting issue");
        assert_eq!(
            rate_finding.unwrap().severity,
            Severity::Medium,
            "Rate limiting finding should be Medium severity"
        );
    }

    #[test]
    fn allows_http_0_0_0_0() {
        let findings = check_url("dev", "http://0.0.0.0:3000/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("Plain HTTP")),
            "Should allow HTTP on 0.0.0.0 (local bind address)"
        );
    }
}
