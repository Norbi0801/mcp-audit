//! MCP-13: Resource Exposure
//!
//! Detects MCP servers that expose sensitive resources through the MCP protocol.
//! Checks for path traversal patterns in resource URIs, filesystem access outside
//! sandboxed boundaries, sensitive file patterns, and missing access control on
//! resource-serving servers.

use super::Rule;
use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Path traversal patterns including URL-encoded variants.
const PATH_TRAVERSAL_PATTERNS: &[(&str, &str)] = &[
    ("../", "dot-dot-slash directory traversal"),
    ("..\\", "dot-dot-backslash directory traversal"),
    ("%2e%2e%2f", "URL-encoded directory traversal (lowercase)"),
    ("%2E%2E%2F", "URL-encoded directory traversal (uppercase)"),
    ("%2e%2e/", "partially URL-encoded directory traversal"),
    ("..%2f", "partially URL-encoded directory traversal"),
    ("..%5c", "URL-encoded backslash traversal"),
    ("%2e%2e%5c", "fully URL-encoded backslash traversal"),
    ("%252e%252e%252f", "double URL-encoded directory traversal"),
    ("....//", "double-dot-double-slash bypass"),
    ("..;/", "semicolon-based traversal bypass"),
];

/// Sensitive file patterns that should never be exposed as resources.
const SENSITIVE_RESOURCE_PATTERNS: &[(&str, &str)] = &[
    (".env", "environment variables file (may contain secrets)"),
    (".env.local", "local environment overrides"),
    (".env.production", "production environment variables"),
    (".env.staging", "staging environment variables"),
    (".git/", "Git repository internals (history, credentials)"),
    (".git/config", "Git configuration (may contain credentials)"),
    (".git/HEAD", "Git HEAD reference"),
    (".gitconfig", "Git user configuration"),
    (".svn/", "Subversion repository metadata"),
    (".hg/", "Mercurial repository metadata"),
    (".DS_Store", "macOS directory metadata"),
    ("Thumbs.db", "Windows thumbnail cache"),
    (".htaccess", "Apache access control file"),
    (".htpasswd", "Apache password file"),
    (
        "wp-config.php",
        "WordPress configuration (database credentials)",
    ),
    ("web.config", "IIS/ASP.NET configuration"),
    (".npmrc", "npm configuration (may contain auth tokens)"),
    (".yarnrc", "Yarn configuration"),
    (".pypirc", "PyPI credentials"),
    ("id_rsa", "SSH RSA private key"),
    ("id_rsa.pub", "SSH RSA public key"),
    ("id_ed25519", "SSH Ed25519 private key"),
    ("id_ecdsa", "SSH ECDSA private key"),
    (".pem", "PEM certificate/key file"),
    (".key", "private key file"),
    (".p12", "PKCS#12 certificate bundle"),
    (".pfx", "PKCS#12 certificate bundle"),
    (".jks", "Java keystore"),
    ("credentials.json", "application credentials"),
    ("credentials.yaml", "application credentials"),
    ("credentials.yml", "application credentials"),
    ("service-account.json", "service account key file"),
    ("secrets.json", "application secrets"),
    ("secrets.yaml", "application secrets"),
    ("secrets.yml", "application secrets"),
    (".dockerenv", "Docker environment indicator"),
    ("docker-compose.yml", "Docker Compose (may contain secrets)"),
    (
        "docker-compose.yaml",
        "Docker Compose (may contain secrets)",
    ),
    (".kube/config", "Kubernetes configuration"),
    ("kubeconfig", "Kubernetes configuration"),
    ("/etc/passwd", "system user database"),
    ("/etc/shadow", "system password hashes"),
    ("/etc/hosts", "network host mappings"),
    ("/proc/", "Linux process filesystem"),
    ("/sys/", "Linux kernel filesystem"),
];

/// Sensitive directory patterns that indicate broad resource exposure.
const SENSITIVE_RESOURCE_DIRS: &[(&str, &str)] = &[
    (".ssh", "SSH keys and configuration"),
    (".gnupg", "GPG keys and keyrings"),
    (".aws", "AWS credentials and configuration"),
    (".azure", "Azure credentials and configuration"),
    (".gcloud", "Google Cloud credentials"),
    (".config/gcloud", "Google Cloud SDK configuration"),
    (".kube", "Kubernetes configuration and tokens"),
    (".docker", "Docker configuration and credentials"),
    (".vault-token", "HashiCorp Vault token"),
    (".password-store", "pass password store"),
    (".mozilla", "Firefox profiles (saved passwords)"),
    (".chrome", "Chrome profiles (saved passwords)"),
    ("node_modules", "npm packages (potential supply chain risk)"),
    ("__pycache__", "Python cache (may leak source paths)"),
];

/// Known MCP resource-serving server packages.
const RESOURCE_SERVER_PACKAGES: &[&str] = &[
    "server-filesystem",
    "server-files",
    "server-fs",
    "mcp-filesystem",
    "mcp-files",
    "mcp-fs",
    "file-server",
    "fileserver",
    "static-server",
    "resource-server",
    "server-resources",
    "server-everything",
    "server-memory",
    "server-knowledge",
    "server-docs",
    "server-documents",
    "server-assets",
    "server-blob",
    "server-storage",
];

/// Arguments that indicate resource access control is configured.
const ACCESS_CONTROL_INDICATORS: &[&str] = &[
    "--allow-list",
    "--allowlist",
    "--allowed-paths",
    "--allowed-resources",
    "--allowed-dirs",
    "--allowed-directories",
    "--allow-pattern",
    "--deny-list",
    "--denylist",
    "--deny-pattern",
    "--blocked-paths",
    "--blocked-resources",
    "--acl",
    "--access-control",
    "--resource-policy",
    "--resource-filter",
    "--whitelist",
    "--blacklist",
    "--include-pattern",
    "--exclude-pattern",
    "--include-path",
    "--exclude-path",
    "--read-only",
    "--readonly",
    "--no-write",
    "--max-depth",
    "--sandbox",
    "--sandboxed",
    "--jail",
    "--chroot",
    "--restrict",
    "--restricted",
];

/// Environment variable names that indicate resource access control.
const ACCESS_CONTROL_ENV_PATTERNS: &[&str] = &[
    "ALLOWED_PATHS",
    "ALLOWED_RESOURCES",
    "ALLOWED_DIRS",
    "ALLOW_LIST",
    "ALLOWLIST",
    "DENY_LIST",
    "DENYLIST",
    "BLOCKED_PATHS",
    "RESOURCE_ACL",
    "RESOURCE_POLICY",
    "RESOURCE_FILTER",
    "ACCESS_CONTROL",
    "SANDBOX_PATH",
    "SANDBOX_DIR",
    "SANDBOX_ROOT",
    "ROOT_DIR",
    "BASE_DIR",
    "SERVE_DIR",
    "MAX_DEPTH",
    "READ_ONLY",
    "READONLY",
    "RESTRICT_PATHS",
];

pub struct ResourceExposureRule;

impl super::Rule for ResourceExposureRule {
    fn id(&self) -> &'static str {
        "MCP-13"
    }

    fn name(&self) -> &'static str {
        "Resource Exposure"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers that expose sensitive resources through path traversal \
         patterns, filesystem access outside sandboxed boundaries, sensitive file \
         patterns (.env, .git/, credentials, keys), and missing access control on \
         resource-serving servers."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-06"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        check_path_traversal(self, server_name, server, &mut findings);
        check_sensitive_resource_patterns(self, server_name, server, &mut findings);
        check_sensitive_resource_dirs(self, server_name, server, &mut findings);
        check_resource_uri_schemes(self, server_name, server, &mut findings);
        check_missing_access_control(self, server_name, server, &mut findings);

        findings
    }
}

/// Check for path traversal patterns in arguments, URLs, and environment variables.
fn check_path_traversal(
    rule: &ResourceExposureRule,
    server_name: &str,
    server: &McpServerConfig,
    findings: &mut Vec<ScanFinding>,
) {
    let args = server.args.as_deref().unwrap_or(&[]);

    // Check arguments for path traversal.
    for arg in args {
        let lower = arg.to_lowercase();
        for (pattern, description) in PATH_TRAVERSAL_PATTERNS {
            if lower.contains(&pattern.to_lowercase()) {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::Critical,
                    title: format!(
                        "Path traversal in resource URI for server '{}'",
                        server_name
                    ),
                    description: format!(
                        "Argument '{}' contains a {} pattern ('{}'). \
                         Path traversal can allow access to files outside the \
                         intended resource directory, potentially exposing \
                         sensitive system files. Remove traversal sequences and \
                         use absolute, validated paths.",
                        arg, description, pattern
                    ),
                });
                break; // One finding per arg is sufficient.
            }
        }
    }

    // Check URL for path traversal.
    if let Some(url) = &server.url {
        let lower = url.to_lowercase();
        for (pattern, description) in PATH_TRAVERSAL_PATTERNS {
            if lower.contains(&pattern.to_lowercase()) {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::Critical,
                    title: format!("Path traversal in server URL for '{}'", server_name),
                    description: format!(
                        "Server URL '{}' contains a {} pattern ('{}'). \
                         This may allow resource access outside the intended scope.",
                        url, description, pattern
                    ),
                });
                break;
            }
        }
    }

    // Check environment variables for path traversal.
    if let Some(env) = &server.env {
        for (key, value) in env {
            let lower = value.to_lowercase();
            for (pattern, description) in PATH_TRAVERSAL_PATTERNS {
                if lower.contains(&pattern.to_lowercase()) {
                    findings.push(ScanFinding {
                        rule_id: rule.id().to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Path traversal in environment variable for server '{}'",
                            server_name
                        ),
                        description: format!(
                            "Environment variable '{}' contains a {} pattern ('{}'). \
                             Validate and sanitize all paths used for resource resolution.",
                            key, description, pattern
                        ),
                    });
                    break;
                }
            }
        }
    }
}

/// Check for sensitive file patterns in arguments and environment variables.
fn check_sensitive_resource_patterns(
    rule: &ResourceExposureRule,
    server_name: &str,
    server: &McpServerConfig,
    findings: &mut Vec<ScanFinding>,
) {
    let args = server.args.as_deref().unwrap_or(&[]);

    // Only flag if the server looks like it serves resources.
    if !is_resource_server(server) {
        return;
    }

    for arg in args {
        let normalized = arg.replace('\\', "/");
        for (pattern, description) in SENSITIVE_RESOURCE_PATTERNS {
            // Check for exact filename match or path containing the pattern.
            if matches_sensitive_pattern(&normalized, pattern) {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::High,
                    title: format!("Sensitive resource exposed by server '{}'", server_name),
                    description: format!(
                        "Server argument '{}' references '{}' ({}). \
                         Exposing this as an MCP resource may leak sensitive data. \
                         Exclude sensitive files from the resource scope.",
                        arg, pattern, description
                    ),
                });
                break; // One finding per arg.
            }
        }
    }

    // Check environment variable values that configure resource paths.
    if let Some(env) = &server.env {
        for (key, value) in env {
            let key_upper = key.to_uppercase();
            // Only check env vars that look like path/resource configuration.
            if !is_resource_path_env(&key_upper) {
                continue;
            }
            let normalized = value.replace('\\', "/");
            for (pattern, description) in SENSITIVE_RESOURCE_PATTERNS {
                if matches_sensitive_pattern(&normalized, pattern) {
                    findings.push(ScanFinding {
                        rule_id: rule.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Sensitive resource path in environment for server '{}'",
                            server_name
                        ),
                        description: format!(
                            "Environment variable '{}' references '{}' ({}). \
                             Do not configure resource servers to expose sensitive files.",
                            key, pattern, description
                        ),
                    });
                    break;
                }
            }
        }
    }
}

/// Check for sensitive directory access in resource server arguments.
fn check_sensitive_resource_dirs(
    rule: &ResourceExposureRule,
    server_name: &str,
    server: &McpServerConfig,
    findings: &mut Vec<ScanFinding>,
) {
    let args = server.args.as_deref().unwrap_or(&[]);

    if !is_resource_server(server) {
        return;
    }

    for arg in args {
        let normalized = arg.replace('\\', "/");
        for (dir_pattern, description) in SENSITIVE_RESOURCE_DIRS {
            if normalized.contains(dir_pattern) {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::High,
                    title: format!("Sensitive directory exposed by server '{}'", server_name),
                    description: format!(
                        "Server argument '{}' includes access to '{}' ({}). \
                         This directory may contain credentials, keys, or other \
                         sensitive data that should not be exposed as MCP resources.",
                        arg, dir_pattern, description
                    ),
                });
                break;
            }
        }
    }
}

/// Check for dangerous resource URI schemes in arguments.
fn check_resource_uri_schemes(
    rule: &ResourceExposureRule,
    server_name: &str,
    server: &McpServerConfig,
    findings: &mut Vec<ScanFinding>,
) {
    let args = server.args.as_deref().unwrap_or(&[]);

    for arg in args {
        let lower = arg.to_lowercase();

        // file:// URIs that reference sensitive system paths.
        if lower.starts_with("file://") {
            let path = &arg[7..]; // Strip "file://"
            let normalized = path.replace('\\', "/");

            // Check for root-level file:// access.
            if normalized == "/"
                || normalized == "//"
                || normalized.starts_with("///")
                || normalized == "."
            {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::Critical,
                    title: format!("Root filesystem resource URI in server '{}'", server_name),
                    description: format!(
                        "Argument '{}' exposes the root filesystem as a resource. \
                         This grants access to all files on the system. \
                         Restrict to specific subdirectories.",
                        arg
                    ),
                });
            }
        }

        // resource:// URIs with overly broad patterns.
        if lower.starts_with("resource://") {
            let path = &arg[11..]; // Strip "resource://"

            // Wildcard resource access.
            if path == "*" || path == "**" || path == "**/*" || path.is_empty() {
                findings.push(ScanFinding {
                    rule_id: rule.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Unrestricted resource URI pattern in server '{}'",
                        server_name
                    ),
                    description: format!(
                        "Argument '{}' uses a wildcard resource URI that exposes \
                         all server resources without restriction. Define explicit \
                         resource patterns to limit exposure.",
                        arg
                    ),
                });
            }
        }
    }
}

/// Check resource-serving servers for missing access control configuration.
fn check_missing_access_control(
    rule: &ResourceExposureRule,
    server_name: &str,
    server: &McpServerConfig,
    findings: &mut Vec<ScanFinding>,
) {
    if !is_resource_server(server) {
        return;
    }

    let args = server.args.as_deref().unwrap_or(&[]);

    // Check if any access control indicators are present in args.
    let has_acl_arg = args.iter().any(|a| {
        let lower = a.to_lowercase();
        ACCESS_CONTROL_INDICATORS
            .iter()
            .any(|indicator| lower.starts_with(&indicator.to_lowercase()))
    });

    // Check if any access control indicators are present in env vars.
    let has_acl_env = server.env.as_ref().is_some_and(|env| {
        env.keys().any(|k| {
            let upper = k.to_uppercase();
            ACCESS_CONTROL_ENV_PATTERNS
                .iter()
                .any(|pattern| upper.contains(pattern))
        })
    });

    if !has_acl_arg && !has_acl_env {
        findings.push(ScanFinding {
            rule_id: rule.id().to_string(),
            severity: Severity::High,
            title: format!("No access control on resource server '{}'", server_name),
            description: format!(
                "Resource-serving MCP server '{}' has no apparent access control \
                 configuration (no allowlist, denylist, sandbox, or read-only \
                 flags detected). Without access control, the server may expose \
                 all available resources to any connected client. Configure \
                 --allowed-paths, --read-only, or equivalent restrictions.",
                server_name
            ),
        });
    }
}

/// Determine if a server appears to be a resource-serving MCP server.
fn is_resource_server(server: &McpServerConfig) -> bool {
    let cmd_and_args = format!(
        "{} {}",
        server.command.as_deref().unwrap_or(""),
        server.args_string()
    )
    .to_lowercase();

    RESOURCE_SERVER_PACKAGES
        .iter()
        .any(|pkg| cmd_and_args.contains(pkg))
}

/// Check if an environment variable name suggests it configures resource paths.
fn is_resource_path_env(key: &str) -> bool {
    const RESOURCE_ENV_INDICATORS: &[&str] = &[
        "PATH",
        "DIR",
        "DIRECTORY",
        "ROOT",
        "BASE",
        "SERVE",
        "RESOURCE",
        "FILE",
        "ASSET",
        "MOUNT",
        "VOLUME",
        "STORAGE",
        "UPLOAD",
        "DOCUMENT",
    ];

    RESOURCE_ENV_INDICATORS
        .iter()
        .any(|indicator| key.contains(indicator))
}

/// Check if a normalized path matches a sensitive file/directory pattern.
fn matches_sensitive_pattern(normalized_path: &str, pattern: &str) -> bool {
    // Exact filename match at end of path.
    if normalized_path.ends_with(pattern) {
        // Make sure it's a full filename match, not a substring.
        let prefix_len = normalized_path.len() - pattern.len();
        if prefix_len == 0 {
            return true;
        }
        let preceding = normalized_path.as_bytes()[prefix_len - 1];
        if preceding == b'/' || preceding == b'\\' {
            return true;
        }
        // File extension patterns (e.g., ".pem", ".key") — match if the
        // pattern starts with a dot and the preceding char is not a separator,
        // since "server.pem" should match ".pem".
        if pattern.starts_with('.') && !pattern.contains('/') {
            return true;
        }
    }

    // Pattern appears as a path segment.
    if pattern.ends_with('/') {
        // Directory pattern — check if it appears in the path.
        return normalized_path.contains(pattern)
            || normalized_path.ends_with(pattern.trim_end_matches('/'));
    }

    // Check for the pattern preceded by a path separator.
    let with_slash = format!("/{}", pattern);
    if normalized_path.contains(&with_slash) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    /// Helper: check a resource server with given args.
    fn check_resource_server(args: &[&str]) -> Vec<ScanFinding> {
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    /// Helper: check a server with given command, args, and env.
    fn check_server_full(
        cmd: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Vec<ScanFinding> {
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    /// Helper: check an HTTP server with given URL.
    fn check_url(url: &str) -> Vec<ScanFinding> {
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    // ==================== Rule Metadata ====================

    #[test]
    fn rule_metadata() {
        let rule = ResourceExposureRule;
        assert_eq!(rule.id(), "MCP-13");
        assert_eq!(rule.name(), "Resource Exposure");
        assert_eq!(rule.default_severity(), Severity::High);
        assert_eq!(rule.owasp_id(), "OWASP-MCP-06");
    }

    // ==================== Path Traversal ====================

    #[test]
    fn detects_path_traversal_in_args() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/app/../../etc/passwd",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Path traversal")),
            "Should detect ../ traversal in args"
        );
    }

    #[test]
    fn detects_url_encoded_traversal() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/app/%2e%2e%2fetc/passwd",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Path traversal")),
            "Should detect URL-encoded traversal"
        );
    }

    #[test]
    fn detects_double_encoded_traversal() {
        let findings = check_resource_server(&["-y", "server-fs", "/data/%252e%252e%252f/secrets"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect double URL-encoded traversal"
        );
    }

    #[test]
    fn detects_backslash_traversal() {
        let findings =
            check_resource_server(&["-y", "server-fs", "C:\\app\\..\\Windows\\System32"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Path traversal")),
            "Should detect backslash traversal"
        );
    }

    #[test]
    fn detects_traversal_in_url() {
        let findings = check_url("https://mcp.example.com/resources/../../admin");
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Path traversal")),
            "Should detect traversal in server URL"
        );
    }

    #[test]
    fn detects_traversal_in_env() {
        let mut env = HashMap::new();
        env.insert("RESOURCE_PATH".into(), "/app/data/../../etc".into());
        let findings = check_server_full("node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Path traversal")),
            "Should detect traversal in env variables"
        );
    }

    #[test]
    fn detects_semicolon_traversal_bypass() {
        let findings =
            check_resource_server(&["-y", "server-filesystem", "/resources/..;/admin/config"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect semicolon-based traversal bypass"
        );
    }

    #[test]
    fn clean_path_no_traversal_finding() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/projects/myapp",
        ]);
        assert!(
            !findings.iter().any(|f| f.title.contains("Path traversal")),
            "Clean absolute path should not trigger traversal finding"
        );
    }

    // ==================== Sensitive File Patterns ====================

    #[test]
    fn detects_env_file_exposure() {
        let findings =
            check_resource_server(&["-y", "@modelcontextprotocol/server-filesystem", "/app/.env"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect .env file in resource server scope"
        );
    }

    #[test]
    fn detects_git_directory_exposure() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/project/.git/config",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect .git/config exposure"
        );
    }

    #[test]
    fn detects_ssh_key_exposure() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/id_rsa",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect SSH private key exposure"
        );
    }

    #[test]
    fn detects_credentials_json_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/app/credentials.json"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect credentials.json exposure"
        );
    }

    #[test]
    fn detects_env_production_exposure() {
        let findings = check_resource_server(&["-y", "server-fs", "/deploy/.env.production"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect .env.production exposure"
        );
    }

    #[test]
    fn detects_pem_file_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/certs/server.pem"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect PEM certificate exposure"
        );
    }

    #[test]
    fn detects_kube_config_exposure() {
        let findings =
            check_resource_server(&["-y", "server-filesystem", "/home/user/.kube/config"]);
        // Both sensitive resource and sensitive directory findings should trigger.
        assert!(
            findings.iter().any(|f| f.title.contains("Sensitive")),
            "Should detect .kube/config exposure"
        );
    }

    #[test]
    fn detects_proc_filesystem_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/proc/self/environ"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource")),
            "Should detect /proc/ filesystem exposure"
        );
    }

    #[test]
    fn non_resource_server_skips_file_check() {
        // A server that is NOT a known resource server should not trigger
        // sensitive file findings (to avoid false positives).
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-github".into(),
                "/app/.env".into(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("github-server", &server);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource exposed")),
            "Non-resource server should not trigger sensitive file findings"
        );
    }

    // ==================== Sensitive Directory Patterns ====================

    #[test]
    fn detects_ssh_directory_exposure() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/.ssh",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive directory")),
            "Should detect .ssh directory exposure"
        );
    }

    #[test]
    fn detects_aws_directory_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/home/user/.aws"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive directory")),
            "Should detect .aws directory exposure"
        );
    }

    #[test]
    fn detects_docker_directory_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/home/user/.docker"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive directory")),
            "Should detect .docker directory exposure"
        );
    }

    #[test]
    fn detects_node_modules_exposure() {
        let findings = check_resource_server(&["-y", "server-filesystem", "/app/node_modules"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive directory")),
            "Should detect node_modules exposure"
        );
    }

    // ==================== Resource URI Schemes ====================

    #[test]
    fn detects_root_file_uri() {
        let findings = check_resource_server(&["-y", "server-fs", "file:///"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical && f.title.contains("Root filesystem")),
            "Should detect file:/// root access"
        );
    }

    #[test]
    fn detects_wildcard_resource_uri() {
        let findings = check_resource_server(&["-y", "server-fs", "resource://**"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Unrestricted resource")),
            "Should detect resource://** wildcard"
        );
    }

    #[test]
    fn detects_star_resource_uri() {
        let findings = check_resource_server(&["-y", "server-fs", "resource://*"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Unrestricted resource")),
            "Should detect resource://* wildcard"
        );
    }

    // ==================== Missing Access Control ====================

    #[test]
    fn detects_missing_access_control() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/docs",
        ]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Resource server without ACL should be flagged"
        );
    }

    #[test]
    fn allowed_paths_arg_passes_acl_check() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/docs",
            "--allowed-paths",
            "/home/user/docs/public",
        ]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Server with --allowed-paths should pass ACL check"
        );
    }

    #[test]
    fn read_only_arg_passes_acl_check() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/docs",
            "--read-only",
        ]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Server with --read-only should pass ACL check"
        );
    }

    #[test]
    fn sandbox_arg_passes_acl_check() {
        let findings =
            check_resource_server(&["-y", "server-filesystem", "/home/user/data", "--sandbox"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Server with --sandbox should pass ACL check"
        );
    }

    #[test]
    fn acl_env_passes_acl_check() {
        let mut env = HashMap::new();
        env.insert("ALLOWED_PATHS".into(), "/app/public".into());
        let findings = check_server_full(
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem", "/app"],
            env,
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Server with ALLOWED_PATHS env should pass ACL check"
        );
    }

    #[test]
    fn sandbox_env_passes_acl_check() {
        let mut env = HashMap::new();
        env.insert("SANDBOX_DIR".into(), "/app/safe".into());
        let findings = check_server_full("npx", &["-y", "server-filesystem", "/app"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Server with SANDBOX_DIR env should pass ACL check"
        );
    }

    #[test]
    fn non_resource_server_no_acl_finding() {
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-github".into(),
            ]),
            ..Default::default()
        };
        let findings = rule.check("github-server", &server);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Non-resource server should not trigger ACL findings"
        );
    }

    // ==================== Sensitive Resource Path in Env ====================

    #[test]
    fn detects_sensitive_path_in_env() {
        let mut env = HashMap::new();
        env.insert("RESOURCE_PATH".into(), "/app/.git/config".into());
        let findings = check_server_full("npx", &["-y", "server-filesystem", "/app"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource path")),
            "Should detect .git/config in resource path env var"
        );
    }

    #[test]
    fn detects_env_file_in_resource_dir_env() {
        let mut env = HashMap::new();
        env.insert("SERVE_DIR".into(), "/app/.env".into());
        let findings = check_server_full("npx", &["-y", "server-filesystem", "/app"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource path")),
            "Should detect .env in SERVE_DIR env var"
        );
    }

    #[test]
    fn non_resource_env_key_skipped() {
        let mut env = HashMap::new();
        env.insert("LOG_LEVEL".into(), "/tmp/.env".into());
        let findings = check_server_full("npx", &["-y", "server-filesystem", "/app"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Sensitive resource path in environment")),
            "Non-resource env key should not trigger sensitive path finding"
        );
    }

    // ==================== Edge Cases ====================

    #[test]
    fn empty_server_no_findings() {
        let rule = ResourceExposureRule;
        let server = McpServerConfig::default();
        let findings = rule.check("empty", &server);
        assert!(
            findings.is_empty(),
            "Empty server config should produce no findings"
        );
    }

    #[test]
    fn server_with_only_url_no_crash() {
        let rule = ResourceExposureRule;
        let server = McpServerConfig {
            url: Some("https://api.example.com/mcp".into()),
            ..Default::default()
        };
        let findings = rule.check("http-server", &server);
        // Should not crash and should not produce path traversal findings.
        assert!(
            !findings.iter().any(|f| f.title.contains("Path traversal")),
            "Clean URL should not trigger findings"
        );
    }

    #[test]
    fn safe_resource_server_with_acl() {
        let findings = check_resource_server(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/projects/public",
            "--read-only",
            "--allowed-paths",
            "/home/user/projects/public",
        ]);
        // Should only pass — no critical/high findings about access control.
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No access control")),
            "Well-configured resource server should not trigger ACL findings"
        );
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn matches_sensitive_pattern_exact_filename() {
        assert!(matches_sensitive_pattern("/app/.env", ".env"));
        assert!(matches_sensitive_pattern(".env", ".env"));
        assert!(matches_sensitive_pattern(
            "/home/user/.env.production",
            ".env.production"
        ));
    }

    #[test]
    fn matches_sensitive_pattern_directory() {
        assert!(matches_sensitive_pattern("/project/.git/config", ".git/"));
        assert!(matches_sensitive_pattern("/project/.git/HEAD", ".git/"));
    }

    #[test]
    fn matches_sensitive_pattern_with_prefix() {
        assert!(matches_sensitive_pattern("/etc/passwd", "/etc/passwd"));
        assert!(matches_sensitive_pattern(
            "/data/credentials.json",
            "credentials.json"
        ));
    }

    #[test]
    fn no_false_positive_on_substring() {
        // "notenv" should not match ".env"
        assert!(!matches_sensitive_pattern("/app/notenv", ".env"));
        // "my_credentials.json.bak" could match (suffix), but that's acceptable.
    }

    #[test]
    fn is_resource_server_detects_filesystem_packages() {
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-filesystem".into(),
                "/tmp".into(),
            ]),
            ..Default::default()
        };
        assert!(is_resource_server(&server));
    }

    #[test]
    fn is_resource_server_rejects_non_resource_server() {
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-github".into(),
            ]),
            ..Default::default()
        };
        assert!(!is_resource_server(&server));
    }
}
