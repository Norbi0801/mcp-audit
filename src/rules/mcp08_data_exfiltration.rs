//! MCP-08: Data Exfiltration
//!
//! Detects MCP server configurations that may facilitate data exfiltration
//! through access to sensitive files, databases, and network services.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Files that contain sensitive system or user data.
const SENSITIVE_FILES: &[(&str, &str)] = &[
    ("/etc/passwd", "system user database"),
    ("/etc/shadow", "system password hashes"),
    ("/etc/hosts", "network host mappings"),
    ("/etc/sudoers", "sudo privilege configuration"),
    (".env", "environment variables (may contain secrets)"),
    (".env.local", "local environment variables"),
    (".env.production", "production environment variables"),
    (".bashrc", "shell configuration (may contain secrets)"),
    (".bash_history", "command history (may contain secrets)"),
    (".zsh_history", "command history"),
    (".netrc", "network authentication credentials"),
    (".pgpass", "PostgreSQL password file"),
    (".my.cnf", "MySQL configuration (may contain passwords)"),
    (".npmrc", "npm configuration (may contain auth tokens)"),
    (".pypirc", "PyPI credentials"),
    (".docker/config.json", "Docker registry credentials"),
    ("credentials.json", "application credentials"),
    ("service-account.json", "service account credentials"),
    ("id_rsa", "SSH private key"),
    ("id_ed25519", "SSH private key"),
    ("known_hosts", "SSH known hosts"),
];

/// Sensitive directories that may contain secrets or PII.
const SENSITIVE_DIRS: &[(&str, &str)] = &[
    (".ssh", "SSH keys and configuration"),
    (".gnupg", "GPG keys and keyrings"),
    (".aws", "AWS credentials and configuration"),
    (".azure", "Azure credentials"),
    (".gcloud", "Google Cloud credentials"),
    (".kube", "Kubernetes configuration"),
    (".config/gcloud", "Google Cloud configuration"),
    (".vault-token", "HashiCorp Vault token"),
    (".password-store", "pass password store"),
    ("secrets", "secrets directory"),
];

/// Database connection string patterns.
const DB_CONNECTION_PATTERNS: &[(&str, &str)] = &[
    ("postgres://", "PostgreSQL"),
    ("postgresql://", "PostgreSQL"),
    ("mysql://", "MySQL"),
    ("mongodb://", "MongoDB"),
    ("mongodb+srv://", "MongoDB Atlas"),
    ("redis://", "Redis"),
    ("rediss://", "Redis (TLS)"),
    ("amqp://", "RabbitMQ"),
    ("mssql://", "SQL Server"),
    ("sqlite:///", "SQLite (absolute path)"),
];

pub struct DataExfiltrationRule;

impl super::Rule for DataExfiltrationRule {
    fn id(&self) -> &'static str {
        "MCP-08"
    }

    fn name(&self) -> &'static str {
        "Data Exfiltration"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers with access to sensitive files, databases, \
         or network services that could facilitate data exfiltration."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-08"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_str = server.args_string();

        // Check arguments for access to sensitive files.
        for (file, description) in SENSITIVE_FILES {
            if args.iter().any(|a| a.contains(file)) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Critical,
                    title: format!("Access to sensitive file in server '{}'", server_name),
                    description: format!(
                        "Server has access to '{}' ({}). This file may contain \
                         sensitive data that could be exfiltrated through the MCP \
                         protocol. Remove access to this file.",
                        file, description
                    ),
                });
            }
        }

        // Check arguments for access to sensitive directories.
        for (dir, description) in SENSITIVE_DIRS {
            if args.iter().any(|a| {
                let normalized = a.replace('\\', "/");
                normalized.contains(dir)
            }) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Access to sensitive directory in server '{}'", server_name),
                    description: format!(
                        "Server has access to path containing '{}' ({}). This \
                         directory may contain credentials and keys.",
                        dir, description
                    ),
                });
            }
        }

        // Check environment variables for database connection strings.
        if let Some(env) = &server.env {
            for (key, value) in env {
                for (pattern, db_type) in DB_CONNECTION_PATTERNS {
                    if value.contains(pattern) {
                        // Check if credentials are embedded in the URL.
                        let has_creds = value.contains('@') && {
                            // pattern://user:pass@host
                            let after_scheme = value.split("://").nth(1).unwrap_or("");
                            after_scheme.contains('@') && after_scheme.contains(':')
                        };

                        let severity = if has_creds {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity,
                            title: format!(
                                "{} connection string in server '{}'",
                                db_type, server_name
                            ),
                            description: format!(
                                "Environment variable '{}' contains a {} connection string{}. \
                                 Database access through MCP servers can enable data \
                                 exfiltration. Use least-privilege database users and \
                                 restrict accessible tables.",
                                key,
                                db_type,
                                if has_creds {
                                    " with embedded credentials"
                                } else {
                                    ""
                                }
                            ),
                        });
                        break;
                    }
                }
            }
        }

        // Check for database servers without access restrictions.
        if is_database_server(&args_str, server) {
            let has_restrictions = args.iter().any(|a| {
                a.contains("--table")
                    || a.contains("--schema")
                    || a.contains("--read-only")
                    || a.contains("--readonly")
                    || a.contains("--allowed-tables")
                    || a.contains("--deny-write")
            });

            if !has_restrictions {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Medium,
                    title: format!("Unrestricted database access in server '{}'", server_name),
                    description: "Database MCP server does not have explicit table or \
                         schema restrictions. This may allow access to all database \
                         tables. Use --table, --schema, or --read-only flags to \
                         restrict access."
                        .to_string(),
                });
            }
        }

        findings
    }
}

/// Check if the server appears to be a database MCP server.
fn is_database_server(args_str: &str, server: &McpServerConfig) -> bool {
    let db_indicators = [
        "server-postgres",
        "server-sqlite",
        "server-mysql",
        "server-mongodb",
        "mcp-postgres",
        "mcp-sqlite",
        "mcp-mysql",
        "mcp-mongodb",
    ];

    let cmd_and_args = format!("{} {}", server.command.as_deref().unwrap_or(""), args_str);

    db_indicators.iter().any(|ind| cmd_and_args.contains(ind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    fn check_args(args: &[&str]) -> Vec<ScanFinding> {
        let rule = DataExfiltrationRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_env(env: Vec<(&str, &str)>) -> Vec<ScanFinding> {
        let rule = DataExfiltrationRule;
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

    #[test]
    fn detects_sensitive_file_access() {
        let findings = check_args(&["-y", "pkg", "/etc/passwd"]);
        assert!(
            findings.iter().any(|f| f.title.contains("sensitive file")),
            "Should detect access to /etc/passwd"
        );
    }

    #[test]
    fn detects_ssh_directory_access() {
        let findings = check_args(&["-y", "pkg", "/home/user/.ssh"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("sensitive directory")),
            "Should detect access to .ssh directory"
        );
    }

    #[test]
    fn detects_env_file_access() {
        let findings = check_args(&["-y", "pkg", "/app/.env"]);
        assert!(
            findings.iter().any(|f| f.title.contains("sensitive file")),
            "Should detect access to .env file"
        );
    }

    #[test]
    fn detects_database_connection_string() {
        let findings = check_env(vec![(
            "DATABASE_URL",
            "postgres://user:pass@localhost:5432/mydb",
        )]);
        assert!(
            findings.iter().any(|f| f.title.contains("PostgreSQL")),
            "Should detect PostgreSQL connection string"
        );
        // Should also detect embedded credentials.
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Connection string with credentials should be critical"
        );
    }

    #[test]
    fn detects_db_connection_without_creds() {
        let findings = check_env(vec![("DATABASE_URL", "postgres://localhost:5432/mydb")]);
        assert!(
            findings.iter().any(|f| f.title.contains("PostgreSQL")),
            "Should still flag connection string without creds"
        );
    }

    #[test]
    fn detects_unrestricted_db_server() {
        let rule = DataExfiltrationRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec![
                "-y".into(),
                "@modelcontextprotocol/server-postgres".into(),
            ]),
            env: Some(HashMap::from([(
                "DATABASE_URL".into(),
                "postgres://localhost/db".into(),
            )])),
            ..Default::default()
        };
        let findings = rule.check("postgres", &server);
        assert!(
            findings.iter().any(|f| f.title.contains("Unrestricted")),
            "Should detect unrestricted database access"
        );
    }

    #[test]
    fn safe_paths_pass() {
        let findings = check_args(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/projects/myapp",
        ]);
        assert!(
            !findings.iter().any(|f| f.severity == Severity::Critical),
            "Normal project path should not trigger critical findings"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = DataExfiltrationRule;
        assert_eq!(rule.id(), "MCP-08");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-08");
        assert_eq!(rule.default_severity(), Severity::High);
    }
}
