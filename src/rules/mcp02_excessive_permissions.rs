//! MCP-02: Excessive Permissions
//!
//! Detects MCP servers with overly broad file system access or permissions.
//! Checks for root-level paths, sensitive directories, and wildcard patterns.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Root-level paths that grant excessive access.
const DANGEROUS_PATHS: &[&str] = &[
    "/", "/home", "/Users", "/etc", "/var", "/usr", "/root", "/opt", "C:\\", "C:/", "D:\\", "D:/",
];

/// Sensitive directories that should not be exposed.
const SENSITIVE_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".gpg",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".docker",
    ".config",
    ".local/share",
    ".password-store",
    ".vault-token",
    "id_rsa",
    "id_ed25519",
    ".env",
];

pub struct ExcessivePermissionsRule;

impl super::Rule for ExcessivePermissionsRule {
    fn id(&self) -> &'static str {
        "MCP-02"
    }

    fn name(&self) -> &'static str {
        "Excessive Permissions"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers configured with overly broad file system access, \
         including root-level paths and sensitive directories."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-02"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_str = server.args_string();

        // Check each argument for dangerous paths.
        for arg in args {
            let normalized = arg.replace('\\', "/");

            // Check for root-level / system-wide paths.
            for dangerous in DANGEROUS_PATHS {
                let norm_dangerous = dangerous.replace('\\', "/");
                if normalized == norm_dangerous
                    || (normalized.starts_with(&norm_dangerous)
                        && normalized.len() == norm_dangerous.len() + 1
                        && normalized.ends_with('/'))
                {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Critical,
                        title: format!("Root-level path access in server '{}'", server_name),
                        description: format!(
                            "Server has access to '{}' which grants overly broad \
                             file system permissions. Restrict to specific subdirectories.",
                            arg
                        ),
                    });
                }
            }

            // Check for sensitive directories.
            for sensitive in SENSITIVE_DIRS {
                if normalized.contains(sensitive) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Critical,
                        title: format!("Sensitive directory access in server '{}'", server_name),
                        description: format!(
                            "Server has access to path containing '{}' which may \
                             expose sensitive data (keys, credentials, configs).",
                            sensitive
                        ),
                    });
                }
            }
        }

        // Check for wildcard patterns in arguments.
        if args_str.contains("**") || args_str.contains("*.*") {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::High,
                title: format!("Wildcard path pattern in server '{}'", server_name),
                description: "Server arguments contain wildcard patterns that may \
                    grant unintended broad access. Use explicit paths instead."
                    .to_string(),
            });
        }

        // Check for home directory expansion (~).
        if args.iter().any(|a| a == "~" || a == "~/") {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::High,
                title: format!("Full home directory access in server '{}'", server_name),
                description: "Server has access to the entire home directory. \
                    Restrict to specific subdirectories (e.g., ~/Documents/project)."
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

    fn check(args: &[&str]) -> Vec<ScanFinding> {
        let rule = ExcessivePermissionsRule;
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    #[test]
    fn detects_root_path() {
        let findings = check(&["-y", "@modelcontextprotocol/server-filesystem", "/"]);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
        assert!(findings.iter().any(|f| f.title.contains("Root-level")));
    }

    #[test]
    fn detects_home_dir() {
        let findings = check(&["-y", "@modelcontextprotocol/server-filesystem", "/home"]);
        assert!(findings.iter().any(|f| f.title.contains("Root-level")));
    }

    #[test]
    fn detects_ssh_directory() {
        let findings = check(&["-y", "pkg", "/home/user/.ssh"]);
        assert!(findings.iter().any(|f| f.title.contains("Sensitive")));
    }

    #[test]
    fn detects_aws_directory() {
        let findings = check(&["-y", "pkg", "/home/user/.aws"]);
        assert!(findings.iter().any(|f| f.title.contains("Sensitive")));
    }

    #[test]
    fn detects_wildcard() {
        let findings = check(&["-y", "pkg", "**"]);
        assert!(findings.iter().any(|f| f.title.contains("Wildcard")));
    }

    #[test]
    fn detects_home_tilde() {
        let findings = check(&["-y", "pkg", "~"]);
        assert!(findings.iter().any(|f| f.title.contains("home directory")));
    }

    #[test]
    fn safe_path_passes() {
        let findings = check(&[
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/home/user/projects/my-app",
        ]);
        assert!(
            !findings.iter().any(|f| f.severity == Severity::Critical),
            "Specific subdirectory should not trigger critical finding"
        );
    }

    #[test]
    fn windows_root_detected() {
        let findings = check(&["-y", "pkg", "C:\\"]);
        assert!(findings.iter().any(|f| f.title.contains("Root-level")));
    }

    #[test]
    fn rule_metadata() {
        let rule = ExcessivePermissionsRule;
        assert_eq!(rule.id(), "MCP-02");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-02");
    }
}
