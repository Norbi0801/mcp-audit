//! MCP-01: Tool Poisoning
//!
//! Detects MCP servers from unverified or potentially malicious sources.
//! Checks for typosquatting patterns, suspicious package names, and
//! servers installed from untrusted registries.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Known legitimate MCP server packages (npm scope + name).
const TRUSTED_SCOPES: &[&str] = &[
    "@modelcontextprotocol/",
    "@anthropic-ai/",
    "@cloudflare/",
    "@aws/",
    "@google-cloud/",
    "@azure/",
    "@vercel/",
    "@supabase/",
];

/// Known legitimate MCP server package names.
const TRUSTED_PACKAGES: &[&str] = &["mcp-server-", "@modelcontextprotocol/server-"];

/// Suspicious patterns that may indicate typosquatting.
const TYPOSQUAT_PATTERNS: &[(&str, &str)] = &[
    ("modeicontextprotocol", "modelcontextprotocol"),
    ("modelcontextprotoco1", "modelcontextprotocol"),
    ("mode1contextprotocol", "modelcontextprotocol"),
    ("modelccontextprotocol", "modelcontextprotocol"),
    ("anthropic-ai-", "@anthropic-ai/"),
    ("mcp_server", "mcp-server"),
];

pub struct ToolPoisoningRule;

impl super::Rule for ToolPoisoningRule {
    fn id(&self) -> &'static str {
        "MCP-01"
    }

    fn name(&self) -> &'static str {
        "Tool Poisoning"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers from unverified or potentially malicious sources, \
         including typosquatting and untrusted package registries."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-01"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        let args_str = server.args_string();
        let cmd = server.command.as_deref().unwrap_or("");

        // Check for typosquatting in package names.
        for (typo, legitimate) in TYPOSQUAT_PATTERNS {
            if args_str.contains(typo) || server_name.contains(typo) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Critical,
                    title: format!("Possible typosquatting in server '{}'", server_name),
                    description: format!(
                        "Package name contains '{}' which is similar to '{}'. \
                         This may be a typosquatting attack.",
                        typo, legitimate
                    ),
                });
            }
        }

        // Check for packages from unknown sources (not in trusted scopes).
        if cmd == "npx" || cmd == "npm" {
            let has_trusted = TRUSTED_SCOPES.iter().any(|scope| args_str.contains(scope))
                || TRUSTED_PACKAGES.iter().any(|pkg| args_str.contains(pkg));

            if !has_trusted && !args_str.is_empty() {
                // Extract the package name from args.
                let package = extract_npm_package(&args_str);
                if let Some(pkg) = package {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!("Unverified package source in server '{}'", server_name),
                        description: format!(
                            "Package '{}' is not from a recognized MCP package scope. \
                             Verify the package is legitimate before use.",
                            pkg
                        ),
                    });
                }
            }
        }

        // Check for installation from Git URLs (potential supply chain risk).
        if args_str.contains("github.com")
            || args_str.contains("gitlab.com")
            || args_str.contains("git+")
        {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!("Server '{}' installed from Git repository", server_name),
                description: "Installing packages directly from Git repositories bypasses \
                    registry security checks. Pin to a specific commit hash."
                    .to_string(),
            });
        }

        findings
    }
}

/// Extract the npm package name from an args string.
fn extract_npm_package(args: &str) -> Option<String> {
    let parts: Vec<&str> = args.split_whitespace().collect();
    for (i, part) in parts.iter().enumerate() {
        // Skip flags like -y, --yes, --package.
        if part.starts_with('-') {
            continue;
        }
        // If previous was --package, this is the package name.
        if i > 0 && (parts[i - 1] == "--package" || parts[i - 1] == "-p") {
            return Some(part.to_string());
        }
        // First non-flag argument after -y is likely the package.
        if !part.starts_with('-') && (i == 0 || parts[i - 1] == "-y" || parts[i - 1] == "--yes") {
            return Some(part.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn check_server(name: &str, cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = ToolPoisoningRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    #[test]
    fn detects_typosquatting() {
        let findings = check_server("fake", "npx", &["-y", "@modeicontextprotocol/server-fs"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect typosquatting as critical"
        );
    }

    #[test]
    fn trusted_scope_passes() {
        let findings = check_server(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        );
        assert!(
            !findings.iter().any(|f| f.title.contains("Unverified")),
            "Trusted scope should not trigger unverified warning"
        );
    }

    #[test]
    fn unknown_package_flagged() {
        let findings = check_server("random", "npx", &["-y", "some-random-mcp-thing"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Unverified")),
            "Unknown package should trigger unverified warning"
        );
    }

    #[test]
    fn git_install_flagged() {
        let findings = check_server("git-server", "npx", &["-y", "github.com/user/mcp-server"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Git repository")),
            "Git install should trigger warning"
        );
    }

    #[test]
    fn non_npx_not_checked_for_packages() {
        let findings = check_server("python-server", "python", &["-m", "my_mcp_server"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("Unverified")),
            "Non-npx commands shouldn't get npm package checks"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = ToolPoisoningRule;
        assert_eq!(rule.id(), "MCP-01");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-01");
        assert_eq!(rule.default_severity(), Severity::High);
    }
}
