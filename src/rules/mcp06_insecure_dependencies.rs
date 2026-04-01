//! MCP-06: Insecure Dependencies
//!
//! Detects MCP servers using unpinned, deprecated, or known-vulnerable packages.
//! Checks npm, pip, and other package managers for version pinning and
//! known-bad packages.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Known deprecated or vulnerable MCP-related packages.
const DEPRECATED_PACKAGES: &[(&str, &str)] = &[
    (
        "mcp-server-fetch",
        "Use @modelcontextprotocol/server-fetch instead",
    ),
    (
        "mcp-server-filesystem",
        "Use @modelcontextprotocol/server-filesystem instead",
    ),
    (
        "mcp-server-github",
        "Use @modelcontextprotocol/server-github instead",
    ),
    (
        "mcp-server-postgres",
        "Use @modelcontextprotocol/server-postgres instead",
    ),
    (
        "mcp-server-sqlite",
        "Use @modelcontextprotocol/server-sqlite instead",
    ),
    (
        "mcp-server-brave-search",
        "Use @modelcontextprotocol/server-brave-search instead",
    ),
    (
        "mcp-server-puppeteer",
        "Use @modelcontextprotocol/server-puppeteer instead",
    ),
    (
        "mcp-server-memory",
        "Use @modelcontextprotocol/server-memory instead",
    ),
    (
        "mcp-server-everything",
        "Use @modelcontextprotocol/server-everything instead",
    ),
    ("node-ipc", "Known malicious package (protestware incident)"),
    (
        "event-stream",
        "Known compromised package (supply chain attack)",
    ),
    ("ua-parser-js", "Had malicious versions published"),
    ("coa", "Had malicious versions published"),
    ("rc", "Had malicious versions published"),
];

/// Package runners that install packages at runtime.
const PACKAGE_RUNNERS: &[&str] = &["npx", "bunx"];

/// pip-style package installers.
const PIP_RUNNERS: &[&str] = &["pip", "pip3", "uvx", "pipx"];

pub struct InsecureDependenciesRule;

impl super::Rule for InsecureDependenciesRule {
    fn id(&self) -> &'static str {
        "MCP-06"
    }

    fn name(&self) -> &'static str {
        "Insecure Dependencies"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers using unpinned versions, deprecated packages, or \
         packages with known vulnerabilities."
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-06"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let cmd = server.command.as_deref().unwrap_or("");
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_str = server.args_string();

        let is_npm_runner = PACKAGE_RUNNERS.contains(&cmd);
        let is_pip_runner = PIP_RUNNERS.contains(&cmd);

        // Check for deprecated / known-vulnerable packages.
        for (pkg, advice) in DEPRECATED_PACKAGES {
            if contains_package_name(&args_str, pkg) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Deprecated/vulnerable package in server '{}'", server_name),
                    description: format!(
                        "Server uses package '{}' which is deprecated or has known \
                         vulnerabilities. {}",
                        pkg, advice
                    ),
                });
            }
        }

        // Check for unpinned npm packages.
        if is_npm_runner {
            let package_arg = args.iter().find(|a| {
                !a.starts_with('-')
                    && *a != "-y"
                    && *a != "--yes"
                    && !a.starts_with("--")
                    // skip path args that look like file paths
                    && !a.starts_with('/')
                    && !a.starts_with('.')
                    && !a.starts_with('~')
            });

            if let Some(pkg) = package_arg {
                if !has_npm_version(pkg) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!("Unpinned npm package in server '{}'", server_name),
                        description: format!(
                            "Package '{}' does not specify a version (e.g., 'pkg@1.2.3'). \
                             Without version pinning, a compromised update could be \
                             automatically installed. Pin to a known-good version.",
                            pkg
                        ),
                    });
                }
            }

            // Check for use of -y/--yes flag (auto-install without confirmation).
            if args.iter().any(|a| a == "-y" || a == "--yes") {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Low,
                    title: format!("Auto-install flag in server '{}'", server_name),
                    description: format!(
                        "Server '{}' uses the -y/--yes flag which automatically \
                         installs packages without confirmation. This bypasses the \
                         opportunity to review what will be installed.",
                        server_name
                    ),
                });
            }
        }

        // Check for unpinned pip packages.
        if is_pip_runner {
            for arg in args {
                // Skip flags and known non-package args.
                if arg.starts_with('-') || arg.starts_with('/') || arg.starts_with('.') {
                    continue;
                }
                // Skip known pip subcommands.
                if arg == "install" || arg == "run" {
                    continue;
                }
                // pip packages are pinned with == or >=.
                if !arg.contains("==") && !arg.contains(">=") && !arg.contains('@') {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!("Unpinned Python package in server '{}'", server_name),
                        description: format!(
                            "Package '{}' does not specify a version constraint. \
                             Pin to a specific version (e.g., 'pkg==1.2.3') to prevent \
                             unexpected updates.",
                            arg
                        ),
                    });
                }
            }
        }

        // Check for risky installation flags.
        let risky_flags = ["--pre", "--force-reinstall", "--no-deps", "--no-verify"];
        for flag in &risky_flags {
            if args.iter().any(|a| a == flag) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::Medium,
                    title: format!("Risky package install flag in server '{}'", server_name),
                    description: format!(
                        "Server uses the '{}' flag which bypasses safety checks \
                         during package installation. Remove this flag unless strictly \
                         necessary.",
                        flag
                    ),
                });
            }
        }

        findings
    }
}

/// Check if an args string contains a package name as a standalone token,
/// not merely as a substring of a longer word.
///
/// A match requires that the package name is preceded by a word boundary
/// (start of string, whitespace, or `/`) and followed by a word boundary
/// (end of string, whitespace, `@`, or `/`). This prevents false positives
/// like matching `"rc"` inside `"search"` or `"server-brave-search"`.
fn contains_package_name(haystack: &str, pkg: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(pkg) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + pkg.len();

        // Check preceding character: must be start of string, whitespace, or '/'
        let valid_start = abs_pos == 0 || {
            let prev = haystack.as_bytes()[abs_pos - 1];
            prev == b' ' || prev == b'/' || prev == b'\t' || prev == b'\n'
        };

        // Check following character: must be end of string, whitespace, '@', or '/'
        let valid_end = end_pos >= haystack.len() || {
            let next = haystack.as_bytes()[end_pos];
            next == b' ' || next == b'@' || next == b'/' || next == b'\t' || next == b'\n'
        };

        if valid_start && valid_end {
            return true;
        }

        start = abs_pos + 1;
    }
    false
}

/// Check if an npm package string includes a version specifier.
fn has_npm_version(pkg: &str) -> bool {
    // Scoped packages: @scope/pkg@version
    if pkg.starts_with('@') {
        // Must have at least 2 '@' signs: @scope/pkg@version
        pkg.chars().filter(|c| *c == '@').count() >= 2
    } else {
        // Unscoped: pkg@version
        pkg.contains('@')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn check_cmd(cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = InsecureDependenciesRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    #[test]
    fn detects_deprecated_package() {
        let findings = check_cmd("npx", &["-y", "mcp-server-fetch"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Deprecated")),
            "Should detect deprecated package"
        );
    }

    #[test]
    fn detects_unpinned_npm() {
        let findings = check_cmd("npx", &["-y", "@modelcontextprotocol/server-filesystem"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Unpinned npm")),
            "Should detect unpinned npm package"
        );
    }

    #[test]
    fn pinned_npm_passes() {
        let findings = check_cmd(
            "npx",
            &[
                "-y",
                "@modelcontextprotocol/server-filesystem@1.0.0",
                "/tmp",
            ],
        );
        assert!(
            !findings.iter().any(|f| f.title.contains("Unpinned npm")),
            "Pinned package should not trigger unpinned warning"
        );
    }

    #[test]
    fn detects_unpinned_pip() {
        let findings = check_cmd("pip", &["install", "mcp-server-custom"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Unpinned Python")),
            "Should detect unpinned pip package"
        );
    }

    #[test]
    fn pinned_pip_passes() {
        let findings = check_cmd("pip", &["install", "mcp-server-custom==1.0.0"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("Unpinned Python")),
            "Pinned pip package should pass"
        );
    }

    #[test]
    fn detects_risky_flags() {
        let findings = check_cmd("pip", &["install", "--pre", "mcp-server"]);
        assert!(
            findings.iter().any(|f| f.title.contains("Risky")),
            "Should detect risky install flags"
        );
    }

    #[test]
    fn has_npm_version_check() {
        assert!(has_npm_version("pkg@1.0.0"));
        assert!(has_npm_version("@scope/pkg@1.0.0"));
        assert!(!has_npm_version("pkg"));
        assert!(!has_npm_version("@scope/pkg"));
    }

    #[test]
    fn rule_metadata() {
        let rule = InsecureDependenciesRule;
        assert_eq!(rule.id(), "MCP-06");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-06");
        assert_eq!(rule.default_severity(), Severity::Medium);
    }

    // ── contains_package_name tests ─────────────────────────────────────

    #[test]
    fn contains_package_exact_match() {
        assert!(contains_package_name("rc", "rc"));
        assert!(contains_package_name("rc@1.0.0", "rc"));
        assert!(contains_package_name("-y rc", "rc"));
        assert!(contains_package_name(
            "mcp-server-filesystem",
            "mcp-server-filesystem"
        ));
    }

    #[test]
    fn contains_package_no_false_positive_substring() {
        // "rc" should NOT match inside "search", "server-brave-search", etc.
        assert!(!contains_package_name(
            "@modelcontextprotocol/server-brave-search@1.0.0",
            "rc"
        ));
        assert!(!contains_package_name("source", "rc"));
        assert!(!contains_package_name("archive", "rc"));
    }

    #[test]
    fn contains_package_scoped_package() {
        assert!(contains_package_name(
            "-y mcp-server-fetch",
            "mcp-server-fetch"
        ));
        assert!(!contains_package_name(
            "-y @modelcontextprotocol/server-fetch@1.0.0",
            "mcp-server-fetch"
        ));
    }

    #[test]
    fn no_false_positive_for_official_brave_search() {
        // Regression: brave-search should not trigger deprecated "rc" detection
        let findings = check_cmd(
            "npx",
            &["-y", "@modelcontextprotocol/server-brave-search@1.0.0"],
        );
        assert!(
            !findings.iter().any(|f| f.description.contains("'rc'")),
            "Official brave-search package should not match deprecated 'rc' package"
        );
    }
}
