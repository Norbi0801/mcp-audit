//! MCP-05: Server Spoofing
//!
//! Detects MCP servers that may be impersonating legitimate services or are
//! configured to connect to suspicious endpoints that could intercept or
//! manipulate tool interactions.

use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

/// Well-known legitimate MCP server names that attackers might spoof.
const SPOOFABLE_NAMES: &[&str] = &[
    "filesystem",
    "github",
    "postgres",
    "sqlite",
    "slack",
    "google-drive",
    "brave-search",
    "puppeteer",
    "memory",
    "fetch",
    "everything",
];

/// Suspicious URL patterns that may indicate server spoofing.
const SUSPICIOUS_URL_PATTERNS: &[&str] = &[
    "ngrok.io",
    "ngrok-free.app",
    "localtunnel.me",
    "serveo.net",
    "localhost.run",
    "loca.lt",
    "telebit.cloud",
    "tunnelto.dev",
    ".trycloudflare.com",
    "requestbin.com",
    "hookbin.com",
    "webhook.site",
    "pipedream.net",
    "beeceptor.com",
    "requestcatcher.com",
];

/// Domains that are commonly typosquatted.
const OFFICIAL_DOMAINS: &[(&str, &[&str])] = &[
    (
        "anthropic.com",
        &[
            "anthropic.io",
            "anthroplc.com",
            "anthr0pic.com",
            "anthrop1c.com",
        ],
    ),
    ("openai.com", &["openal.com", "0penai.com", "opena1.com"]),
    (
        "modelcontextprotocol.io",
        &["modelcontextprotocol.com", "modeicontextprotocol.io"],
    ),
];

pub struct ServerSpoofingRule;

impl super::Rule for ServerSpoofingRule {
    fn id(&self) -> &'static str {
        "MCP-05"
    }

    fn name(&self) -> &'static str {
        "Server Spoofing"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers that may be impersonating legitimate services or \
         connecting to suspicious endpoints designed to intercept tool requests."
    }

    fn default_severity(&self) -> Severity {
        Severity::High
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-05"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let name_lower = server_name.to_lowercase();

        // Check if the server name matches a well-known service but uses a
        // non-standard command or source.
        if SPOOFABLE_NAMES.contains(&name_lower.as_str()) {
            if let Some(cmd) = &server.command {
                let args_str = server.args_string();
                let full_cmd = format!("{} {}", cmd, args_str);

                // A well-known name should typically use @modelcontextprotocol/ packages.
                let uses_official = full_cmd.contains("@modelcontextprotocol/")
                    || full_cmd.contains("@anthropic-ai/");

                if !uses_official {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Medium,
                        title: format!(
                            "Server '{}' uses well-known name with non-official package",
                            server_name
                        ),
                        description: format!(
                            "Server '{}' has a name matching a well-known MCP service \
                             but does not use the official @modelcontextprotocol/ package. \
                             This could indicate server spoofing. Verify the package source.",
                            server_name
                        ),
                    });
                }
            }
        }

        // Check URL-based servers for suspicious endpoints.
        if let Some(url) = &server.url {
            let url_lower = url.to_lowercase();

            // Check for tunnel/proxy services.
            for pattern in SUSPICIOUS_URL_PATTERNS {
                if url_lower.contains(pattern) {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!("Server '{}' connects to tunnel/proxy service", server_name),
                        description: format!(
                            "Server URL contains '{}' which is a tunnel or proxy service. \
                             These services can intercept and modify traffic. Use direct \
                             connections to verified endpoints instead.",
                            pattern
                        ),
                    });
                    break;
                }
            }

            // Check for HTTP (non-TLS) connections.
            if url_lower.starts_with("http://")
                && !url_lower.contains("localhost")
                && !url_lower.contains("127.0.0.1")
            {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!("Server '{}' uses unencrypted HTTP connection", server_name),
                    description: format!(
                        "Server URL '{}' uses plain HTTP instead of HTTPS. \
                         This allows man-in-the-middle attacks that could intercept \
                         or modify MCP traffic. Use HTTPS for all remote connections.",
                        url
                    ),
                });
            }

            // Check for typosquatted domains.
            for (legitimate, typos) in OFFICIAL_DOMAINS {
                for typo in *typos {
                    if url_lower.contains(typo) {
                        findings.push(ScanFinding {
                            rule_id: self.id().to_string(),
                            severity: Severity::Critical,
                            title: format!(
                                "Possible domain typosquatting in server '{}'",
                                server_name
                            ),
                            description: format!(
                                "Server URL contains '{}' which is similar to '{}'. \
                                 This may be a typosquatting attack designed to redirect \
                                 MCP traffic to a malicious server.",
                                typo, legitimate
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn check_url(name: &str, url: &str) -> Vec<ScanFinding> {
        let rule = ServerSpoofingRule;
        let server = McpServerConfig {
            url: Some(url.into()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_cmd(name: &str, cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = ServerSpoofingRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    #[test]
    fn detects_ngrok_tunnel() {
        let findings = check_url("api", "https://abc123.ngrok-free.app/mcp");
        assert!(
            findings.iter().any(|f| f.title.contains("tunnel")),
            "Should detect ngrok tunnel service"
        );
    }

    #[test]
    fn detects_unencrypted_http() {
        let findings = check_url("remote", "http://api.example.com/mcp");
        assert!(
            findings.iter().any(|f| f.title.contains("unencrypted")),
            "Should detect unencrypted HTTP"
        );
    }

    #[test]
    fn allows_http_localhost() {
        let findings = check_url("local", "http://localhost:8080/mcp");
        assert!(
            !findings.iter().any(|f| f.title.contains("unencrypted")),
            "Should allow HTTP for localhost"
        );
    }

    #[test]
    fn detects_domain_typosquat() {
        let findings = check_url("remote", "https://api.anthropic.io/mcp");
        assert!(
            findings.iter().any(|f| f.title.contains("typosquatting")),
            "Should detect domain typosquatting"
        );
    }

    #[test]
    fn detects_spoofed_name_with_custom_package() {
        let findings = check_cmd("filesystem", "npx", &["-y", "evil-filesystem-server"]);
        assert!(
            findings.iter().any(|f| f.title.contains("well-known")),
            "Should detect well-known name with non-official package"
        );
    }

    #[test]
    fn official_package_with_known_name_passes() {
        let findings = check_cmd(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        );
        assert!(
            !findings.iter().any(|f| f.title.contains("well-known")),
            "Official package with known name should pass"
        );
    }

    #[test]
    fn rule_metadata() {
        let rule = ServerSpoofingRule;
        assert_eq!(rule.id(), "MCP-05");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-05");
        assert_eq!(rule.default_severity(), Severity::High);
    }
}
