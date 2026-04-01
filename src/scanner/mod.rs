//! MCP server scanner — discovers scannable MCP servers from monitor events
//! and produces structured scan targets for vulnerability assessment.

use crate::monitors::{MonitorEvent, MonitorSource, Severity};

/// A discovered MCP server ready to be scanned.
#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    pub name: String,
    pub url: String,
    pub source_event: MonitorEvent,
    pub server_type: ServerType,
}

/// Classification of how the MCP server was found / how to scan it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    /// MCP server config JSON (claude_desktop_config.json, etc.)
    StdioConfig,
    /// HTTP-based MCP server endpoint
    HttpEndpoint,
    /// GitHub repo containing MCP server code
    Repository,
}

impl std::fmt::Display for ServerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdioConfig => write!(f, "Stdio Config"),
            Self::HttpEndpoint => write!(f, "HTTP Endpoint"),
            Self::Repository => write!(f, "Repository"),
        }
    }
}

/// The result of scanning a single discovered server.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub server: DiscoveredServer,
    pub findings: Vec<ScanFinding>,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
}

impl ScanResult {
    /// Returns true if any finding has Critical or High severity.
    pub fn has_critical_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical || f.severity == Severity::High)
    }

    /// Count findings grouped by severity.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        use std::collections::HashMap;
        let mut counts: HashMap<Severity, usize> = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.severity).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0));
        sorted
    }
}

/// A single finding from a security scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

/// Extracts scannable servers from monitor events.
///
/// Filters GitHub events that look like MCP server repos, extracts URLs, and
/// classifies them by server type. Non-GitHub events are skipped for now since
/// they represent CVEs, OWASP docs, or adoption signals rather than scannable
/// targets.
pub fn discover_servers(events: &[MonitorEvent]) -> Vec<DiscoveredServer> {
    let mut servers = Vec::new();

    for event in events {
        // CVE events may reference affected packages but are not scannable targets.
        // OWASP and Adoption events are informational.
        if event.source == MonitorSource::GitHub {
            if let Some(server) = discover_from_github(event) {
                servers.push(server);
            }
        }
    }

    servers
}

/// Try to extract a scannable server from a GitHub monitor event.
fn discover_from_github(event: &MonitorEvent) -> Option<DiscoveredServer> {
    // Only consider repository events (not advisories).
    if !event.tags.iter().any(|t| t == "repository") {
        return None;
    }

    // Must have a URL.
    if event.url.is_empty() {
        return None;
    }

    // Classify the server type based on tags, title, and metadata.
    let server_type = classify_server_type(event);

    // Extract a clean name from the URL or title.
    let name = extract_server_name(event);

    Some(DiscoveredServer {
        name,
        url: event.url.clone(),
        source_event: event.clone(),
        server_type,
    })
}

/// Classify a GitHub repo event into a ServerType.
fn classify_server_type(event: &MonitorEvent) -> ServerType {
    let title_lower = event.title.to_lowercase();
    let desc_lower = event.description.to_lowercase();
    let combined = format!("{} {}", title_lower, desc_lower);

    // Check tags and content for HTTP server indicators.
    let http_indicators = ["http", "rest", "api", "endpoint", "sse", "streamable"];
    let is_http = http_indicators.iter().any(|kw| combined.contains(kw))
        || event.tags.iter().any(|t| {
            let t_lower = t.to_lowercase();
            http_indicators.iter().any(|kw| t_lower.contains(kw))
        });

    if is_http {
        return ServerType::HttpEndpoint;
    }

    // Check for stdio/config indicators.
    let stdio_indicators = ["stdio", "config", "claude_desktop", "desktop_config"];
    let is_stdio = stdio_indicators.iter().any(|kw| combined.contains(kw))
        || event.tags.iter().any(|t| {
            let t_lower = t.to_lowercase();
            stdio_indicators.iter().any(|kw| t_lower.contains(kw))
        });

    if is_stdio {
        return ServerType::StdioConfig;
    }

    // Default: treat as a repository to scan source code.
    ServerType::Repository
}

/// Extract a clean server name from a GitHub event.
fn extract_server_name(event: &MonitorEvent) -> String {
    // Try to extract "owner/repo" from the URL.
    if let Some(path) = event.url.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 2 {
            return format!("{}/{}", parts[0], parts[1]);
        }
    }

    // Fall back to title, stripping the "New MCP repo: " prefix if present.
    event
        .title
        .strip_prefix("New MCP repo: ")
        .unwrap_or(&event.title)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::{MonitorEvent, MonitorSource, Severity};
    use chrono::Utc;

    fn make_github_repo_event(
        name: &str,
        url: &str,
        tags: Vec<&str>,
        description: &str,
    ) -> MonitorEvent {
        MonitorEvent {
            id: format!("gh-repo-{}", name),
            source: MonitorSource::GitHub,
            title: format!("New MCP repo: {}", name),
            description: description.to_string(),
            url: url.to_string(),
            discovered_at: Utc::now(),
            severity: Some(Severity::Low),
            tags: tags.into_iter().map(String::from).collect(),
            metadata: serde_json::json!({
                "stars": 50,
                "language": "TypeScript",
            }),
        }
    }

    fn make_advisory_event() -> MonitorEvent {
        MonitorEvent {
            id: "gh-advisory-GHSA-1234".into(),
            source: MonitorSource::GitHub,
            title: "Security Advisory: MCP server injection".into(),
            description: "A vulnerability".into(),
            url: "https://github.com/advisories/GHSA-1234".into(),
            discovered_at: Utc::now(),
            severity: Some(Severity::Critical),
            tags: vec!["advisory".into(), "security".into()],
            metadata: serde_json::json!({}),
        }
    }

    fn make_cve_event() -> MonitorEvent {
        MonitorEvent {
            id: "nvd-CVE-2026-0001".into(),
            source: MonitorSource::Cve,
            title: "CVE-2026-0001".into(),
            description: "A CVE".into(),
            url: "https://nvd.nist.gov/vuln/detail/CVE-2026-0001".into(),
            discovered_at: Utc::now(),
            severity: Some(Severity::High),
            tags: vec!["cve".into()],
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn test_discover_servers_from_github_repos() {
        let events = vec![
            make_github_repo_event(
                "user/mcp-server",
                "https://github.com/user/mcp-server",
                vec!["repository", "mcp"],
                "An MCP server implementation",
            ),
            make_github_repo_event(
                "org/mcp-http-api",
                "https://github.com/org/mcp-http-api",
                vec!["repository", "mcp", "http"],
                "HTTP MCP server with REST endpoint",
            ),
        ];

        let servers = discover_servers(&events);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "user/mcp-server");
        assert_eq!(servers[1].name, "org/mcp-http-api");
    }

    #[test]
    fn test_discover_skips_advisories() {
        let events = vec![make_advisory_event()];
        let servers = discover_servers(&events);
        assert!(servers.is_empty());
    }

    #[test]
    fn test_discover_skips_non_github_events() {
        let events = vec![make_cve_event()];
        let servers = discover_servers(&events);
        assert!(servers.is_empty());
    }

    #[test]
    fn test_classify_http_endpoint() {
        let event = make_github_repo_event(
            "org/mcp-http-server",
            "https://github.com/org/mcp-http-server",
            vec!["repository", "mcp", "http"],
            "HTTP-based MCP server with SSE transport",
        );
        let server = discover_from_github(&event).unwrap();
        assert_eq!(server.server_type, ServerType::HttpEndpoint);
    }

    #[test]
    fn test_classify_stdio_config() {
        let event = make_github_repo_event(
            "user/mcp-stdio-server",
            "https://github.com/user/mcp-stdio-server",
            vec!["repository", "mcp", "stdio"],
            "A stdio MCP server config",
        );
        let server = discover_from_github(&event).unwrap();
        assert_eq!(server.server_type, ServerType::StdioConfig);
    }

    #[test]
    fn test_classify_default_repository() {
        let event = make_github_repo_event(
            "user/mcp-tools",
            "https://github.com/user/mcp-tools",
            vec!["repository", "mcp"],
            "MCP utilities and helpers",
        );
        let server = discover_from_github(&event).unwrap();
        assert_eq!(server.server_type, ServerType::Repository);
    }

    #[test]
    fn test_extract_server_name_from_url() {
        let event = make_github_repo_event(
            "owner/repo",
            "https://github.com/owner/repo",
            vec!["repository"],
            "",
        );
        let name = extract_server_name(&event);
        assert_eq!(name, "owner/repo");
    }

    #[test]
    fn test_extract_server_name_fallback() {
        let mut event = make_github_repo_event(
            "my-server",
            "https://other-host.com/something",
            vec!["repository"],
            "",
        );
        event.title = "New MCP repo: my-server".to_string();
        let name = extract_server_name(&event);
        assert_eq!(name, "my-server");
    }

    #[test]
    fn test_server_type_display() {
        assert_eq!(ServerType::StdioConfig.to_string(), "Stdio Config");
        assert_eq!(ServerType::HttpEndpoint.to_string(), "HTTP Endpoint");
        assert_eq!(ServerType::Repository.to_string(), "Repository");
    }

    #[test]
    fn test_scan_result_has_critical_findings() {
        let server = DiscoveredServer {
            name: "test".into(),
            url: "https://github.com/test/repo".into(),
            source_event: make_github_repo_event(
                "test",
                "https://github.com/test/repo",
                vec!["repository"],
                "",
            ),
            server_type: ServerType::Repository,
        };

        let result_with_critical = ScanResult {
            server: server.clone(),
            findings: vec![ScanFinding {
                rule_id: "MCP-001".into(),
                severity: Severity::Critical,
                title: "Critical issue".into(),
                description: "A critical finding".into(),
            }],
            scanned_at: Utc::now(),
        };
        assert!(result_with_critical.has_critical_findings());

        let result_without_critical = ScanResult {
            server: server.clone(),
            findings: vec![ScanFinding {
                rule_id: "MCP-002".into(),
                severity: Severity::Low,
                title: "Minor issue".into(),
                description: "A low finding".into(),
            }],
            scanned_at: Utc::now(),
        };
        assert!(!result_without_critical.has_critical_findings());

        let empty_result = ScanResult {
            server,
            findings: vec![],
            scanned_at: Utc::now(),
        };
        assert!(!empty_result.has_critical_findings());
    }

    #[test]
    fn test_scan_result_severity_counts() {
        let server = DiscoveredServer {
            name: "test".into(),
            url: "https://github.com/test/repo".into(),
            source_event: make_github_repo_event(
                "test",
                "https://github.com/test/repo",
                vec!["repository"],
                "",
            ),
            server_type: ServerType::Repository,
        };

        let result = ScanResult {
            server,
            findings: vec![
                ScanFinding {
                    rule_id: "MCP-001".into(),
                    severity: Severity::Critical,
                    title: "Critical".into(),
                    description: String::new(),
                },
                ScanFinding {
                    rule_id: "MCP-002".into(),
                    severity: Severity::Critical,
                    title: "Critical 2".into(),
                    description: String::new(),
                },
                ScanFinding {
                    rule_id: "MCP-003".into(),
                    severity: Severity::Low,
                    title: "Low".into(),
                    description: String::new(),
                },
            ],
            scanned_at: Utc::now(),
        };

        let counts = result.severity_counts();
        assert_eq!(counts.len(), 2);
        // Critical should come first.
        assert_eq!(counts[0].0, Severity::Critical);
        assert_eq!(counts[0].1, 2);
        assert_eq!(counts[1].0, Severity::Low);
        assert_eq!(counts[1].1, 1);
    }

    #[test]
    fn test_discover_servers_mixed_events() {
        let events = vec![
            make_github_repo_event(
                "user/mcp-server",
                "https://github.com/user/mcp-server",
                vec!["repository", "mcp"],
                "An MCP server",
            ),
            make_advisory_event(),
            make_cve_event(),
            MonitorEvent {
                id: "adoption-1".into(),
                source: MonitorSource::Adoption,
                title: "npm downloads".into(),
                description: String::new(),
                url: String::new(),
                discovered_at: Utc::now(),
                severity: Some(Severity::Info),
                tags: vec!["adoption".into()],
                metadata: serde_json::json!({}),
            },
        ];

        let servers = discover_servers(&events);
        // Only the one GitHub repo event should produce a server.
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "user/mcp-server");
    }

    #[test]
    fn test_discover_skips_empty_url() {
        let mut event =
            make_github_repo_event("test", "", vec!["repository", "mcp"], "An MCP server");
        event.url = String::new();
        let servers = discover_servers(&[event]);
        assert!(servers.is_empty());
    }
}
