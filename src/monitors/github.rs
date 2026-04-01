//! GitHub ecosystem monitor — tracks MCP-related repositories, issues, and security advisories.
//!
//! Uses the GitHub Search API and Security Advisories API to discover:
//! - New MCP server repositories
//! - Security advisories affecting MCP packages
//! - Trending MCP projects (by recent star activity)
//! - Issues/PRs related to MCP security

use crate::error::Result;
use crate::http::RateLimitedClient;
use crate::monitors::{Monitor, MonitorEvent, MonitorSource, PollOptions, Severity};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;

/// GitHub Search API base URL.
const GITHUB_SEARCH_REPOS_URL: &str = "https://api.github.com/search/repositories";
const GITHUB_ADVISORIES_URL: &str = "https://api.github.com/advisories";

/// Search queries targeting MCP ecosystem.
const MCP_SEARCH_QUERIES: &[&str] = &[
    "mcp server",
    "model context protocol server",
    "mcp-server",
    "topic:mcp",
];

/// Keywords for security advisory search.
const ADVISORY_KEYWORDS: &[&str] = &["mcp", "model context protocol", "mcp-server"];

// ── GitHub API response types ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    items: Vec<RepoItem>,
    total_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RepoItem {
    id: u64,
    full_name: String,
    description: Option<String>,
    html_url: String,
    stargazers_count: u64,
    language: Option<String>,
    created_at: String,
    updated_at: String,
    topics: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    has_issues: bool,
    open_issues_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryItem {
    ghsa_id: String,
    summary: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    html_url: String,
    published_at: Option<String>,
    #[allow(dead_code)]
    updated_at: Option<String>,
    cve_id: Option<String>,
    vulnerabilities: Option<Vec<AdvisoryVulnerability>>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryVulnerability {
    package: Option<AdvisoryPackage>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryPackage {
    ecosystem: Option<String>,
    name: Option<String>,
}

// ── Monitor implementation ──────────────────────────────────────────────

/// Monitors GitHub for new MCP server repos and security advisories.
pub struct GitHubMonitor {
    client: RateLimitedClient,
}

impl GitHubMonitor {
    pub fn new(client: RateLimitedClient) -> Self {
        Self { client }
    }

    /// Search for MCP-related repositories.
    async fn search_repos(&self, opts: &PollOptions) -> Result<Vec<MonitorEvent>> {
        let mut all_events = Vec::new();
        let per_query_limit = (opts.max_results / MCP_SEARCH_QUERIES.len()).max(5);

        for query in MCP_SEARCH_QUERIES {
            let mut url = format!(
                "{}?q={}&sort=updated&order=desc&per_page={}",
                GITHUB_SEARCH_REPOS_URL,
                urlencoding::encode(query),
                per_query_limit.min(100),
            );

            // Filter by date if watermark provided.
            if let Some(since) = opts.since {
                let date_str = since.format("%Y-%m-%dT%H:%M:%S").to_string();
                url = format!(
                    "{}?q={}+pushed:>={}&sort=updated&order=desc&per_page={}",
                    GITHUB_SEARCH_REPOS_URL,
                    urlencoding::encode(query),
                    date_str,
                    per_query_limit.min(100),
                );
            }

            tracing::debug!(query = %query, url = %url, "Searching GitHub repos");

            match self.client.get_json::<SearchResponse>(&url).await {
                Ok(search) => {
                    tracing::info!(
                        query = %query,
                        total = ?search.total_count,
                        returned = search.items.len(),
                        "GitHub repo search results"
                    );
                    for item in search.items {
                        all_events.push(repo_to_event(item));
                    }
                }
                Err(e) => {
                    tracing::warn!(query = %query, error = %e, "GitHub search failed, continuing");
                }
            }

            if all_events.len() >= opts.max_results {
                break;
            }
        }

        // Deduplicate by ID (same repo may match multiple queries).
        all_events.sort_by(|a, b| a.id.cmp(&b.id));
        all_events.dedup_by(|a, b| a.id == b.id);
        all_events.truncate(opts.max_results);

        Ok(all_events)
    }

    /// Search for security advisories related to MCP.
    async fn search_advisories(&self, opts: &PollOptions) -> Result<Vec<MonitorEvent>> {
        let mut all_events = Vec::new();

        for keyword in ADVISORY_KEYWORDS {
            let mut url = format!(
                "{}?per_page={}&type=reviewed",
                GITHUB_ADVISORIES_URL,
                opts.max_results.min(100),
            );

            if let Some(since) = opts.since {
                url.push_str(&format!("&updated={}", since.format("%Y-%m-%d")));
            }

            tracing::debug!(keyword = %keyword, url = %url, "Searching GitHub advisories");

            match self.client.get_json::<Vec<AdvisoryItem>>(&url).await {
                Ok(advisories) => {
                    for advisory in advisories {
                        // Filter: only include advisories mentioning MCP keywords.
                        let text = format!(
                            "{} {}",
                            advisory.summary.as_deref().unwrap_or(""),
                            advisory.description.as_deref().unwrap_or(""),
                        )
                        .to_lowercase();

                        let is_mcp_related = ADVISORY_KEYWORDS.iter().any(|kw| text.contains(kw));
                        let has_mcp_package = advisory
                            .vulnerabilities
                            .as_ref()
                            .map(|vulns| {
                                vulns.iter().any(|v| {
                                    v.package
                                        .as_ref()
                                        .and_then(|p| p.name.as_ref())
                                        .map(|n| n.to_lowercase().contains("mcp"))
                                        .unwrap_or(false)
                                })
                            })
                            .unwrap_or(false);

                        if is_mcp_related || has_mcp_package {
                            all_events.push(advisory_to_event(advisory));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(keyword = %keyword, error = %e, "Advisory search failed");
                }
            }

            if all_events.len() >= opts.max_results {
                break;
            }
        }

        all_events.truncate(opts.max_results);
        Ok(all_events)
    }
}

impl Monitor for GitHubMonitor {
    fn source(&self) -> MonitorSource {
        MonitorSource::GitHub
    }

    fn name(&self) -> &str {
        "GitHub MCP Ecosystem"
    }

    fn poll(
        &self,
        opts: &PollOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        let opts = opts.clone();
        Box::pin(async move {
            let mut events = Vec::new();

            // Fetch repos and advisories concurrently.
            let (repos_result, advisories_result) =
                tokio::join!(self.search_repos(&opts), self.search_advisories(&opts));

            match repos_result {
                Ok(repo_events) => {
                    tracing::info!(count = repo_events.len(), "GitHub repos discovered");
                    events.extend(repo_events);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to search GitHub repos");
                }
            }

            match advisories_result {
                Ok(adv_events) => {
                    tracing::info!(count = adv_events.len(), "GitHub advisories discovered");
                    events.extend(adv_events);
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to search GitHub advisories");
                }
            }

            // Sort by discovered_at descending.
            events.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
            events.truncate(opts.max_results);

            Ok(events)
        })
    }
}

// ── Conversion helpers ──────────────────────────────────────────────────

fn repo_to_event(item: RepoItem) -> MonitorEvent {
    let created = parse_github_date(&item.created_at);
    let updated = parse_github_date(&item.updated_at);

    let mut tags = vec!["repository".to_string(), "mcp".to_string()];
    if let Some(lang) = &item.language {
        tags.push(lang.to_lowercase());
    }
    if let Some(topics) = &item.topics {
        for topic in topics {
            if !tags.contains(topic) {
                tags.push(topic.clone());
            }
        }
    }

    // Assess "interest" severity based on stars.
    let severity = match item.stargazers_count {
        0..=10 => Severity::Info,
        11..=100 => Severity::Low,
        101..=500 => Severity::Medium,
        501..=2000 => Severity::High,
        _ => Severity::Critical,
    };

    MonitorEvent {
        id: format!("gh-repo-{}", item.id),
        source: MonitorSource::GitHub,
        title: format!("New MCP repo: {}", item.full_name),
        description: item
            .description
            .unwrap_or_else(|| "No description".to_string()),
        url: item.html_url,
        discovered_at: updated.unwrap_or_else(Utc::now),
        severity: Some(severity),
        tags,
        metadata: serde_json::json!({
            "stars": item.stargazers_count,
            "language": item.language,
            "created_at": created,
            "updated_at": updated,
            "open_issues": item.open_issues_count,
        }),
    }
}

fn advisory_to_event(item: AdvisoryItem) -> MonitorEvent {
    let severity = match item.severity.as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("medium") | Some("moderate") => Severity::Medium,
        Some("low") => Severity::Low,
        _ => Severity::Info,
    };

    let published = item
        .published_at
        .as_deref()
        .and_then(parse_github_date)
        .unwrap_or_else(Utc::now);

    let mut tags = vec!["advisory".to_string(), "security".to_string()];
    if let Some(cve_id) = &item.cve_id {
        tags.push(cve_id.clone());
    }

    let packages: Vec<String> = item
        .vulnerabilities
        .as_ref()
        .map(|vulns| {
            vulns
                .iter()
                .filter_map(|v| {
                    v.package.as_ref().and_then(|p| {
                        let eco = p.ecosystem.as_deref().unwrap_or("unknown");
                        p.name.as_ref().map(|n| format!("{}:{}", eco, n))
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    MonitorEvent {
        id: format!("gh-advisory-{}", item.ghsa_id),
        source: MonitorSource::GitHub,
        title: format!(
            "Security Advisory: {}",
            item.summary.as_deref().unwrap_or(&item.ghsa_id)
        ),
        description: item
            .description
            .unwrap_or_else(|| "No description available".to_string()),
        url: item.html_url,
        discovered_at: published,
        severity: Some(severity),
        tags,
        metadata: serde_json::json!({
            "ghsa_id": item.ghsa_id,
            "cve_id": item.cve_id,
            "packages": packages,
        }),
    }
}

fn parse_github_date(s: &str) -> Option<DateTime<Utc>> {
    // GitHub dates: "2024-01-15T10:30:00Z"
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Percent-encode a string for use in URL query parameters.
mod urlencoding {
    pub fn encode(input: &str) -> String {
        let mut result = String::with_capacity(input.len() * 3);
        for byte in input.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                b' ' => result.push('+'),
                _ => {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_to_event_basic() {
        let item = RepoItem {
            id: 12345,
            full_name: "user/mcp-server".to_string(),
            description: Some("An MCP server implementation".to_string()),
            html_url: "https://github.com/user/mcp-server".to_string(),
            stargazers_count: 50,
            language: Some("Rust".to_string()),
            created_at: "2025-01-15T10:00:00Z".to_string(),
            updated_at: "2026-03-20T15:00:00Z".to_string(),
            topics: Some(vec!["mcp".to_string(), "security".to_string()]),
            has_issues: true,
            open_issues_count: Some(5),
        };

        let event = repo_to_event(item);
        assert_eq!(event.id, "gh-repo-12345");
        assert_eq!(event.source, MonitorSource::GitHub);
        assert!(event.title.contains("mcp-server"));
        assert_eq!(event.severity, Some(Severity::Low)); // 50 stars
        assert!(event.tags.contains(&"rust".to_string()));
    }

    #[test]
    fn test_advisory_to_event() {
        let item = AdvisoryItem {
            ghsa_id: "GHSA-test-1234".to_string(),
            summary: Some("MCP server command injection".to_string()),
            description: Some("A critical vulnerability in MCP server".to_string()),
            severity: Some("critical".to_string()),
            html_url: "https://github.com/advisories/GHSA-test-1234".to_string(),
            published_at: Some("2026-03-15T12:00:00Z".to_string()),
            updated_at: Some("2026-03-20T12:00:00Z".to_string()),
            cve_id: Some("CVE-2026-1234".to_string()),
            vulnerabilities: Some(vec![AdvisoryVulnerability {
                package: Some(AdvisoryPackage {
                    ecosystem: Some("npm".to_string()),
                    name: Some("mcp-server-auth".to_string()),
                }),
            }]),
        };

        let event = advisory_to_event(item);
        assert_eq!(event.id, "gh-advisory-GHSA-test-1234");
        assert_eq!(event.severity, Some(Severity::Critical));
        assert!(event.tags.contains(&"CVE-2026-1234".to_string()));
    }

    #[test]
    fn test_star_severity_mapping() {
        let make_repo = |stars| RepoItem {
            id: stars,
            full_name: "user/repo".to_string(),
            description: None,
            html_url: "https://github.com/user/repo".to_string(),
            stargazers_count: stars,
            language: None,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: "2025-01-01T00:00:00Z".to_string(),
            topics: None,
            has_issues: false,
            open_issues_count: None,
        };

        assert_eq!(repo_to_event(make_repo(5)).severity, Some(Severity::Info));
        assert_eq!(repo_to_event(make_repo(50)).severity, Some(Severity::Low));
        assert_eq!(
            repo_to_event(make_repo(200)).severity,
            Some(Severity::Medium)
        );
        assert_eq!(
            repo_to_event(make_repo(1000)).severity,
            Some(Severity::High)
        );
        assert_eq!(
            repo_to_event(make_repo(5000)).severity,
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding::encode("hello world"), "hello+world");
        assert_eq!(urlencoding::encode("mcp server"), "mcp+server");
        assert_eq!(urlencoding::encode("topic:mcp"), "topic%3Amcp");
    }
}
