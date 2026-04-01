//! Adoption monitor — tracks MCP ecosystem growth metrics.
//!
//! Aggregates adoption signals from multiple public sources:
//! - npm registry: download counts for MCP-related packages
//! - crates.io: download counts for Rust MCP crates
//! - GitHub: star trends for key MCP repositories
//! - PyPI: download counts for Python MCP packages

use crate::error::Result;
use crate::http::RateLimitedClient;
use crate::monitors::{Monitor, MonitorEvent, MonitorSource, PollOptions, Severity};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;

/// npm registry API for download counts.
const NPM_DOWNLOADS_URL: &str = "https://api.npmjs.org/downloads/point/last-week";

/// crates.io API base URL.
const CRATES_IO_URL: &str = "https://crates.io/api/v1/crates";

/// Key npm packages to track.
const NPM_PACKAGES: &[&str] = &[
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@anthropic-ai/sdk",
    "mcp-framework",
];

/// Key Rust crates to track.
const RUST_CRATES: &[&str] = &["rmcp", "mcp-server", "mcp-client"];

/// Key GitHub repos to track for star/fork trends.
const TRACKED_REPOS: &[&str] = &[
    "modelcontextprotocol/servers",
    "modelcontextprotocol/specification",
    "anthropics/claude-code",
];

// ── API response types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct NpmDownloads {
    downloads: Option<u64>,
    #[allow(dead_code)]
    package: Option<String>,
    start: Option<String>,
    end: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    #[serde(rename = "crate")]
    krate: Option<CrateInfo>,
}

#[derive(Debug, Deserialize)]
struct CrateInfo {
    name: String,
    downloads: Option<u64>,
    recent_downloads: Option<u64>,
    description: Option<String>,
    max_version: Option<String>,
    updated_at: Option<String>,
    repository: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRepoInfo {
    full_name: String,
    description: Option<String>,
    html_url: String,
    stargazers_count: u64,
    forks_count: u64,
    open_issues_count: u64,
    updated_at: String,
    subscribers_count: Option<u64>,
}

// ── Monitor ─────────────────────────────────────────────────────────────

/// Tracks MCP ecosystem growth metrics from npm, crates.io, and GitHub.
pub struct AdoptionMonitor {
    client: RateLimitedClient,
}

impl AdoptionMonitor {
    pub fn new(client: RateLimitedClient) -> Self {
        Self { client }
    }

    /// Fetch npm download statistics for MCP packages.
    async fn check_npm(&self) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        for package in NPM_PACKAGES {
            let url = format!("{}/{}", NPM_DOWNLOADS_URL, package);

            match self.client.get_json::<NpmDownloads>(&url).await {
                Ok(stats) => {
                    let downloads = stats.downloads.unwrap_or(0);
                    let severity = downloads_to_severity(downloads);

                    events.push(MonitorEvent {
                        id: format!("npm-downloads-{}", slug(package)),
                        source: MonitorSource::Adoption,
                        title: format!(
                            "npm: {} — {} weekly downloads",
                            package,
                            format_number(downloads)
                        ),
                        description: format!(
                            "Package {} had {} downloads in the last week (period: {} to {})",
                            package,
                            format_number(downloads),
                            stats.start.as_deref().unwrap_or("?"),
                            stats.end.as_deref().unwrap_or("?"),
                        ),
                        url: format!("https://www.npmjs.com/package/{}", package),
                        discovered_at: Utc::now(),
                        severity: Some(severity),
                        tags: vec!["npm".into(), "adoption".into(), "downloads".into()],
                        metadata: serde_json::json!({
                            "package": package,
                            "registry": "npm",
                            "weekly_downloads": downloads,
                            "period_start": stats.start,
                            "period_end": stats.end,
                        }),
                    });
                }
                Err(e) => {
                    tracing::warn!(package, error = %e, "npm download fetch failed");
                }
            }
        }

        Ok(events)
    }

    /// Fetch crates.io statistics for Rust MCP crates.
    async fn check_crates_io(&self) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        for crate_name in RUST_CRATES {
            let url = format!("{}/{}", CRATES_IO_URL, crate_name);

            match self.client.get_json::<CratesIoResponse>(&url).await {
                Ok(resp) => {
                    if let Some(info) = resp.krate {
                        let downloads = info.downloads.unwrap_or(0);
                        let recent = info.recent_downloads.unwrap_or(0);

                        events.push(MonitorEvent {
                            id: format!("crate-{}", info.name),
                            source: MonitorSource::Adoption,
                            title: format!(
                                "crates.io: {} v{} — {} total downloads",
                                info.name,
                                info.max_version.as_deref().unwrap_or("?"),
                                format_number(downloads),
                            ),
                            description: info.description.unwrap_or_default(),
                            url: format!("https://crates.io/crates/{}", info.name),
                            discovered_at: info
                                .updated_at
                                .as_deref()
                                .and_then(parse_date)
                                .unwrap_or_else(Utc::now),
                            severity: Some(downloads_to_severity(recent)),
                            tags: vec!["crates.io".into(), "rust".into(), "adoption".into()],
                            metadata: serde_json::json!({
                                "crate": info.name,
                                "registry": "crates.io",
                                "total_downloads": downloads,
                                "recent_downloads": recent,
                                "max_version": info.max_version,
                                "repository": info.repository,
                            }),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!(crate_name, error = %e, "crates.io fetch failed");
                }
            }
        }

        Ok(events)
    }

    /// Fetch GitHub star/fork metrics for key MCP repositories.
    async fn check_github_stars(&self) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        for repo in TRACKED_REPOS {
            let url = format!("https://api.github.com/repos/{}", repo);

            match self.client.get_json::<GitHubRepoInfo>(&url).await {
                Ok(info) => {
                    let severity = stars_to_severity(info.stargazers_count);

                    events.push(MonitorEvent {
                        id: format!("gh-stars-{}", slug(repo)),
                        source: MonitorSource::Adoption,
                        title: format!(
                            "GitHub: {} — ⭐ {} stars, {} forks",
                            info.full_name,
                            format_number(info.stargazers_count),
                            format_number(info.forks_count),
                        ),
                        description: info.description.unwrap_or_default(),
                        url: info.html_url,
                        discovered_at: parse_date(&info.updated_at).unwrap_or_else(Utc::now),
                        severity: Some(severity),
                        tags: vec!["github".into(), "stars".into(), "adoption".into()],
                        metadata: serde_json::json!({
                            "repo": info.full_name,
                            "stars": info.stargazers_count,
                            "forks": info.forks_count,
                            "open_issues": info.open_issues_count,
                            "watchers": info.subscribers_count,
                        }),
                    });
                }
                Err(e) => {
                    tracing::warn!(repo, error = %e, "GitHub stars fetch failed");
                }
            }
        }

        Ok(events)
    }
}

impl Monitor for AdoptionMonitor {
    fn source(&self) -> MonitorSource {
        MonitorSource::Adoption
    }

    fn name(&self) -> &str {
        "MCP Adoption Metrics"
    }

    fn poll(
        &self,
        opts: &PollOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        let max_results = opts.max_results;
        Box::pin(async move {
            let (npm_res, crates_res, stars_res) = tokio::join!(
                self.check_npm(),
                self.check_crates_io(),
                self.check_github_stars(),
            );

            let mut events = Vec::new();

            match npm_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "npm check failed"),
            }
            match crates_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "crates.io check failed"),
            }
            match stars_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "GitHub stars check failed"),
            }

            events.truncate(max_results);
            Ok(events)
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn downloads_to_severity(downloads: u64) -> Severity {
    match downloads {
        0..=100 => Severity::Info,
        101..=1_000 => Severity::Low,
        1_001..=10_000 => Severity::Medium,
        10_001..=100_000 => Severity::High,
        _ => Severity::Critical,
    }
}

fn stars_to_severity(stars: u64) -> Severity {
    match stars {
        0..=50 => Severity::Info,
        51..=500 => Severity::Low,
        501..=2_000 => Severity::Medium,
        2_001..=10_000 => Severity::High,
        _ => Severity::Critical,
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn slug(s: &str) -> String {
    s.to_lowercase()
        .replace(['/', '@', '.'], "-")
        .replace("--", "-")
        .trim_matches('-')
        .to_string()
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(500), "500");
        assert_eq!(format_number(1_500), "1.5K");
        assert_eq!(format_number(2_500_000), "2.5M");
    }

    #[test]
    fn test_downloads_to_severity() {
        assert_eq!(downloads_to_severity(50), Severity::Info);
        assert_eq!(downloads_to_severity(500), Severity::Low);
        assert_eq!(downloads_to_severity(5_000), Severity::Medium);
        assert_eq!(downloads_to_severity(50_000), Severity::High);
        assert_eq!(downloads_to_severity(500_000), Severity::Critical);
    }

    #[test]
    fn test_slug() {
        assert_eq!(
            slug("@modelcontextprotocol/sdk"),
            "modelcontextprotocol-sdk"
        );
        assert_eq!(slug("user/repo"), "user-repo");
    }

    #[test]
    fn test_stars_to_severity() {
        assert_eq!(stars_to_severity(10), Severity::Info);
        assert_eq!(stars_to_severity(100), Severity::Low);
        assert_eq!(stars_to_severity(1000), Severity::Medium);
        assert_eq!(stars_to_severity(5000), Severity::High);
        assert_eq!(stars_to_severity(50000), Severity::Critical);
    }
}
