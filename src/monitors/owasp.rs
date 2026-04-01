//! OWASP monitor — tracks updates to the OWASP MCP Top 10 and related publications.
//!
//! Monitors the OWASP GitHub organisation for:
//! - New commits / releases on the MCP Top 10 repository
//! - New OWASP projects related to MCP security
//! - Updates to existing OWASP MCP guidance documents

use crate::error::Result;
use crate::http::RateLimitedClient;
use crate::monitors::{Monitor, MonitorEvent, MonitorSource, PollOptions, Severity};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;

/// GitHub API URLs for OWASP MCP-related repos.
const OWASP_MCP_REPOS: &[&str] = &[
    "https://api.github.com/repos/OWASP/www-project-machine-learning-security-top-10",
    "https://api.github.com/repos/OWASP/www-project-top-10-for-large-language-model-applications",
];

/// OWASP org search for MCP-related content.
const OWASP_SEARCH_URL: &str =
    "https://api.github.com/search/repositories?q=org:OWASP+mcp+OR+model+context+protocol&sort=updated&order=desc&per_page=10";

// ── GitHub API response types ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RepoInfo {
    full_name: String,
    description: Option<String>,
    html_url: String,
    updated_at: String,
    #[allow(dead_code)]
    pushed_at: Option<String>,
    stargazers_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CommitItem {
    sha: String,
    commit: CommitDetail,
    html_url: String,
}

#[derive(Debug, Deserialize)]
struct CommitDetail {
    message: String,
    committer: Option<CommitAuthor>,
}

#[derive(Debug, Deserialize)]
struct CommitAuthor {
    date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseItem {
    id: u64,
    tag_name: String,
    name: Option<String>,
    body: Option<String>,
    html_url: String,
    published_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SearchResult {
    #[serde(default)]
    items: Vec<RepoInfo>,
}

// ── Monitor ─────────────────────────────────────────────────────────────

/// Monitors OWASP GitHub repos for MCP security guidance updates.
pub struct OwaspMonitor {
    client: RateLimitedClient,
}

impl OwaspMonitor {
    pub fn new(client: RateLimitedClient) -> Self {
        Self { client }
    }

    /// Fetch recent commits from known OWASP MCP repos.
    async fn check_commits(&self, opts: &PollOptions) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        for repo_url in OWASP_MCP_REPOS {
            let commits_url = format!("{}/commits?per_page={}", repo_url, opts.max_results.min(20));

            match self.client.get_json::<Vec<CommitItem>>(&commits_url).await {
                Ok(commits) => {
                    for commit in commits {
                        let date = commit
                            .commit
                            .committer
                            .as_ref()
                            .and_then(|c| c.date.as_deref())
                            .and_then(parse_date)
                            .unwrap_or_else(Utc::now);

                        // Skip if before watermark.
                        if let Some(since) = opts.since {
                            if date < since {
                                continue;
                            }
                        }

                        // Extract repo name from URL.
                        let repo_name = repo_url
                            .strip_prefix("https://api.github.com/repos/")
                            .unwrap_or("OWASP/unknown");

                        let message = commit
                            .commit
                            .message
                            .lines()
                            .next()
                            .unwrap_or("")
                            .to_string();

                        events.push(MonitorEvent {
                            id: format!("owasp-commit-{}", &commit.sha[..12]),
                            source: MonitorSource::Owasp,
                            title: format!("OWASP update: {}", truncate(&message, 80)),
                            description: commit.commit.message.clone(),
                            url: commit.html_url,
                            discovered_at: date,
                            severity: Some(Severity::Medium),
                            tags: vec!["owasp".into(), "commit".into(), repo_name.to_string()],
                            metadata: serde_json::json!({
                                "sha": commit.sha,
                                "repo": repo_name,
                                "message": commit.commit.message,
                            }),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!(repo = %repo_url, error = %e, "OWASP commit fetch failed");
                }
            }
        }

        Ok(events)
    }

    /// Check for new releases on OWASP MCP repos.
    async fn check_releases(&self, opts: &PollOptions) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        for repo_url in OWASP_MCP_REPOS {
            let releases_url = format!("{}/releases?per_page=5", repo_url);

            match self
                .client
                .get_json::<Vec<ReleaseItem>>(&releases_url)
                .await
            {
                Ok(releases) => {
                    for release in releases {
                        let date = release
                            .published_at
                            .as_deref()
                            .and_then(parse_date)
                            .unwrap_or_else(Utc::now);

                        if let Some(since) = opts.since {
                            if date < since {
                                continue;
                            }
                        }

                        let repo_name = repo_url
                            .strip_prefix("https://api.github.com/repos/")
                            .unwrap_or("OWASP/unknown");

                        events.push(MonitorEvent {
                            id: format!("owasp-release-{}", release.id),
                            source: MonitorSource::Owasp,
                            title: format!(
                                "OWASP Release: {} {}",
                                repo_name,
                                release.name.as_deref().unwrap_or(&release.tag_name)
                            ),
                            description: release.body.unwrap_or_default(),
                            url: release.html_url,
                            discovered_at: date,
                            severity: Some(Severity::High),
                            tags: vec!["owasp".into(), "release".into(), release.tag_name.clone()],
                            metadata: serde_json::json!({
                                "tag": release.tag_name,
                                "repo": repo_name,
                            }),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!(repo = %repo_url, error = %e, "OWASP release fetch failed");
                }
            }
        }

        Ok(events)
    }

    /// Search for new OWASP repos related to MCP.
    async fn search_owasp_repos(&self, opts: &PollOptions) -> Result<Vec<MonitorEvent>> {
        let result: SearchResult = match self.client.get_json(OWASP_SEARCH_URL).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "OWASP repo search failed");
                return Ok(Vec::new());
            }
        };

        let events: Vec<MonitorEvent> = result
            .items
            .into_iter()
            .filter_map(|repo| {
                let updated = parse_date(&repo.updated_at)?;
                if let Some(since) = opts.since {
                    if updated < since {
                        return None;
                    }
                }

                Some(MonitorEvent {
                    id: format!("owasp-repo-{}", slug(&repo.full_name)),
                    source: MonitorSource::Owasp,
                    title: format!("OWASP MCP Project: {}", repo.full_name),
                    description: repo.description.unwrap_or_default(),
                    url: repo.html_url,
                    discovered_at: updated,
                    severity: Some(Severity::Medium),
                    tags: vec!["owasp".into(), "project".into()],
                    metadata: serde_json::json!({
                        "stars": repo.stargazers_count,
                    }),
                })
            })
            .collect();

        Ok(events)
    }
}

impl Monitor for OwaspMonitor {
    fn source(&self) -> MonitorSource {
        MonitorSource::Owasp
    }

    fn name(&self) -> &str {
        "OWASP MCP Top 10"
    }

    fn poll(
        &self,
        opts: &PollOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        let opts = opts.clone();
        Box::pin(async move {
            let (commits_res, releases_res, repos_res) = tokio::join!(
                self.check_commits(&opts),
                self.check_releases(&opts),
                self.search_owasp_repos(&opts),
            );

            let mut events = Vec::new();

            match commits_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "OWASP commit check failed"),
            }
            match releases_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "OWASP release check failed"),
            }
            match repos_res {
                Ok(v) => events.extend(v),
                Err(e) => tracing::error!(error = %e, "OWASP repo search failed"),
            }

            events.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
            events.truncate(opts.max_results);

            Ok(events)
        })
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

fn slug(s: &str) -> String {
    s.to_lowercase().replace('/', "-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_slug() {
        assert_eq!(slug("OWASP/www-project-mcp"), "owasp-www-project-mcp");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long string indeed", 10), "a very lon...");
    }

    #[test]
    fn test_parse_date() {
        let dt = parse_date("2026-03-20T15:30:00Z");
        assert!(dt.is_some());
        assert_eq!(dt.unwrap().year(), 2026);

        assert!(parse_date("invalid").is_none());
    }
}
