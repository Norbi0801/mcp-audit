//! Weekly digest generator — aggregates MonitorEvents into a structured
//! report with severity breakdown, trending topics, and actionable insights.
//!
//! The digest is designed to be published as:
//! - A newsletter email
//! - A blog post / content marketing piece
//! - SEO-optimized web page

use crate::monitors::{MonitorEvent, MonitorSource, Severity};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Note: rendering is handled by the output module (output::render_digest).

/// A weekly digest report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyDigest {
    /// The time period this digest covers.
    pub period: DigestPeriod,
    /// Events from the GitHub monitor.
    pub github_events: Vec<MonitorEvent>,
    /// Events from the CVE/NVD monitor.
    pub cve_events: Vec<MonitorEvent>,
    /// Events from the OWASP monitor.
    pub owasp_events: Vec<MonitorEvent>,
    /// Events from the Adoption monitor.
    pub adoption_events: Vec<MonitorEvent>,
    /// Aggregated statistics.
    pub statistics: DigestStatistics,
    /// When this digest was generated.
    pub generated_at: DateTime<Utc>,
    /// SEO keywords (empty if SEO not requested).
    pub seo_keywords: Vec<String>,
}

/// Time period for a digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestPeriod {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl DigestPeriod {
    /// The previous full ISO week (Monday 00:00 to Sunday 23:59 UTC).
    pub fn last_week() -> Self {
        let today = Utc::now().date_naive();
        let days_since_monday = today.weekday().num_days_from_monday();
        let this_monday = today - chrono::Duration::days(days_since_monday as i64);
        let prev_monday = this_monday - chrono::Duration::days(7);
        let prev_sunday = this_monday - chrono::Duration::days(1);

        Self {
            start: prev_monday.and_hms_opt(0, 0, 0).unwrap().and_utc(),
            end: prev_sunday.and_hms_opt(23, 59, 59).unwrap().and_utc(),
        }
    }

    /// Build a period from an ISO week string like "2026-W13".
    pub fn from_iso_week(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split("-W").collect();
        if parts.len() != 2 {
            return None;
        }
        let year: i32 = parts[0].parse().ok()?;
        let week: u32 = parts[1].parse().ok()?;
        if week == 0 || week > 53 {
            return None;
        }

        let jan4 = NaiveDate::from_ymd_opt(year, 1, 4)?;
        let jan4_wd = jan4.weekday().num_days_from_monday();
        let week1_monday = jan4 - chrono::Duration::days(jan4_wd as i64);
        let target_monday = week1_monday + chrono::Duration::weeks((week - 1) as i64);
        let target_sunday = target_monday + chrono::Duration::days(6);

        Some(Self {
            start: target_monday.and_hms_opt(0, 0, 0)?.and_utc(),
            end: target_sunday.and_hms_opt(23, 59, 59)?.and_utc(),
        })
    }

    /// Format as ISO week string.
    pub fn iso_week_label(&self) -> String {
        let d = self.start.date_naive();
        format!("{}-W{:02}", d.year(), d.iso_week().week())
    }
}

/// Aggregated statistics for a digest period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestStatistics {
    pub total_events: usize,
    pub new_servers: usize,
    pub new_cves: usize,
    pub critical_cves: usize,
    pub owasp_updates: usize,
    pub adoption_signals: usize,
    pub top_languages: Vec<(String, usize)>,
    pub severity_breakdown: Vec<(Severity, usize)>,
}

// ── Builder ─────────────────────────────────────────────────────────────

/// Build a weekly digest from a collection of events.
pub fn build_digest(
    events: Vec<MonitorEvent>,
    week: Option<&str>,
    include_seo: bool,
) -> WeeklyDigest {
    let period = week
        .and_then(DigestPeriod::from_iso_week)
        .unwrap_or_else(DigestPeriod::last_week);

    // Filter events within the period.
    let filtered: Vec<MonitorEvent> = events
        .into_iter()
        .filter(|e| e.discovered_at >= period.start && e.discovered_at <= period.end)
        .collect();

    // Split by source.
    let github_events: Vec<MonitorEvent> = filtered
        .iter()
        .filter(|e| e.source == MonitorSource::GitHub)
        .cloned()
        .collect();
    let cve_events: Vec<MonitorEvent> = filtered
        .iter()
        .filter(|e| e.source == MonitorSource::Cve)
        .cloned()
        .collect();
    let owasp_events: Vec<MonitorEvent> = filtered
        .iter()
        .filter(|e| e.source == MonitorSource::Owasp)
        .cloned()
        .collect();
    let adoption_events: Vec<MonitorEvent> = filtered
        .iter()
        .filter(|e| e.source == MonitorSource::Adoption)
        .cloned()
        .collect();

    let statistics = compute_statistics(&filtered);
    let seo_keywords = if include_seo {
        generate_seo_keywords(&filtered)
    } else {
        Vec::new()
    };

    WeeklyDigest {
        period,
        github_events,
        cve_events,
        owasp_events,
        adoption_events,
        statistics,
        generated_at: Utc::now(),
        seo_keywords,
    }
}

fn compute_statistics(events: &[MonitorEvent]) -> DigestStatistics {
    let severity_count = |sev: Severity| events.iter().filter(|e| e.severity == Some(sev)).count();

    // Severity breakdown (only non-zero).
    let mut severity_breakdown = Vec::new();
    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        let count = severity_count(*sev);
        if count > 0 {
            severity_breakdown.push((*sev, count));
        }
    }

    // Top languages from repository metadata.
    let mut lang_counts: HashMap<String, usize> = HashMap::new();
    for event in events {
        if let Some(lang) = event.metadata.get("language").and_then(|v| v.as_str()) {
            if !lang.is_empty() {
                *lang_counts.entry(lang.to_string()).or_default() += 1;
            }
        }
    }
    let mut top_languages: Vec<(String, usize)> = lang_counts.into_iter().collect();
    top_languages.sort_by(|a, b| b.1.cmp(&a.1));
    top_languages.truncate(10);

    DigestStatistics {
        total_events: events.len(),
        new_servers: events
            .iter()
            .filter(|e| e.tags.contains(&"repository".to_string()))
            .count(),
        new_cves: events
            .iter()
            .filter(|e| {
                e.tags.contains(&"cve".to_string()) || e.tags.contains(&"vulnerability".to_string())
            })
            .count(),
        critical_cves: events
            .iter()
            .filter(|e| e.source == MonitorSource::Cve && e.severity == Some(Severity::Critical))
            .count(),
        owasp_updates: events
            .iter()
            .filter(|e| e.source == MonitorSource::Owasp)
            .count(),
        adoption_signals: events
            .iter()
            .filter(|e| e.source == MonitorSource::Adoption)
            .count(),
        top_languages,
        severity_breakdown,
    }
}

fn generate_seo_keywords(events: &[MonitorEvent]) -> Vec<String> {
    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    for event in events {
        for tag in &event.tags {
            if !matches!(
                tag.as_str(),
                "test" | "mcp" | "repository" | "adoption" | "downloads"
            ) {
                *tag_counts.entry(tag.clone()).or_default() += 1;
            }
        }
    }

    let mut sorted: Vec<(String, usize)> = tag_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let mut keywords = vec![
        "MCP security".to_string(),
        "Model Context Protocol".to_string(),
        "MCP vulnerabilities".to_string(),
        "MCP server audit".to_string(),
        "OWASP MCP".to_string(),
    ];

    for (tag, _) in sorted.into_iter().take(10) {
        if !keywords.contains(&tag) {
            keywords.push(tag);
        }
    }

    keywords
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_event(
        title: &str,
        sev: Severity,
        source: MonitorSource,
        tags: Vec<&str>,
    ) -> MonitorEvent {
        MonitorEvent {
            id: format!("test-{}", title),
            source,
            title: title.to_string(),
            description: "Description".to_string(),
            url: "https://example.com".to_string(),
            discovered_at: Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap(),
            severity: Some(sev),
            tags: tags.into_iter().map(String::from).collect(),
            metadata: serde_json::json!({"language": "Rust"}),
        }
    }

    #[test]
    fn test_build_digest() {
        let events = vec![
            make_event(
                "CVE-001",
                Severity::Critical,
                MonitorSource::Cve,
                vec!["cve", "security"],
            ),
            make_event(
                "New repo",
                Severity::Low,
                MonitorSource::GitHub,
                vec!["repository", "rust"],
            ),
            make_event(
                "OWASP update",
                Severity::Medium,
                MonitorSource::Owasp,
                vec!["owasp", "commit"],
            ),
        ];

        let digest = build_digest(events, Some("2026-W13"), false);
        assert_eq!(digest.statistics.total_events, 3);
        assert_eq!(digest.statistics.critical_cves, 1);
        assert_eq!(digest.statistics.new_servers, 1);
        assert_eq!(digest.cve_events.len(), 1);
        assert_eq!(digest.github_events.len(), 1);
        assert_eq!(digest.owasp_events.len(), 1);
        assert!(digest.seo_keywords.is_empty());
    }

    #[test]
    fn test_build_digest_with_seo() {
        let events = vec![make_event(
            "Test",
            Severity::High,
            MonitorSource::Cve,
            vec!["cve"],
        )];
        let digest = build_digest(events, Some("2026-W13"), true);
        assert!(!digest.seo_keywords.is_empty());
        assert!(digest.seo_keywords.contains(&"MCP security".to_string()));
    }

    #[test]
    fn test_digest_period_last_week() {
        let period = DigestPeriod::last_week();
        assert!(period.start < period.end);
        assert!(period.end < Utc::now());
    }

    #[test]
    fn test_digest_period_from_iso_week() {
        let period = DigestPeriod::from_iso_week("2026-W13").unwrap();
        assert!(period.start < period.end);
        assert_eq!(period.start.weekday(), chrono::Weekday::Mon);
    }

    #[test]
    fn test_digest_period_iso_week_label() {
        let period = DigestPeriod::from_iso_week("2026-W13").unwrap();
        assert_eq!(period.iso_week_label(), "2026-W13");
    }

    #[test]
    fn test_empty_digest() {
        let digest = build_digest(Vec::new(), Some("2026-W13"), false);
        assert_eq!(digest.statistics.total_events, 0);
        assert!(digest.github_events.is_empty());
        assert!(digest.cve_events.is_empty());
    }

    #[test]
    fn test_statistics_severity_breakdown() {
        let events = vec![
            make_event("e1", Severity::Critical, MonitorSource::Cve, vec!["cve"]),
            make_event("e2", Severity::Critical, MonitorSource::Cve, vec!["cve"]),
            make_event(
                "e3",
                Severity::Low,
                MonitorSource::GitHub,
                vec!["repository"],
            ),
        ];
        let stats = compute_statistics(&events);
        assert_eq!(stats.severity_breakdown.len(), 2); // Critical=2, Low=1
        assert_eq!(stats.severity_breakdown[0], (Severity::Critical, 2));
    }

    #[test]
    fn test_statistics_top_languages() {
        let events = vec![
            make_event(
                "e1",
                Severity::Low,
                MonitorSource::GitHub,
                vec!["repository"],
            ),
            make_event(
                "e2",
                Severity::Low,
                MonitorSource::GitHub,
                vec!["repository"],
            ),
        ];
        let stats = compute_statistics(&events);
        assert!(!stats.top_languages.is_empty());
        assert_eq!(stats.top_languages[0].0, "Rust");
    }
}
