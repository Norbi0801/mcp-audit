//! Markdown output formatter — generates newsletter-ready markdown.

use crate::digest::WeeklyDigest;
use crate::monitors::{MonitorEvent, MonitorSource, Severity};
use crate::output::{truncate, OutputFormatter};
use crate::rules::ScanReport;

/// Formats events, digests, and scan reports as Markdown.
pub struct MarkdownFormatter;

impl OutputFormatter for MarkdownFormatter {
    fn format_events(&self, events: &[MonitorEvent]) -> String {
        if events.is_empty() {
            return "No events found.\n".to_string();
        }
        render_events_markdown(events)
    }

    fn format_scan_report(&self, report: &ScanReport) -> String {
        let mut md = String::new();

        md.push_str("# MCP Security Scan Report\n\n");
        md.push_str(&format!("**Source:** `{}`\n\n", report.source));
        md.push_str(&format!(
            "**Scanned:** {} | **Servers:** {} | **Rules:** {}\n\n",
            report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.servers_scanned,
            report.rules_applied,
        ));

        if report.findings.is_empty() {
            md.push_str("> **No issues found.** Configuration passed all security checks.\n");
            return md;
        }

        md.push_str(&format!(
            "**Total findings:** {}\n\n",
            report.findings.len()
        ));

        // Summary table.
        md.push_str("| Severity | Count |\n|----------|-------|\n");
        for (sev, count) in report.severity_counts() {
            md.push_str(&format!("| {} | {} |\n", sev, count));
        }
        md.push('\n');

        // Findings.
        md.push_str("## Findings\n\n");
        for finding in &report.findings {
            let badge = match finding.severity {
                Severity::Critical => "**CRITICAL**",
                Severity::High => "**HIGH**",
                Severity::Medium => "MEDIUM",
                Severity::Low => "LOW",
                Severity::Info => "INFO",
            };
            md.push_str(&format!(
                "### {} `{}` — {}\n\n{}\n\n",
                badge, finding.rule_id, finding.title, finding.description
            ));
        }

        md
    }

    fn format_digest(&self, digest: &WeeklyDigest) -> String {
        let mut md = String::new();

        let start = digest.period.start.format("%Y-%m-%d");
        let end = digest.period.end.format("%Y-%m-%d");

        // Title.
        md.push_str(&format!("# MCP Weekly Digest: {} to {}\n\n", start, end));
        md.push_str(&format!(
            "_Generated: {}_\n\n",
            digest.generated_at.format("%Y-%m-%d %H:%M UTC")
        ));

        // Statistics summary.
        md.push_str("## Summary\n\n");
        md.push_str("| Metric | Count |\n|--------|-------|\n");
        md.push_str(&format!(
            "| Total events | {} |\n",
            digest.statistics.total_events
        ));
        md.push_str(&format!(
            "| New MCP servers | {} |\n",
            digest.statistics.new_servers
        ));
        md.push_str(&format!("| New CVEs | {} |\n", digest.statistics.new_cves));
        md.push_str(&format!(
            "| Critical CVEs | {} |\n",
            digest.statistics.critical_cves
        ));
        md.push_str(&format!(
            "| OWASP updates | {} |\n",
            digest.statistics.owasp_updates
        ));
        md.push_str(&format!(
            "| Adoption signals | {} |\n",
            digest.statistics.adoption_signals
        ));
        md.push('\n');

        // Severity breakdown.
        if !digest.statistics.severity_breakdown.is_empty() {
            md.push_str("### Severity Breakdown\n\n");
            for (sev, count) in &digest.statistics.severity_breakdown {
                let badge = severity_badge(Some(*sev));
                md.push_str(&format!("- {} **{}**: {}\n", badge, sev, count));
            }
            md.push('\n');
        }

        // Top languages.
        if !digest.statistics.top_languages.is_empty() {
            md.push_str("### Top Languages\n\n");
            for (lang, count) in &digest.statistics.top_languages {
                md.push_str(&format!("- **{}**: {} repos\n", lang, count));
            }
            md.push('\n');
        }

        // Events per source.
        let sections: &[(&str, &[MonitorEvent])] = &[
            ("CVE Vulnerabilities", &digest.cve_events),
            ("GitHub Ecosystem", &digest.github_events),
            ("OWASP Updates", &digest.owasp_events),
            ("Adoption Signals", &digest.adoption_events),
        ];

        for (title, events) in sections {
            if events.is_empty() {
                continue;
            }

            md.push_str(&format!("## {} ({})\n\n", title, events.len()));

            for event in *events {
                let badge = severity_badge(event.severity);

                md.push_str(&format!("### {} {}\n\n", badge, event.title));
                md.push_str(&format!(
                    "- **Date:** {}\n",
                    event.discovered_at.format("%Y-%m-%d")
                ));
                md.push_str(&format!("- **URL:** {}\n", event.url));

                if !event.tags.is_empty() {
                    let tags: Vec<String> = event.tags.iter().map(|t| format!("`{}`", t)).collect();
                    md.push_str(&format!("- **Tags:** {}\n", tags.join(", ")));
                }

                if !event.description.is_empty() {
                    let desc = truncate(&event.description, 300);
                    md.push_str(&format!("\n> {}\n", desc));
                }

                md.push('\n');
            }
        }

        // SEO metadata section.
        if !digest.seo_keywords.is_empty() {
            md.push_str("---\n\n");
            md.push_str("## SEO Metadata\n\n");
            md.push_str(&format!(
                "**Keywords:** {}\n\n",
                digest.seo_keywords.join(", ")
            ));
            md.push_str(&format!(
                "**Description:** MCP ecosystem weekly digest covering {} events \
                 from {} to {}, including {} new CVEs and {} new MCP servers.\n",
                digest.statistics.total_events,
                start,
                end,
                digest.statistics.new_cves,
                digest.statistics.new_servers,
            ));
        }

        md
    }
}

/// Render a list of events as Markdown (used by format_events).
fn render_events_markdown(events: &[MonitorEvent]) -> String {
    let mut md = String::new();

    md.push_str("# MCP Ecosystem Monitor Report\n\n");
    md.push_str(&format!(
        "_Generated: {}_\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC")
    ));

    // Summary.
    let total = events.len();
    let critical = events
        .iter()
        .filter(|e| e.severity == Some(Severity::Critical))
        .count();
    let high = events
        .iter()
        .filter(|e| e.severity == Some(Severity::High))
        .count();

    md.push_str(&format!("**Total events:** {}\n", total));
    if critical > 0 {
        md.push_str(&format!("**Critical:** {}\n", critical));
    }
    if high > 0 {
        md.push_str(&format!("**High:** {}\n", high));
    }
    md.push('\n');

    // Group by source.
    let sources = [
        MonitorSource::Cve,
        MonitorSource::GitHub,
        MonitorSource::Owasp,
        MonitorSource::Adoption,
    ];

    for source in &sources {
        let source_events: Vec<&MonitorEvent> =
            events.iter().filter(|e| &e.source == source).collect();
        if source_events.is_empty() {
            continue;
        }

        md.push_str(&format!("## {} ({})\n\n", source, source_events.len()));

        for event in source_events {
            let badge = severity_badge(event.severity);

            md.push_str(&format!("### {} {}\n\n", badge, event.title));
            md.push_str(&format!(
                "- **Date:** {}\n",
                event.discovered_at.format("%Y-%m-%d")
            ));
            md.push_str(&format!("- **URL:** {}\n", event.url));

            if !event.tags.is_empty() {
                let tags: Vec<String> = event.tags.iter().map(|t| format!("`{}`", t)).collect();
                md.push_str(&format!("- **Tags:** {}\n", tags.join(", ")));
            }

            if !event.description.is_empty() {
                let desc = truncate(&event.description, 300);
                md.push_str(&format!("\n> {}\n", desc));
            }

            md.push('\n');
        }
    }

    md
}

/// Return a text badge for a severity level.
fn severity_badge(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(Severity::Critical) => "CRITICAL",
        Some(Severity::High) => "HIGH",
        Some(Severity::Medium) => "MEDIUM",
        Some(Severity::Low) => "LOW",
        Some(Severity::Info) | None => "INFO",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{DigestPeriod, DigestStatistics};
    use chrono::Utc;

    fn make_event(title: &str, severity: Severity, source: MonitorSource) -> MonitorEvent {
        MonitorEvent {
            id: format!("test-{}", title),
            source,
            title: title.to_string(),
            description: "Test description".to_string(),
            url: "https://example.com".to_string(),
            discovered_at: Utc::now(),
            severity: Some(severity),
            tags: vec!["test".to_string()],
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn test_format_events_empty() {
        let formatter = MarkdownFormatter;
        let output = formatter.format_events(&[]);
        assert_eq!(output, "No events found.\n");
    }

    #[test]
    fn test_format_events_markdown() {
        let formatter = MarkdownFormatter;
        let events = vec![
            make_event("Critical CVE", Severity::Critical, MonitorSource::Cve),
            make_event("OWASP Update", Severity::Medium, MonitorSource::Owasp),
        ];
        let output = formatter.format_events(&events);
        assert!(output.contains("# MCP Ecosystem Monitor Report"));
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("Critical CVE"));
        assert!(output.contains("OWASP Update"));
    }

    #[test]
    fn test_format_digest_markdown() {
        let formatter = MarkdownFormatter;
        let digest = WeeklyDigest {
            period: DigestPeriod::last_week(),
            github_events: vec![make_event("repo1", Severity::Low, MonitorSource::GitHub)],
            cve_events: vec![make_event("CVE-1", Severity::Critical, MonitorSource::Cve)],
            owasp_events: vec![],
            adoption_events: vec![],
            statistics: DigestStatistics {
                total_events: 2,
                new_servers: 1,
                new_cves: 1,
                critical_cves: 1,
                owasp_updates: 0,
                adoption_signals: 0,
                top_languages: vec![("TypeScript".to_string(), 3), ("Rust".to_string(), 1)],
                severity_breakdown: vec![(Severity::Critical, 1), (Severity::Low, 1)],
            },
            generated_at: Utc::now(),
            seo_keywords: vec!["MCP".to_string(), "MCP security".to_string()],
        };

        let output = formatter.format_digest(&digest);
        assert!(output.contains("# MCP Weekly Digest"));
        assert!(output.contains("## Summary"));
        assert!(output.contains("| Total events | 2 |"));
        assert!(output.contains("| Critical CVEs | 1 |"));
        assert!(output.contains("### Severity Breakdown"));
        assert!(output.contains("### Top Languages"));
        assert!(output.contains("TypeScript"));
        assert!(output.contains("## CVE Vulnerabilities"));
        assert!(output.contains("## GitHub Ecosystem"));
        // OWASP section should not appear since empty.
        assert!(!output.contains("## OWASP Updates"));
        // SEO section.
        assert!(output.contains("## SEO Metadata"));
        assert!(output.contains("MCP security"));
    }

    #[test]
    fn test_severity_badge() {
        assert_eq!(severity_badge(Some(Severity::Critical)), "CRITICAL");
        assert_eq!(severity_badge(Some(Severity::Info)), "INFO");
        assert_eq!(severity_badge(None), "INFO");
    }

    #[test]
    fn test_format_scan_report_markdown() {
        use crate::rules::ScanReport;
        use crate::scanner::ScanFinding;
        use chrono::Utc;

        let formatter = MarkdownFormatter;
        let report = ScanReport {
            source: "test-config.json".to_string(),
            findings: vec![
                ScanFinding {
                    rule_id: "MCP-07".into(),
                    severity: Severity::Critical,
                    title: "Shell command execution".into(),
                    description: "Uses sh -c".into(),
                },
                ScanFinding {
                    rule_id: "MCP-04".into(),
                    severity: Severity::High,
                    title: "Hardcoded API key".into(),
                    description: "Contains secret".into(),
                },
            ],
            servers_scanned: 2,
            rules_applied: 10,
            per_server: vec![],
            scanned_at: Utc::now(),
        };

        let output = formatter.format_scan_report(&report);
        assert!(output.contains("# MCP Security Scan Report"));
        assert!(output.contains("**Source:** `test-config.json`"));
        assert!(output.contains("**Total findings:** 2"));
        assert!(output.contains("## Findings"));
        assert!(output.contains("**CRITICAL** `MCP-07`"));
        assert!(output.contains("**HIGH** `MCP-04`"));
    }

    #[test]
    fn test_format_scan_report_no_findings() {
        use crate::rules::ScanReport;
        use chrono::Utc;

        let formatter = MarkdownFormatter;
        let report = ScanReport {
            source: "clean.json".to_string(),
            findings: vec![],
            servers_scanned: 1,
            rules_applied: 10,
            per_server: vec![],
            scanned_at: Utc::now(),
        };

        let output = formatter.format_scan_report(&report);
        assert!(output.contains("No issues found."));
        assert!(!output.contains("## Findings"));
    }

    #[test]
    fn test_digest_no_seo_keywords() {
        let formatter = MarkdownFormatter;
        let digest = WeeklyDigest {
            period: DigestPeriod::last_week(),
            github_events: vec![],
            cve_events: vec![],
            owasp_events: vec![],
            adoption_events: vec![],
            statistics: DigestStatistics {
                total_events: 0,
                new_servers: 0,
                new_cves: 0,
                critical_cves: 0,
                owasp_updates: 0,
                adoption_signals: 0,
                top_languages: vec![],
                severity_breakdown: vec![],
            },
            generated_at: Utc::now(),
            seo_keywords: vec![],
        };

        let output = formatter.format_digest(&digest);
        assert!(!output.contains("## SEO Metadata"));
    }
}
