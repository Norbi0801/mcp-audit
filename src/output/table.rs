//! Table output formatter using comfy-table with colored severity.

use crate::digest::WeeklyDigest;
use crate::monitors::{MonitorEvent, Severity};
use crate::output::{truncate, OutputFormatter};
use crate::rules::ScanReport;
use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Cell, Color, ContentArrangement, Table,
};

/// Formats events, digests, and scan reports as colored ASCII tables.
///
/// When `no_color` is true, both `colored` ANSI codes and comfy-table
/// cell foreground colors are suppressed.
pub struct TableFormatter {
    no_color: bool,
}

impl TableFormatter {
    /// Create a new table formatter with optional color suppression.
    pub fn new(no_color: bool) -> Self {
        Self { no_color }
    }

    /// Create a new [`Table`], applying `force_no_tty` when colors are disabled.
    fn make_table(&self) -> Table {
        let mut table = Table::new();
        if self.no_color {
            table.force_no_tty();
        }
        table
    }
}

impl OutputFormatter for TableFormatter {
    fn format_events(&self, events: &[MonitorEvent]) -> String {
        if events.is_empty() {
            return "No events found.".to_string();
        }
        self.build_events_table(events)
    }

    fn format_digest(&self, digest: &WeeklyDigest) -> String {
        let mut output = String::new();

        // Header.
        let start = digest.period.start.format("%Y-%m-%d");
        let end = digest.period.end.format("%Y-%m-%d");
        output.push_str(&format!(
            "{}\n",
            format!("MCP Weekly Digest: {} to {}", start, end).bold()
        ));
        output.push_str(&format!(
            "Generated: {}\n\n",
            digest.generated_at.format("%Y-%m-%d %H:%M UTC")
        ));

        // Statistics summary.
        output.push_str(&format!("{}\n", "Statistics".bold().underline()));
        output.push_str(&format!(
            "  Total events:     {}\n",
            digest.statistics.total_events
        ));
        output.push_str(&format!(
            "  New servers:      {}\n",
            digest.statistics.new_servers
        ));
        output.push_str(&format!(
            "  New CVEs:         {}\n",
            digest.statistics.new_cves
        ));
        if digest.statistics.critical_cves > 0 {
            output.push_str(&format!(
                "  Critical CVEs:    {}\n",
                format!("{}", digest.statistics.critical_cves).red().bold()
            ));
        }
        output.push_str(&format!(
            "  OWASP updates:    {}\n",
            digest.statistics.owasp_updates
        ));
        output.push_str(&format!(
            "  Adoption signals: {}\n",
            digest.statistics.adoption_signals
        ));

        // Top languages.
        if !digest.statistics.top_languages.is_empty() {
            output.push_str(&format!("\n{}\n", "Top Languages".bold().underline()));
            for (lang, count) in &digest.statistics.top_languages {
                output.push_str(&format!("  {}: {}\n", lang, count));
            }
        }

        // Severity breakdown.
        if !digest.statistics.severity_breakdown.is_empty() {
            output.push_str(&format!("\n{}\n", "Severity Breakdown".bold().underline()));
            for (sev, count) in &digest.statistics.severity_breakdown {
                let colored = colorize_severity(*sev);
                output.push_str(&format!("  {}: {}\n", colored, count));
            }
        }

        output.push('\n');

        // Events tables per source.
        let sections: &[(&str, &[MonitorEvent])] = &[
            ("GitHub Events", &digest.github_events),
            ("CVE Events", &digest.cve_events),
            ("OWASP Events", &digest.owasp_events),
            ("Adoption Events", &digest.adoption_events),
        ];

        for (title, events) in sections {
            if events.is_empty() {
                continue;
            }
            output.push_str(&format!("{}\n", title.bold().underline()));
            output.push_str(&self.build_events_table(events));
            output.push_str("\n\n");
        }

        output
    }

    fn format_scan_report(&self, report: &ScanReport) -> String {
        let mut output = String::new();

        // Header.
        output.push_str(&format!(
            "\n{}\n",
            "MCP Security Scan Report".bold().underline()
        ));
        output.push_str(&format!("  Source: {}\n", report.source));
        output.push_str(&format!("  Servers scanned: {}\n", report.servers_scanned));
        output.push_str(&format!("  Rules applied: {}\n", report.rules_applied));
        output.push_str(&format!(
            "  Scanned at: {}\n",
            report.scanned_at.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        if report.findings.is_empty() {
            output.push_str(&format!("\n  {} No issues found!\n", "✓".green().bold()));
            return output;
        }

        output.push_str(&format!(
            "\n  {} {} finding(s)\n",
            "!".red().bold(),
            report.findings.len()
        ));

        // Severity summary.
        let counts = report.severity_counts();
        for (sev, count) in &counts {
            let label = match sev {
                Severity::Critical => format!("{}", "CRITICAL".red().bold()),
                Severity::High => format!("{}", "HIGH".red()),
                Severity::Medium => format!("{}", "MEDIUM".yellow()),
                Severity::Low => format!("{}", "LOW".cyan()),
                Severity::Info => format!("{}", "INFO".white()),
            };
            output.push_str(&format!("    {} {}\n", label, count));
        }

        // Findings table.
        let mut table = self.make_table();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["Severity", "Rule", "Title"]);

        for finding in &report.findings {
            let sev_str = match finding.severity {
                Severity::Critical => "CRITICAL".red().bold().to_string(),
                Severity::High => "HIGH".red().to_string(),
                Severity::Medium => "MEDIUM".yellow().to_string(),
                Severity::Low => "LOW".cyan().to_string(),
                Severity::Info => "INFO".white().to_string(),
            };
            table.add_row(vec![
                sev_str,
                finding.rule_id.clone(),
                truncate(&finding.title, 60),
            ]);
        }

        output.push_str(&format!("\n{}\n", table));

        // Detailed findings.
        output.push_str(&format!("\n{}\n", "Details:".bold()));
        for (i, finding) in report.findings.iter().enumerate() {
            output.push_str(&format!(
                "\n  {}. [{}] {}\n",
                i + 1,
                finding.rule_id,
                finding.title
            ));
            output.push_str(&format!("     {}\n", finding.description));
        }

        output
    }
}

impl TableFormatter {
    /// Build a comfy-table for a list of events.
    fn build_events_table(&self, events: &[MonitorEvent]) -> String {
        let mut table = self.make_table();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_header(vec![
                Cell::new("Severity").fg(Color::White),
                Cell::new("Source").fg(Color::White),
                Cell::new("Title").fg(Color::White),
                Cell::new("Date").fg(Color::White),
                Cell::new("URL").fg(Color::White),
            ]);

        for event in events {
            let severity_str = event
                .severity
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| "—".to_string());

            let severity_color = severity_to_color(event.severity);

            let date = event.discovered_at.format("%Y-%m-%d").to_string();
            let title = truncate(&event.title, 60);
            let url = truncate(&event.url, 50);

            table.add_row(vec![
                Cell::new(&severity_str).fg(severity_color),
                Cell::new(event.source.to_string()),
                Cell::new(&title),
                Cell::new(&date),
                Cell::new(&url),
            ]);
        }

        table.to_string()
    }
}

/// Map a severity level to a comfy-table color.
fn severity_to_color(severity: Option<Severity>) -> Color {
    match severity {
        Some(Severity::Critical) => Color::Red,
        Some(Severity::High) => Color::DarkRed,
        Some(Severity::Medium) => Color::Yellow,
        Some(Severity::Low) => Color::Cyan,
        Some(Severity::Info) | None => Color::White,
    }
}

/// Return a colorized string for a severity using the colored crate.
fn colorize_severity(severity: Severity) -> String {
    let label = severity.to_string();
    match severity {
        Severity::Critical => format!("{}", label.red().bold()),
        Severity::High => format!("{}", label.red()),
        Severity::Medium => format!("{}", label.yellow()),
        Severity::Low => format!("{}", label.cyan()),
        Severity::Info => format!("{}", label.white()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::{DigestPeriod, DigestStatistics};
    use crate::monitors::{MonitorSource, Severity};
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
        let formatter = TableFormatter::new(false);
        let output = formatter.format_events(&[]);
        assert_eq!(output, "No events found.");
    }

    #[test]
    fn test_format_events_with_rows() {
        let formatter = TableFormatter::new(false);
        let events = vec![
            make_event("CVE-2026-001", Severity::Critical, MonitorSource::Cve),
            make_event("New MCP repo", Severity::Low, MonitorSource::GitHub),
        ];
        let output = formatter.format_events(&events);
        assert!(output.contains("CVE-2026-001"));
        assert!(output.contains("New MCP repo"));
        assert!(output.contains("Severity"));
        assert!(output.contains("Source"));
    }

    #[test]
    fn test_format_digest() {
        let formatter = TableFormatter::new(false);
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
                top_languages: vec![("Rust".to_string(), 1)],
                severity_breakdown: vec![(Severity::Critical, 1), (Severity::Low, 1)],
            },
            generated_at: Utc::now(),
            seo_keywords: vec!["MCP".to_string()],
        };

        let output = formatter.format_digest(&digest);
        assert!(output.contains("MCP Weekly Digest"));
        assert!(output.contains("Total events"));
        assert!(output.contains("New servers"));
        assert!(output.contains("Rust"));
        assert!(output.contains("GitHub Events"));
        assert!(output.contains("CVE Events"));
        // OWASP section should not appear since empty.
        assert!(!output.contains("OWASP Events"));
    }

    #[test]
    fn test_severity_to_color() {
        assert_eq!(severity_to_color(Some(Severity::Critical)), Color::Red);
        assert_eq!(severity_to_color(Some(Severity::High)), Color::DarkRed);
        assert_eq!(severity_to_color(Some(Severity::Medium)), Color::Yellow);
        assert_eq!(severity_to_color(Some(Severity::Low)), Color::Cyan);
        assert_eq!(severity_to_color(Some(Severity::Info)), Color::White);
        assert_eq!(severity_to_color(None), Color::White);
    }

    #[test]
    fn test_colorize_severity() {
        let critical = colorize_severity(Severity::Critical);
        assert!(!critical.is_empty());
        let info = colorize_severity(Severity::Info);
        assert!(!info.is_empty());
    }

    #[test]
    fn test_format_scan_report_table() {
        use crate::rules::ScanReport;
        use crate::scanner::ScanFinding;
        use chrono::Utc;

        let formatter = TableFormatter::new(false);
        let report = ScanReport {
            source: "test-config.json".to_string(),
            findings: vec![ScanFinding {
                rule_id: "MCP-07".into(),
                severity: Severity::Critical,
                title: "Shell command execution".into(),
                description: "Uses sh -c".into(),
            }],
            servers_scanned: 1,
            rules_applied: 10,
            per_server: vec![],
            scanned_at: Utc::now(),
        };

        let output = formatter.format_scan_report(&report);
        assert!(output.contains("MCP Security Scan Report"));
        assert!(output.contains("Servers scanned: 1"));
        assert!(output.contains("MCP-07"));
        assert!(output.contains("Details:"));
    }

    #[test]
    fn test_format_scan_report_no_issues() {
        use crate::rules::ScanReport;
        use chrono::Utc;

        let formatter = TableFormatter::new(false);
        let report = ScanReport {
            source: "test-config.json".to_string(),
            findings: vec![],
            servers_scanned: 1,
            rules_applied: 10,
            per_server: vec![],
            scanned_at: Utc::now(),
        };

        let output = formatter.format_scan_report(&report);
        assert!(output.contains("No issues found!"));
    }

    #[test]
    fn test_no_color_mode() {
        let formatter = TableFormatter::new(true);
        let events = vec![make_event("Test", Severity::Critical, MonitorSource::Cve)];
        let output = formatter.format_events(&events);
        // Should still contain the text, just without ANSI color codes from comfy-table.
        assert!(output.contains("Test"));
    }
}
