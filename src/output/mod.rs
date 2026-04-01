//! Output formatters — renders MonitorEvents, digests, and scan reports as
//! JSON, human-readable tables (comfy-table), Markdown, or SARIF.

mod json;
mod markdown;
pub mod sarif;
mod table;

use crate::config::OutputFormat;
use crate::digest::WeeklyDigest;
use crate::monitors::MonitorEvent;
use crate::rules::ScanReport;

/// Trait for formatting monitor events, digests, and scan reports.
///
/// Each output format (JSON, Table, Markdown, SARIF) implements this trait
/// so the CLI can dispatch formatting through a single interface.
pub trait OutputFormatter {
    /// Format a slice of events into a displayable string.
    fn format_events(&self, events: &[MonitorEvent]) -> String;

    /// Format a full weekly digest into a displayable string.
    fn format_digest(&self, digest: &WeeklyDigest) -> String;

    /// Format a security scan report into a displayable string.
    fn format_scan_report(&self, report: &ScanReport) -> String;
}

/// Create a formatter for the given output format.
///
/// When `no_color` is true, the table formatter disables ANSI color codes
/// in both the `colored` crate output and comfy-table cell coloring.
pub fn create_formatter(format: OutputFormat, no_color: bool) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Json => Box::new(json::JsonFormatter),
        OutputFormat::Table => Box::new(table::TableFormatter::new(no_color)),
        OutputFormat::Markdown => Box::new(markdown::MarkdownFormatter),
        OutputFormat::Sarif => Box::new(sarif::SarifFormatter),
    }
}

/// Convenience: render events in the given format (delegates to the formatter trait).
pub fn render_events(events: &[MonitorEvent], format: OutputFormat) -> String {
    create_formatter(format, false).format_events(events)
}

/// Convenience: render a digest in the given format.
pub fn render_digest(digest: &WeeklyDigest, format: OutputFormat) -> String {
    create_formatter(format, false).format_digest(digest)
}

/// Render a summary line for terminal output (used by the monitor command).
pub fn render_summary(events: &[MonitorEvent]) -> String {
    use crate::monitors::Severity;
    use colored::Colorize;

    if events.is_empty() {
        return format!("{}", "No new events discovered.".dimmed());
    }

    let total = events.len();
    let critical = events
        .iter()
        .filter(|e| e.severity == Some(Severity::Critical))
        .count();
    let high = events
        .iter()
        .filter(|e| e.severity == Some(Severity::High))
        .count();
    let medium = events
        .iter()
        .filter(|e| e.severity == Some(Severity::Medium))
        .count();

    let mut parts = vec![format!("{} events found", total)];
    if critical > 0 {
        parts.push(format!("{}", format!("{} critical", critical).red().bold()));
    }
    if high > 0 {
        parts.push(format!("{}", format!("{} high", high).red()));
    }
    if medium > 0 {
        parts.push(format!("{}", format!("{} medium", medium).yellow()));
    }

    parts.join(" | ")
}

/// Render a scan report in the given format.
///
/// Delegates to the appropriate [`OutputFormatter`] implementation.
/// Pass `no_color = false` for default behavior; the convenience signature
/// exists so callers that don't track color state can still use the function.
pub fn render_scan_report(report: &ScanReport, format: OutputFormat) -> String {
    render_scan_report_with_opts(report, format, false)
}

/// Render a scan report with explicit color control.
pub fn render_scan_report_with_opts(
    report: &ScanReport,
    format: OutputFormat,
    no_color: bool,
) -> String {
    create_formatter(format, no_color).format_scan_report(report)
}

/// Render a scan summary line for terminal output.
///
/// Displays: X passed, Y failed (with per-server breakdown).
pub fn render_scan_summary(report: &ScanReport) -> String {
    use crate::monitors::Severity;
    use colored::Colorize;

    let mut output = String::new();

    output.push_str(&format!("\n{}\n", "Scan Summary".bold().underline()));

    let passed = report.per_server.iter().filter(|s| s.passed).count();
    let failed = report.per_server.iter().filter(|s| !s.passed).count();

    output.push_str(&format!(
        "  {} server(s) scanned, {} rule(s) applied\n",
        report.servers_scanned, report.rules_applied
    ));

    if passed > 0 {
        output.push_str(&format!("  {} {} passed\n", "✓".green().bold(), passed));
    }
    if failed > 0 {
        output.push_str(&format!("  {} {} failed\n", "✗".red().bold(), failed));
    }

    // Severity breakdown if there are findings.
    if !report.findings.is_empty() {
        output.push_str(&format!(
            "\n  {} total finding(s):\n",
            report.findings.len()
        ));
        for (sev, count) in report.severity_counts() {
            let label = match sev {
                Severity::Critical => format!("{}", "CRITICAL".red().bold()),
                Severity::High => format!("{}", "HIGH".red()),
                Severity::Medium => format!("{}", "MEDIUM".yellow()),
                Severity::Low => format!("{}", "LOW".cyan()),
                Severity::Info => format!("{}", "INFO".white()),
            };
            output.push_str(&format!("    {} {}\n", label, count));
        }
    }

    // Per-server breakdown.
    if report.per_server.len() > 1 {
        output.push_str(&format!("\n  {}:\n", "Per-server results".dimmed()));
        for sr in &report.per_server {
            let icon = if sr.passed {
                "✓".green().bold().to_string()
            } else {
                "✗".red().bold().to_string()
            };
            let detail = if sr.passed {
                "clean".green().to_string()
            } else {
                format!("{} finding(s)", sr.finding_count).red().to_string()
            };
            output.push_str(&format!("    {} {} — {}\n", icon, sr.name, detail));
        }
    }

    output
}

/// Truncate a string to at most `max` characters, appending "..." if truncated.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::{MonitorEvent, MonitorSource, Severity};
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
    fn test_create_formatter_json() {
        let formatter = create_formatter(OutputFormat::Json, false);
        let events = vec![make_event("Test", Severity::High, MonitorSource::Cve)];
        let output = formatter.format_events(&events);
        assert!(output.contains("\"title\": \"Test\""));
    }

    #[test]
    fn test_create_formatter_table() {
        let formatter = create_formatter(OutputFormat::Table, false);
        let events = vec![make_event("Test", Severity::High, MonitorSource::Cve)];
        let output = formatter.format_events(&events);
        assert!(output.contains("Test"));
        assert!(output.contains("Severity"));
    }

    #[test]
    fn test_create_formatter_markdown() {
        let formatter = create_formatter(OutputFormat::Markdown, false);
        let events = vec![make_event("Test", Severity::High, MonitorSource::Cve)];
        let output = formatter.format_events(&events);
        assert!(output.contains("# MCP Ecosystem Monitor Report"));
        assert!(output.contains("Test"));
    }

    #[test]
    fn test_render_events_convenience() {
        let events = vec![make_event("Test", Severity::Low, MonitorSource::GitHub)];
        let json = render_events(&events, OutputFormat::Json);
        assert!(json.contains("\"title\": \"Test\""));
    }

    #[test]
    fn test_render_summary() {
        let events = vec![
            make_event("e1", Severity::Critical, MonitorSource::Cve),
            make_event("e2", Severity::High, MonitorSource::GitHub),
            make_event("e3", Severity::Low, MonitorSource::Adoption),
        ];
        let summary = render_summary(&events);
        assert!(summary.contains("3 events found"));
    }

    #[test]
    fn test_render_summary_empty() {
        let summary = render_summary(&[]);
        assert!(summary.contains("No new events"));
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long text", 10), "a very lon...");
    }
}
