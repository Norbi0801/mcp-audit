//! JSON output formatter.

use crate::digest::WeeklyDigest;
use crate::monitors::MonitorEvent;
use crate::output::OutputFormatter;
use crate::rules::ScanReport;

/// Formats events, digests, and scan reports as pretty-printed JSON.
pub struct JsonFormatter;

impl OutputFormatter for JsonFormatter {
    fn format_events(&self, events: &[MonitorEvent]) -> String {
        serde_json::to_string_pretty(events).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }

    fn format_digest(&self, digest: &WeeklyDigest) -> String {
        serde_json::to_string_pretty(digest).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }

    fn format_scan_report(&self, report: &ScanReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn test_format_events_json() {
        let formatter = JsonFormatter;
        let events = vec![
            make_event("CVE-2026-001", Severity::Critical, MonitorSource::Cve),
            make_event("New repo", Severity::Low, MonitorSource::GitHub),
        ];
        let output = formatter.format_events(&events);

        assert!(output.contains("\"title\": \"CVE-2026-001\""));
        assert!(output.contains("\"severity\": \"Critical\""));

        // Should be valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_format_events_empty() {
        let formatter = JsonFormatter;
        let output = formatter.format_events(&[]);
        assert_eq!(output, "[]");
    }

    #[test]
    fn test_format_digest_json() {
        let formatter = JsonFormatter;
        let events = vec![
            make_event("CVE-1", Severity::Critical, MonitorSource::Cve),
            make_event("repo1", Severity::Low, MonitorSource::GitHub),
        ];
        let digest = crate::digest::build_digest(events, Some("2026-W13"), false);
        let output = formatter.format_digest(&digest);

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_object());
        // The digest has a period field with start/end, and statistics.
        assert!(parsed["period"].is_object());
        assert!(parsed["statistics"].is_object());
    }

    #[test]
    fn test_format_scan_report_json() {
        use crate::rules::ScanReport;
        use crate::scanner::ScanFinding;
        use chrono::Utc;

        let formatter = JsonFormatter;
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
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["findings"].is_array());
        assert_eq!(parsed["findings"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["servers_scanned"], 1);
    }
}
