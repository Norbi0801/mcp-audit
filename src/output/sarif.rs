//! SARIF v2.1.0 output formatter for GitHub Code Scanning integration.
//!
//! Produces [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! (Static Analysis Results Interchange Format) JSON that can be uploaded to
//! GitHub Code Scanning, Azure DevOps, or any tool that consumes SARIF.
//!
//! Two entry points:
//! - [`SarifFormatter`] — implements [`OutputFormatter`] to convert
//!   `MonitorEvent`s and digests (the latter is a no-op).
//! - [`findings_to_sarif`] — standalone function that converts a slice of
//!   [`Finding`]s (the primary scan output) into a SARIF JSON string.

use serde::Serialize;
use std::collections::HashMap;

use crate::digest::WeeklyDigest;
use crate::monitors::{MonitorEvent, Severity};
use crate::output::OutputFormatter;
use crate::rules::ScanReport;
use crate::scanner::ScanFinding;

// ── Constants ──────────────────────────────────────────────────────────

const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "mcp-audit";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const TOOL_INFO_URI: &str = "https://github.com/mcp-audit/mcp-audit";

// ── Finding (forward-compatible with the planned rules module) ─────────

/// A single finding from a security scan.
///
/// This mirrors the `Finding` struct that the `rules` module will expose.
/// Once `crate::rules::Finding` exists, this type can be replaced with a
/// re-export or a `From` impl.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub server_name: Option<String>,
    pub location: Option<String>,
    pub remediation: Option<String>,
}

// ── SARIF JSON model ───────────────────────────────────────────────────

/// Top-level SARIF log object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    /// JSON Schema URI for validation.
    #[serde(rename = "$schema")]
    schema: String,
    /// SARIF specification version.
    version: String,
    /// Array of runs; typically one per invocation.
    runs: Vec<SarifRun>,
}

/// A single analysis run (one invocation of the tool).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    invocations: Vec<SarifInvocation>,
}

/// The tool that performed the analysis.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifTool {
    driver: SarifToolComponent,
}

/// Tool component (driver) with version info and rule definitions.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifToolComponent {
    name: String,
    version: String,
    semantic_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    information_uri: Option<String>,
    rules: Vec<SarifReportingDescriptor>,
}

/// A rule (reporting descriptor) in the SARIF tool component.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReportingDescriptor {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    short_description: SarifMessage,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_description: Option<SarifMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    help: Option<SarifMessage>,
    default_configuration: SarifRuleConfiguration,
}

/// Default configuration for a rule, carrying the severity level.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRuleConfiguration {
    level: String,
}

/// A single analysis result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: String,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

/// A SARIF location, comprising a physical location within an artifact.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

/// Physical location — artifact URI and optional region.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<SarifRegion>,
}

/// Artifact URI reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri_base_id: Option<String>,
}

/// Source region (line/column). Optional for MCP scanner results since
/// findings often refer to configuration files rather than source ranges.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
}

/// Reusable SARIF message object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifMessage {
    text: String,
}

/// Invocation metadata (execution status).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifInvocation {
    execution_successful: bool,
}

// ── Severity mapping ───────────────────────────────────────────────────

/// Map [`Severity`] to the SARIF `level` string.
///
/// SARIF defines three result levels: `"error"`, `"warning"`, and `"note"`.
/// - Critical / High  -> `"error"`
/// - Medium           -> `"warning"`
/// - Low / Info       -> `"note"`
fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Map an optional [`Severity`] (as used on `MonitorEvent`) to a SARIF level.
fn optional_severity_to_sarif_level(severity: Option<Severity>) -> &'static str {
    match severity {
        Some(s) => severity_to_sarif_level(s),
        None => "note",
    }
}

// ── Helper: build SARIF log from parts ─────────────────────────────────

/// Build a complete [`SarifLog`] from pre-computed rules and results.
fn build_sarif_log(rules: Vec<SarifReportingDescriptor>, results: Vec<SarifResult>) -> SarifLog {
    SarifLog {
        schema: SARIF_SCHEMA.to_string(),
        version: SARIF_VERSION.to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifToolComponent {
                    name: TOOL_NAME.to_string(),
                    version: TOOL_VERSION.to_string(),
                    semantic_version: TOOL_VERSION.to_string(),
                    information_uri: Some(TOOL_INFO_URI.to_string()),
                    rules,
                },
            },
            results,
            invocations: vec![SarifInvocation {
                execution_successful: true,
            }],
        }],
    }
}

// ── Public API: Finding -> SARIF ───────────────────────────────────────

/// Format scan findings as SARIF v2.1.0 JSON.
///
/// This is the **primary** use case for SARIF output — it converts the
/// structured findings from the rule engine into GitHub-Code-Scanning-
/// compatible SARIF.
///
/// `source_path` is used as the artifact URI when a finding has no explicit
/// `location`. Pass `None` to omit locations entirely.
pub fn findings_to_sarif(findings: &[Finding], source_path: Option<&str>) -> String {
    // Deduplicate rules — each unique rule_id gets one descriptor.
    let mut rule_map: HashMap<String, (usize, &Finding)> = HashMap::new();
    let mut rule_order: Vec<String> = Vec::new();

    for finding in findings {
        if !rule_map.contains_key(&finding.rule_id) {
            let idx = rule_order.len();
            rule_map.insert(finding.rule_id.clone(), (idx, finding));
            rule_order.push(finding.rule_id.clone());
        }
    }

    // Build rule descriptors.
    let rules: Vec<SarifReportingDescriptor> = rule_order
        .iter()
        .map(|rule_id| {
            let (_, finding) = &rule_map[rule_id];
            SarifReportingDescriptor {
                id: finding.rule_id.clone(),
                name: Some(finding.rule_name.clone()),
                short_description: SarifMessage {
                    text: finding.title.clone(),
                },
                full_description: Some(SarifMessage {
                    text: finding.description.clone(),
                }),
                help: finding
                    .remediation
                    .as_ref()
                    .map(|r| SarifMessage { text: r.clone() }),
                default_configuration: SarifRuleConfiguration {
                    level: severity_to_sarif_level(finding.severity).to_string(),
                },
            }
        })
        .collect();

    // Build results.
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let rule_index = rule_map.get(&f.rule_id).map(|(idx, _)| *idx);

            // Build location from the finding's explicit location or the
            // provided source_path fallback.
            let uri = f.location.as_deref().or(source_path).map(|s| s.to_string());

            let locations = match uri {
                Some(u) => vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: u,
                            uri_base_id: Some("%SRCROOT%".to_string()),
                        },
                        region: Some(SarifRegion {
                            start_line: 1,
                            start_column: None,
                        }),
                    },
                }],
                None => Vec::new(),
            };

            // Build a descriptive message including the server name when
            // available.
            let message_text = match &f.server_name {
                Some(name) => format!("[{}] {}: {}", name, f.title, f.description),
                None => format!("{}: {}", f.title, f.description),
            };

            SarifResult {
                rule_id: f.rule_id.clone(),
                rule_index,
                level: severity_to_sarif_level(f.severity).to_string(),
                message: SarifMessage { text: message_text },
                locations,
            }
        })
        .collect();

    let log = build_sarif_log(rules, results);
    serde_json::to_string_pretty(&log).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

// ── OutputFormatter impl (MonitorEvent -> SARIF) ───────────────────────

/// SARIF output formatter for [`MonitorEvent`]s.
///
/// Converts monitor events into SARIF results so they can be consumed by
/// the same tooling that handles scan findings. Each event becomes a single
/// SARIF result keyed by its source monitor.
pub struct SarifFormatter;

impl OutputFormatter for SarifFormatter {
    fn format_events(&self, events: &[MonitorEvent]) -> String {
        let mut rule_map: HashMap<String, usize> = HashMap::new();
        let mut rule_order: Vec<String> = Vec::new();
        let mut rules: Vec<SarifReportingDescriptor> = Vec::new();

        // One SARIF rule per event source.
        for event in events {
            let rule_id = format!("mcp-monitor/{}", event.source.to_string().to_lowercase());
            if !rule_map.contains_key(&rule_id) {
                let idx = rule_order.len();
                rule_map.insert(rule_id.clone(), idx);
                rule_order.push(rule_id.clone());
                rules.push(SarifReportingDescriptor {
                    id: rule_id,
                    name: Some(format!("MCP Monitor: {}", event.source)),
                    short_description: SarifMessage {
                        text: format!("Events from the {} ecosystem monitor", event.source),
                    },
                    full_description: None,
                    help: None,
                    default_configuration: SarifRuleConfiguration {
                        level: optional_severity_to_sarif_level(event.severity).to_string(),
                    },
                });
            }
        }

        let results: Vec<SarifResult> = events
            .iter()
            .map(|e| {
                let rule_id = format!("mcp-monitor/{}", e.source.to_string().to_lowercase());
                let rule_index = rule_map.get(&rule_id).copied();

                let locations = if e.url.is_empty() {
                    Vec::new()
                } else {
                    vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: e.url.clone(),
                                uri_base_id: None,
                            },
                            region: None,
                        },
                    }]
                };

                SarifResult {
                    rule_id,
                    rule_index,
                    level: optional_severity_to_sarif_level(e.severity).to_string(),
                    message: SarifMessage {
                        text: format!("{}: {}", e.title, e.description),
                    },
                    locations,
                }
            })
            .collect();

        let log = build_sarif_log(rules, results);
        serde_json::to_string_pretty(&log).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
    }

    fn format_digest(&self, _digest: &WeeklyDigest) -> String {
        // SARIF is not a meaningful format for digest output.
        // Return a minimal valid JSON object.
        "{}".to_string()
    }

    fn format_scan_report(&self, report: &ScanReport) -> String {
        scan_report_to_sarif(report)
    }
}

// ── ScanReport -> SARIF conversion ────────────────────────────────────

/// Convert a [`ScanReport`] (from the rule engine) into SARIF v2.1.0 JSON.
///
/// This is the recommended function for outputting scan results as SARIF
/// for GitHub Code Scanning or CI integration.
pub fn scan_report_to_sarif(report: &ScanReport) -> String {
    let findings: Vec<Finding> = report
        .findings
        .iter()
        .map(|f| scan_finding_to_finding(f, &report.source))
        .collect();
    findings_to_sarif(&findings, Some(&report.source))
}

/// Convert a [`ScanFinding`] into a [`Finding`] for SARIF output.
fn scan_finding_to_finding(f: &ScanFinding, source: &str) -> Finding {
    Finding {
        rule_id: f.rule_id.clone(),
        rule_name: f.rule_id.clone(),
        severity: f.severity,
        title: f.title.clone(),
        description: f.description.clone(),
        server_name: extract_server_name(&f.title),
        location: Some(source.to_string()),
        remediation: None,
    }
}

/// Try to extract a server name from a finding title like "... in server 'foo'".
fn extract_server_name(title: &str) -> Option<String> {
    let marker = "server '";
    if let Some(start) = title.find(marker) {
        let rest = &title[start + marker.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::{MonitorSource, Severity};
    use chrono::Utc;

    /// Helper: create a [`Finding`] with the given parameters.
    fn make_finding(
        rule_id: &str,
        severity: Severity,
        server_name: Option<&str>,
        location: Option<&str>,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: format!("{}-name", rule_id),
            severity,
            title: format!("Title for {}", rule_id),
            description: format!("Description for {}", rule_id),
            server_name: server_name.map(String::from),
            location: location.map(String::from),
            remediation: Some(format!("Fix for {}", rule_id)),
        }
    }

    /// Helper: create a [`MonitorEvent`].
    fn make_event(title: &str, severity: Severity, source: MonitorSource) -> MonitorEvent {
        MonitorEvent {
            id: format!("test-{}", title),
            source,
            title: title.to_string(),
            description: "Test event description".to_string(),
            url: "https://example.com/event".to_string(),
            discovered_at: Utc::now(),
            severity: Some(severity),
            tags: vec!["test".to_string()],
            metadata: serde_json::json!({}),
        }
    }

    // ── findings_to_sarif tests ────────────────────────────────────────

    #[test]
    fn test_empty_findings_produce_valid_sarif() {
        let output = findings_to_sarif(&[], None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["$schema"], SARIF_SCHEMA);
        assert_eq!(parsed["version"], SARIF_VERSION);
        assert!(parsed["runs"].is_array());
        assert_eq!(parsed["runs"].as_array().unwrap().len(), 1);

        let run = &parsed["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], TOOL_NAME);
        assert_eq!(run["results"].as_array().unwrap().len(), 0);
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_findings_map_to_correct_severity_levels() {
        let findings = vec![
            make_finding("CRIT-001", Severity::Critical, None, None),
            make_finding("HIGH-001", Severity::High, None, None),
            make_finding("MED-001", Severity::Medium, None, None),
            make_finding("LOW-001", Severity::Low, None, None),
            make_finding("INFO-001", Severity::Info, None, None),
        ];

        let output = findings_to_sarif(&findings, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = parsed["runs"][0]["results"].as_array().unwrap();

        assert_eq!(results[0]["level"], "error"); // Critical
        assert_eq!(results[1]["level"], "error"); // High
        assert_eq!(results[2]["level"], "warning"); // Medium
        assert_eq!(results[3]["level"], "note"); // Low
        assert_eq!(results[4]["level"], "note"); // Info
    }

    #[test]
    fn test_sarif_output_is_valid_json() {
        let findings = vec![
            make_finding(
                "MCP-001",
                Severity::High,
                Some("my-server"),
                Some("config.json"),
            ),
            make_finding("MCP-002", Severity::Medium, None, None),
        ];

        let output = findings_to_sarif(&findings, Some("mcp-config.json"));
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Top-level structure.
        assert!(parsed.is_object());
        assert!(parsed["$schema"].is_string());
        assert!(parsed["version"].is_string());
        assert!(parsed["runs"].is_array());
    }

    #[test]
    fn test_source_path_appears_in_location() {
        let findings = vec![make_finding("MCP-001", Severity::High, None, None)];
        let output = findings_to_sarif(&findings, Some("claude_desktop_config.json"));
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let locations = parsed["runs"][0]["results"][0]["locations"]
            .as_array()
            .unwrap();
        assert_eq!(locations.len(), 1);
        assert_eq!(
            locations[0]["physicalLocation"]["artifactLocation"]["uri"],
            "claude_desktop_config.json"
        );
    }

    #[test]
    fn test_finding_explicit_location_overrides_source_path() {
        let findings = vec![make_finding(
            "MCP-001",
            Severity::High,
            None,
            Some("specific/path.json"),
        )];
        let output = findings_to_sarif(&findings, Some("fallback.json"));
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let uri = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"];
        assert_eq!(uri, "specific/path.json");
    }

    #[test]
    fn test_no_location_when_both_absent() {
        let findings = vec![make_finding("MCP-001", Severity::Low, None, None)];
        let output = findings_to_sarif(&findings, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let locations = parsed["runs"][0]["results"][0]["locations"]
            .as_array()
            .unwrap();
        assert!(locations.is_empty());
    }

    #[test]
    fn test_rules_deduplicated() {
        // Two findings with the same rule_id should produce one rule descriptor.
        let findings = vec![
            make_finding("MCP-001", Severity::High, Some("server-a"), None),
            make_finding("MCP-001", Severity::High, Some("server-b"), None),
        ];
        let output = findings_to_sarif(&findings, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        // Both results point to the same rule index.
        assert_eq!(results[0]["ruleIndex"], 0);
        assert_eq!(results[1]["ruleIndex"], 0);
    }

    #[test]
    fn test_tool_metadata() {
        let output = findings_to_sarif(&[], None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let driver = &parsed["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], TOOL_NAME);
        assert_eq!(driver["version"], TOOL_VERSION);
        assert_eq!(driver["semanticVersion"], TOOL_VERSION);
        assert_eq!(driver["informationUri"], TOOL_INFO_URI);
    }

    #[test]
    fn test_remediation_in_rule_help() {
        let findings = vec![make_finding("MCP-001", Severity::Medium, None, None)];
        let output = findings_to_sarif(&findings, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["help"]["text"], "Fix for MCP-001");
    }

    #[test]
    fn test_finding_without_remediation_omits_help() {
        let mut finding = make_finding("MCP-001", Severity::Low, None, None);
        finding.remediation = None;

        let output = findings_to_sarif(&[finding], None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rule = &parsed["runs"][0]["tool"]["driver"]["rules"][0];
        assert!(rule.get("help").is_none());
    }

    #[test]
    fn test_server_name_in_message() {
        let findings = vec![make_finding(
            "MCP-001",
            Severity::High,
            Some("my-mcp-server"),
            None,
        )];
        let output = findings_to_sarif(&findings, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let msg = parsed["runs"][0]["results"][0]["message"]["text"]
            .as_str()
            .unwrap();
        assert!(msg.contains("[my-mcp-server]"));
    }

    #[test]
    fn test_invocation_present() {
        let output = findings_to_sarif(&[], None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let invocations = parsed["runs"][0]["invocations"].as_array().unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0]["executionSuccessful"], true);
    }

    // ── OutputFormatter (events) tests ─────────────────────────────────

    #[test]
    fn test_events_to_sarif_conversion() {
        let formatter = SarifFormatter;
        let events = vec![
            make_event("CVE-2026-001", Severity::Critical, MonitorSource::Cve),
            make_event("New MCP repo", Severity::Low, MonitorSource::GitHub),
        ];

        let output = formatter.format_events(&events);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        // Valid SARIF envelope.
        assert_eq!(parsed["$schema"], SARIF_SCHEMA);
        assert_eq!(parsed["version"], SARIF_VERSION);

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);

        // First event: Critical CVE -> "error".
        assert_eq!(results[0]["level"], "error");
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("CVE-2026-001"));

        // Second event: Low GitHub -> "note".
        assert_eq!(results[1]["level"], "note");
    }

    #[test]
    fn test_events_empty_produces_valid_sarif() {
        let formatter = SarifFormatter;
        let output = formatter.format_events(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_events_rule_ids_use_source_name() {
        let formatter = SarifFormatter;
        let events = vec![
            make_event("e1", Severity::High, MonitorSource::Cve),
            make_event("e2", Severity::Medium, MonitorSource::Owasp),
        ];

        let output = formatter.format_events(&events);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let rule_ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(rule_ids.contains(&"mcp-monitor/cve"));
        assert!(rule_ids.contains(&"mcp-monitor/owasp"));
    }

    #[test]
    fn test_event_url_appears_in_location() {
        let formatter = SarifFormatter;
        let events = vec![make_event("e1", Severity::Medium, MonitorSource::GitHub)];

        let output = formatter.format_events(&events);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        let loc = &parsed["runs"][0]["results"][0]["locations"][0];
        assert_eq!(
            loc["physicalLocation"]["artifactLocation"]["uri"],
            "https://example.com/event"
        );
    }

    #[test]
    fn test_format_digest_returns_empty_json_object() {
        let formatter = SarifFormatter;
        let digest = crate::digest::build_digest(Vec::new(), Some("2026-W13"), false);
        let output = formatter.format_digest(&digest);
        assert_eq!(output, "{}");
    }

    // ── ScanReport -> SARIF tests ─────────────────────────────────────

    #[test]
    fn test_scan_report_to_sarif() {
        let report = ScanReport {
            source: "claude_desktop_config.json".to_string(),
            findings: vec![
                ScanFinding {
                    rule_id: "MCP-07".into(),
                    severity: Severity::Critical,
                    title: "Shell command execution in server 'bad-server'".into(),
                    description: "Uses sh -c".into(),
                },
                ScanFinding {
                    rule_id: "MCP-04".into(),
                    severity: Severity::High,
                    title: "Hardcoded API key in server 'bad-server'".into(),
                    description: "Contains hardcoded secret".into(),
                },
            ],
            servers_scanned: 1,
            rules_applied: 10,
            per_server: vec![],
            scanned_at: Utc::now(),
        };
        let output = scan_report_to_sarif(&report);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(parsed["version"], SARIF_VERSION);
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
    }

    #[test]
    fn test_extract_server_name_from_title() {
        assert_eq!(
            extract_server_name("Shell command in server 'my-server'"),
            Some("my-server".to_string())
        );
        assert_eq!(extract_server_name("No server mentioned"), None);
    }
}
