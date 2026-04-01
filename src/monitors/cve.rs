//! CVE/NVD monitor — tracks new CVEs related to MCP servers via the NVD API.
//!
//! Uses the NVD 2.0 REST API to discover CVEs matching MCP-related keywords.
//! Supports both authenticated (with API key) and unauthenticated access.

use crate::error::Result;
use crate::http::RateLimitedClient;
use crate::monitors::{Monitor, MonitorEvent, MonitorSource, PollOptions, Severity};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;

/// NVD 2.0 API base URL.
const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Search keywords for MCP-related vulnerabilities.
const CVE_KEYWORDS: &[&str] = &["model context protocol", "MCP server", "mcp-server"];

// ── NVD API response types ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    #[allow(dead_code)]
    results_per_page: Option<u32>,
    #[allow(dead_code)]
    start_index: Option<u32>,
    total_results: Option<u32>,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdCve {
    id: String,
    source_identifier: Option<String>,
    published: Option<String>,
    #[allow(dead_code)]
    last_modified: Option<String>,
    descriptions: Option<Vec<NvdDescription>>,
    metrics: Option<NvdMetrics>,
    references: Option<Vec<NvdReference>>,
    weaknesses: Option<Vec<NvdWeakness>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v31: Option<Vec<CvssEntry>>,
    cvss_metric_v30: Option<Vec<CvssEntry>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssEntry {
    cvss_data: Option<CvssData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    base_score: Option<f64>,
    base_severity: Option<String>,
    #[allow(dead_code)]
    vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: Option<String>,
    #[allow(dead_code)]
    source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    description: Option<Vec<NvdDescription>>,
}

// ── Monitor implementation ──────────────────────────────────────────────

/// Monitors the NVD for CVEs related to MCP servers.
pub struct CveMonitor {
    client: RateLimitedClient,
}

impl CveMonitor {
    pub fn new(client: RateLimitedClient) -> Self {
        Self { client }
    }

    /// Query NVD for CVEs matching a specific keyword.
    async fn search_keyword(
        &self,
        keyword: &str,
        opts: &PollOptions,
    ) -> Result<Vec<NvdVulnerability>> {
        let mut url = format!(
            "{}?keywordSearch={}&resultsPerPage={}",
            NVD_API_URL,
            keyword.replace(' ', "%20"),
            opts.max_results.min(100),
        );

        // Add date range filter if watermark is set.
        if let Some(since) = opts.since {
            let since_str = since.format("%Y-%m-%dT%H:%M:%S.000").to_string();
            let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%S.000").to_string();
            url.push_str(&format!(
                "&lastModStartDate={}&lastModEndDate={}",
                since_str, now_str,
            ));
        }

        tracing::debug!(keyword = %keyword, url = %url, "Querying NVD API");

        let nvd_resp: NvdResponse = self.client.get_json(&url).await?;

        tracing::info!(
            keyword = %keyword,
            total = ?nvd_resp.total_results,
            returned = nvd_resp.vulnerabilities.len(),
            "NVD search results"
        );

        Ok(nvd_resp.vulnerabilities)
    }
}

impl Monitor for CveMonitor {
    fn source(&self) -> MonitorSource {
        MonitorSource::Cve
    }

    fn name(&self) -> &str {
        "NVD CVE Tracker"
    }

    fn poll(
        &self,
        opts: &PollOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        let opts = opts.clone();
        Box::pin(async move {
            let mut all_events = Vec::new();
            let mut seen_ids = std::collections::HashSet::new();

            for keyword in CVE_KEYWORDS {
                match self.search_keyword(keyword, &opts).await {
                    Ok(vulns) => {
                        for vuln in vulns {
                            if seen_ids.insert(vuln.cve.id.clone()) {
                                all_events.push(cve_to_event(vuln));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(keyword = %keyword, error = %e, "NVD search failed");
                    }
                }

                if all_events.len() >= opts.max_results {
                    break;
                }
            }

            // Sort by severity descending, then by date.
            all_events.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| b.discovered_at.cmp(&a.discovered_at))
            });
            all_events.truncate(opts.max_results);

            Ok(all_events)
        })
    }
}

// ── Conversion helpers ──────────────────────────────────────────────────

fn cve_to_event(vuln: NvdVulnerability) -> MonitorEvent {
    let cve = vuln.cve;

    // Extract English description.
    let description = cve
        .descriptions
        .as_ref()
        .and_then(|descs| {
            descs
                .iter()
                .find(|d| d.lang == "en")
                .or(descs.first())
                .map(|d| d.value.clone())
        })
        .unwrap_or_else(|| format!("No description available for {}", cve.id));

    // Extract CVSS score and severity.
    let (cvss_score, severity) = extract_cvss(&cve.metrics);

    // Parse published date.
    let published = cve
        .published
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    // Build URL.
    let url = format!("https://nvd.nist.gov/vuln/detail/{}", cve.id);

    // Extract CWE IDs from weaknesses.
    let cwes: Vec<String> = cve
        .weaknesses
        .as_ref()
        .map(|ws| {
            ws.iter()
                .flat_map(|w| {
                    w.description
                        .as_ref()
                        .map(|descs| {
                            descs
                                .iter()
                                .filter(|d| d.value.starts_with("CWE-"))
                                .map(|d| d.value.clone())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default();

    // References.
    let references: Vec<String> = cve
        .references
        .as_ref()
        .map(|refs| refs.iter().filter_map(|r| r.url.clone()).collect())
        .unwrap_or_default();

    let mut tags = vec!["cve".to_string(), "vulnerability".to_string()];
    for cwe in &cwes {
        tags.push(cwe.clone());
    }

    MonitorEvent {
        id: format!("cve-{}", cve.id),
        source: MonitorSource::Cve,
        title: format!("{}: {}", cve.id, truncate(&description, 100)),
        description,
        url,
        discovered_at: published,
        severity: Some(severity),
        tags,
        metadata: serde_json::json!({
            "cve_id": cve.id,
            "cvss_score": cvss_score,
            "cwes": cwes,
            "references": references,
            "source_identifier": cve.source_identifier,
        }),
    }
}

fn extract_cvss(metrics: &Option<NvdMetrics>) -> (Option<f64>, Severity) {
    let entry = metrics
        .as_ref()
        .and_then(|m| {
            m.cvss_metric_v31
                .as_ref()
                .and_then(|v| v.first())
                .or_else(|| m.cvss_metric_v30.as_ref().and_then(|v| v.first()))
        })
        .and_then(|e| e.cvss_data.as_ref());

    match entry {
        Some(data) => {
            let score = data.base_score;
            let severity = match data.base_severity.as_deref() {
                Some("CRITICAL") => Severity::Critical,
                Some("HIGH") => Severity::High,
                Some("MEDIUM") => Severity::Medium,
                Some("LOW") => Severity::Low,
                _ => score_to_severity(score),
            };
            (score, severity)
        }
        None => (None, Severity::Info),
    }
}

fn score_to_severity(score: Option<f64>) -> Severity {
    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s >= 0.1 => Severity::Low,
        _ => Severity::Info,
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_score() {
        assert_eq!(score_to_severity(Some(9.8)), Severity::Critical);
        assert_eq!(score_to_severity(Some(7.5)), Severity::High);
        assert_eq!(score_to_severity(Some(5.0)), Severity::Medium);
        assert_eq!(score_to_severity(Some(2.0)), Severity::Low);
        assert_eq!(score_to_severity(None), Severity::Info);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a longer string here", 10), "a longer s...");
    }

    #[test]
    fn test_cve_to_event_basic() {
        let vuln = NvdVulnerability {
            cve: NvdCve {
                id: "CVE-2026-0001".to_string(),
                source_identifier: Some("cna@vendor.com".to_string()),
                published: Some("2026-03-15T12:00:00.000Z".to_string()),
                last_modified: Some("2026-03-20T12:00:00.000Z".to_string()),
                descriptions: Some(vec![NvdDescription {
                    lang: "en".to_string(),
                    value: "MCP server allows command injection via tool invocation".to_string(),
                }]),
                metrics: Some(NvdMetrics {
                    cvss_metric_v31: Some(vec![CvssEntry {
                        cvss_data: Some(CvssData {
                            base_score: Some(9.8),
                            base_severity: Some("CRITICAL".to_string()),
                            vector_string: Some(
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                            ),
                        }),
                    }]),
                    cvss_metric_v30: None,
                }),
                references: Some(vec![NvdReference {
                    url: Some("https://example.com/advisory".to_string()),
                    source: Some("vendor".to_string()),
                }]),
                weaknesses: Some(vec![NvdWeakness {
                    description: Some(vec![NvdDescription {
                        lang: "en".to_string(),
                        value: "CWE-78".to_string(),
                    }]),
                }]),
            },
        };

        let event = cve_to_event(vuln);
        assert_eq!(event.id, "cve-CVE-2026-0001");
        assert_eq!(event.source, MonitorSource::Cve);
        assert_eq!(event.severity, Some(Severity::Critical));
        assert!(event.tags.contains(&"CWE-78".to_string()));
        assert!(event.url.contains("CVE-2026-0001"));
    }

    #[test]
    fn test_extract_cvss_empty_metrics() {
        let (score, sev) = extract_cvss(&None);
        assert!(score.is_none());
        assert_eq!(sev, Severity::Info);
    }
}
