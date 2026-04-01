//! Integration tests for the `scan` command.
//!
//! Tests the full scanning pipeline: config parsing → rule engine → output.

use mcp_audit::config::OutputFormat;
use mcp_audit::monitors::Severity;
use mcp_audit::output;
use mcp_audit::parser::McpConfig;
use mcp_audit::rules::RuleEngine;
use tempfile::TempDir;

// ── Config file scanning ───────────────────────────────────────────────

#[test]
fn scan_config_file_with_vulnerable_server() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("mcp.json");
    std::fs::write(
        &config_path,
        r#"{
            "mcpServers": {
                "bad-server": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"],
                    "env": {
                        "SECRET_KEY": "sk-abc123def456ghi789jkl012mno345pqr678"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let mcp_config = McpConfig::from_file(&config_path).unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 1);
    assert!(!report.findings.is_empty());
    assert_eq!(report.per_server.len(), 1);
    assert!(!report.per_server[0].passed);
    assert!(report.per_server[0].finding_count > 0);
    assert!(report.exit_code() != 0);
}

#[test]
fn scan_config_file_with_safe_server() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/safe-dir", "--read-only"],
                    "env": {
                        "LOG_LEVEL": "info"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 1);
    assert_eq!(report.per_server.len(), 1);
    // Some info-level findings may still appear, but no critical/high.
    assert!(!report.has_critical_or_high());
}

#[test]
fn scan_multiple_servers_per_server_tracking() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "safe-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "bad-server": {
                    "command": "sh",
                    "args": ["-c", "eval $USER_INPUT"],
                    "env": {
                        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                    }
                }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 2);
    assert_eq!(report.per_server.len(), 2);

    // Per-server results should be sorted by name.
    assert_eq!(report.per_server[0].name, "bad-server");
    assert_eq!(report.per_server[1].name, "safe-server");

    // bad-server should have findings; safe-server may or may not.
    assert!(!report.per_server[0].passed);
    assert!(report.per_server[0].finding_count > 0);
}

// ── --server flag (single server from command line) ───────────────────

#[test]
fn scan_single_server_from_command_line() {
    let mcp_config =
        McpConfig::from_server_command("npx -y @modelcontextprotocol/server-filesystem /tmp")
            .unwrap();

    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 1);
    assert_eq!(report.per_server.len(), 1);
    assert!(report.source.starts_with("cli:"));
}

#[test]
fn scan_single_server_shell_command_detected() {
    let mcp_config = McpConfig::from_server_command("sh -c 'echo hello'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    // Shell interpreter should trigger command injection rule.
    assert!(!report.findings.is_empty());
    assert!(
        report.findings.iter().any(|f| f.rule_id.contains("MCP-07")),
        "Expected MCP-07 (Command Injection) finding for sh -c"
    );
}

// ── --url flag (single HTTP server) ───────────────────────────────────

#[test]
fn scan_single_url_sse_server() {
    let mcp_config = McpConfig::from_url("https://mcp.example.com/sse").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 1);
    assert_eq!(report.per_server.len(), 1);
    assert_eq!(report.per_server[0].name, "mcp.example.com");
    assert!(report.source.contains("https://mcp.example.com/sse"));
}

#[test]
fn scan_single_url_http_unencrypted_detected() {
    let mcp_config = McpConfig::from_url("http://mcp.example.com/api").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    // Unencrypted HTTP should trigger server spoofing rule.
    let spoofing_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule_id.contains("MCP-05"))
        .collect();
    assert!(
        !spoofing_findings.is_empty(),
        "Expected MCP-05 finding for unencrypted HTTP"
    );
}

// ── Severity filtering ────────────────────────────────────────────────

#[test]
fn severity_filter_high_only_shows_high_and_above() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "bad": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"],
                    "env": { "SECRET": "sk-abc123def456ghi789jkl012mno345pqr678" }
                }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new().with_min_severity(Severity::High);
    let report = engine.scan(&mcp_config);

    for finding in &report.findings {
        assert!(
            finding.severity >= Severity::High,
            "Finding {} has severity {:?}, expected >= High",
            finding.rule_id,
            finding.severity
        );
    }
}

#[test]
fn severity_filter_critical_only() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "bad": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"],
                    "env": { "SECRET": "sk-abc123def456ghi789jkl012mno345pqr678" }
                }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new().with_min_severity(Severity::Critical);
    let report = engine.scan(&mcp_config);

    for finding in &report.findings {
        assert_eq!(
            finding.severity,
            Severity::Critical,
            "Finding {} has severity {:?}, expected Critical",
            finding.rule_id,
            finding.severity
        );
    }
}

// ── Output formats ─────────────────────────────────────────────────────

#[test]
fn scan_report_renders_json() {
    let mcp_config = McpConfig::from_server_command("sh -c 'echo test'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    let json = output::render_scan_report(&report, OutputFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["findings"].is_array());
    assert!(parsed["per_server"].is_array());
    assert!(parsed["servers_scanned"].is_number());
}

#[test]
fn scan_report_renders_sarif() {
    let mcp_config = McpConfig::from_server_command("sh -c 'echo test'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    let sarif = output::render_scan_report(&report, OutputFormat::Sarif);
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    assert_eq!(parsed["version"], "2.1.0");
}

#[test]
fn scan_report_renders_table() {
    let mcp_config = McpConfig::from_server_command("sh -c 'echo test'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    let table = output::render_scan_report(&report, OutputFormat::Table);
    assert!(table.contains("MCP Security Scan Report"));
    assert!(table.contains("Servers scanned"));
}

#[test]
fn scan_report_renders_markdown() {
    let mcp_config = McpConfig::from_server_command("sh -c 'echo test'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    let md = output::render_scan_report(&report, OutputFormat::Markdown);
    assert!(md.contains("# MCP Security Scan Report"));
    assert!(md.contains("**Source:**"));
}

// ── Summary rendering ──────────────────────────────────────────────────

#[test]
fn scan_summary_shows_passed_and_failed_counts() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "safe": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "bad": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"]
                }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);
    let summary = output::render_scan_summary(&report);

    assert!(summary.contains("Scan Summary"));
    assert!(summary.contains("2 server(s) scanned"));
    // bad-server should fail.
    assert!(summary.contains("failed"));
}

#[test]
fn scan_summary_clean_scan() {
    let mcp_config = McpConfig::parse(r#"{"mcpServers": {}}"#).unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);
    let summary = output::render_scan_summary(&report);

    assert!(summary.contains("Scan Summary"));
    assert!(summary.contains("0 server(s) scanned"));
}

// ── Output to file ────────────────────────────────────────────────────

#[test]
fn scan_report_can_be_written_to_file() {
    let tmp = TempDir::new().unwrap();
    let output_path = tmp.path().join("report.sarif");

    let mcp_config = McpConfig::from_server_command("sh -c 'echo test'").unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);
    let rendered = output::render_scan_report(&report, OutputFormat::Sarif);

    std::fs::write(&output_path, &rendered).unwrap();

    let content = std::fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
}

// ── Edge cases ─────────────────────────────────────────────────────────

#[test]
fn scan_empty_config_produces_clean_report() {
    let mcp_config = McpConfig::parse(r#"{"mcpServers": {}}"#).unwrap();
    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.servers_scanned, 0);
    assert!(report.findings.is_empty());
    assert!(report.per_server.is_empty());
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn from_server_command_preserves_complex_args() {
    let mcp_config =
        McpConfig::from_server_command("node /path/to/server.js --port 3000 --verbose").unwrap();
    let (_, server) = mcp_config.mcp_servers.iter().next().unwrap();

    assert_eq!(server.command.as_deref(), Some("node"));
    assert_eq!(
        server.args.as_ref().unwrap(),
        &["/path/to/server.js", "--port", "3000", "--verbose"]
    );
}

#[test]
fn from_url_with_port() {
    let mcp_config = McpConfig::from_url("https://localhost:8443/mcp").unwrap();
    let (name, server) = mcp_config.mcp_servers.iter().next().unwrap();

    assert_eq!(name, "localhost");
    assert_eq!(server.url.as_deref(), Some("https://localhost:8443/mcp"));
}

#[test]
fn per_server_results_are_deterministically_sorted() {
    let mcp_config = McpConfig::parse(
        r#"{
            "mcpServers": {
                "zeta": { "command": "echo", "args": ["z"] },
                "alpha": { "command": "echo", "args": ["a"] },
                "mid": { "command": "echo", "args": ["m"] }
            }
        }"#,
    )
    .unwrap();

    let engine = RuleEngine::new();
    let report = engine.scan(&mcp_config);

    assert_eq!(report.per_server[0].name, "alpha");
    assert_eq!(report.per_server[1].name, "mid");
    assert_eq!(report.per_server[2].name, "zeta");
}
