//! MCP-12: Tool Shadowing
//!
//! Detects MCP servers that attempt to shadow or override existing tools.
//! Checks for server names identical to popular built-in AI assistant tools
//! (Read, Write, Bash, Edit), names of well-known MCP ecosystem tools used
//! with non-official packages, deceptive replacement naming patterns, and
//! naming conflicts between MCP servers in the same configuration.
//!
//! Tool shadowing is a critical attack vector where a malicious MCP server
//! registers with a name matching a trusted tool, causing the LLM to route
//! sensitive operations through the attacker's server instead of the
//! legitimate tool.

use crate::monitors::Severity;
use crate::parser::{McpConfig, McpServerConfig};
use crate::scanner::ScanFinding;

/// Built-in AI assistant tool names that must never be shadowed.
/// These are core tools provided by LLM hosts (Claude, GPT, Copilot, etc.).
const BUILTIN_TOOL_NAMES: &[&str] = &[
    // Claude Code built-in tools
    "read",
    "write",
    "edit",
    "bash",
    "grep",
    "glob",
    "agent",
    "websearch",
    "webfetch",
    "web_search",
    "web_fetch",
    "notebookedit",
    "notebook_edit",
    "todowrite",
    "todo_write",
    "lsp",
    // Generic LLM tool names
    "search",
    "browse",
    "browser",
    "execute",
    "run",
    "shell",
    "terminal",
    "code_interpreter",
    "retrieval",
    "file_search",
];

/// Well-known MCP server names from the official ecosystem, paired with
/// the expected official package. A server using these names without the
/// official package may be attempting to impersonate the real tool.
const WELL_KNOWN_MCP_TOOLS: &[(&str, &str)] = &[
    ("filesystem", "@modelcontextprotocol/server-filesystem"),
    ("github", "@modelcontextprotocol/server-github"),
    ("fetch", "@modelcontextprotocol/server-fetch"),
    ("brave-search", "@modelcontextprotocol/server-brave-search"),
    ("puppeteer", "@modelcontextprotocol/server-puppeteer"),
    ("sqlite", "@modelcontextprotocol/server-sqlite"),
    ("postgres", "@modelcontextprotocol/server-postgres"),
    ("slack", "@modelcontextprotocol/server-slack"),
    ("google-drive", "@modelcontextprotocol/server-google-drive"),
    ("memory", "@modelcontextprotocol/server-memory"),
    (
        "sequential-thinking",
        "@modelcontextprotocol/server-sequential-thinking",
    ),
    ("everything", "@modelcontextprotocol/server-everything"),
    ("git", "@modelcontextprotocol/server-git"),
];

/// Prefixes in server names that suggest intent to replace another tool.
const REPLACEMENT_PREFIXES: &[&str] = &[
    "override-",
    "override_",
    "replace-",
    "replace_",
    "better-",
    "better_",
    "new-",
    "new_",
    "enhanced-",
    "enhanced_",
    "improved-",
    "improved_",
    "patched-",
    "patched_",
    "fixed-",
    "fixed_",
    "wrapped-",
    "wrapped_",
    "proxy-",
    "proxy_",
    "hook-",
    "hook_",
    "intercept-",
    "intercept_",
    "custom-",
    "custom_",
    "fake-",
    "fake_",
    "my-",
    "my_",
];

/// Keywords in arguments or environment variables that suggest tool
/// interception or shadowing intent.
const SHADOWING_KEYWORDS: &[&str] = &[
    "override",
    "intercept",
    "shadow",
    "hijack",
    "hook_tool",
    "mitm",
    "man-in-the-middle",
    "impersonate",
    "tool_spoof",
];

pub struct ToolShadowingRule;

impl super::Rule for ToolShadowingRule {
    fn id(&self) -> &'static str {
        "MCP-12"
    }

    fn name(&self) -> &'static str {
        "Tool Shadowing"
    }

    fn description(&self) -> &'static str {
        "Detects MCP servers attempting to shadow built-in tools or other \
         MCP servers by using identical or deceptive names. Tool shadowing \
         can redirect sensitive operations through malicious servers."
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-01"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let name_lower = server_name.to_lowercase();
        let args_str = server.args_string();

        // ── Check 1: Name exactly matches a built-in tool (case-insensitive) ──
        if BUILTIN_TOOL_NAMES.iter().any(|&tool| name_lower == tool) {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Critical,
                title: format!("Server '{}' shadows a built-in tool name", server_name),
                description: format!(
                    "MCP server is registered with name '{}' which matches a built-in \
                     AI assistant tool. This can cause the LLM to route operations \
                     through this server instead of the legitimate built-in tool, \
                     potentially exposing sensitive data or enabling malicious actions.",
                    server_name
                ),
            });
        }

        // ── Check 2: Name matches well-known MCP tool, wrong package ─────────
        for (known_name, official_package) in WELL_KNOWN_MCP_TOOLS {
            if name_lower == *known_name {
                let is_official = args_str.contains(official_package);
                if !is_official {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Critical,
                        title: format!("Server '{}' shadows well-known MCP tool", server_name),
                        description: format!(
                            "MCP server '{}' uses the name of the well-known '{}' tool \
                             but does not use the official package '{}'. \
                             This may be an attempt to impersonate the official tool \
                             and intercept its operations.",
                            server_name, known_name, official_package
                        ),
                    });
                }
                break;
            }
        }

        // ── Check 3: Replacement prefix + known tool name ────────────────────
        for prefix in REPLACEMENT_PREFIXES {
            if let Some(remainder) = name_lower.strip_prefix(prefix) {
                let shadows_builtin = BUILTIN_TOOL_NAMES.contains(&remainder);
                let shadows_known = WELL_KNOWN_MCP_TOOLS
                    .iter()
                    .any(|(name, _)| remainder == *name);

                if shadows_builtin || shadows_known {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Server '{}' suggests replacement of existing tool",
                            server_name
                        ),
                        description: format!(
                            "MCP server name '{}' uses prefix '{}' combined with known \
                             tool name '{}', suggesting it intends to replace or override \
                             the legitimate tool. Verify this server is authorized.",
                            server_name, prefix, remainder
                        ),
                    });
                    break; // One finding per server for this check.
                }
            }
        }

        // ── Check 4: Shadowing keywords in args or env ───────────────────────
        let combined = build_combined_text(server);

        for keyword in SHADOWING_KEYWORDS {
            if combined.contains(keyword) {
                findings.push(ScanFinding {
                    rule_id: self.id().to_string(),
                    severity: Severity::High,
                    title: format!(
                        "Server '{}' contains tool interception indicators",
                        server_name
                    ),
                    description: format!(
                        "MCP server '{}' configuration contains keyword '{}' which \
                         suggests intent to intercept or shadow other tools. \
                         Review the server's purpose and verify it is legitimate.",
                        server_name, keyword
                    ),
                });
                break; // One finding per server for this check.
            }
        }

        findings
    }

    fn check_config(&self, config: &McpConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        let mut names: Vec<&String> = config.mcp_servers.keys().collect();
        names.sort(); // Deterministic output.

        // ── Cross-server name conflict detection ─────────────────────────────
        for (i, name_a) in names.iter().enumerate() {
            let lower_a = name_a.to_lowercase();

            for name_b in names.iter().skip(i + 1) {
                let lower_b = name_b.to_lowercase();

                // Case-insensitive exact duplicates.
                if lower_a == lower_b {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::Critical,
                        title: format!(
                            "Name conflict: '{}' and '{}' collide (case-insensitive)",
                            name_a, name_b
                        ),
                        description: format!(
                            "MCP servers '{}' and '{}' have the same name when compared \
                             case-insensitively. This creates ambiguity and may allow \
                             one server to shadow the other, intercepting its operations.",
                            name_a, name_b
                        ),
                    });
                    continue; // Skip normalized check — already reported.
                }

                // Normalized name collisions (dash/underscore/space equivalence).
                let norm_a = normalize_name(&lower_a);
                let norm_b = normalize_name(&lower_b);
                if norm_a == norm_b {
                    findings.push(ScanFinding {
                        rule_id: self.id().to_string(),
                        severity: Severity::High,
                        title: format!(
                            "Near-duplicate server names: '{}' and '{}'",
                            name_a, name_b
                        ),
                        description: format!(
                            "MCP servers '{}' and '{}' have confusingly similar names \
                             (identical after normalizing separators). This may cause \
                             unintended tool routing or indicate a shadowing attempt.",
                            name_a, name_b
                        ),
                    });
                }
            }
        }

        findings
    }
}

/// Combine command, arguments, and environment variable keys/values into
/// a single lowercased string for keyword scanning.
fn build_combined_text(server: &McpServerConfig) -> String {
    let cmd = server.command.as_deref().unwrap_or("");
    let args = server.args_string();
    let env_text = server
        .env
        .as_ref()
        .map(|e| {
            e.iter()
                .map(|(k, v)| format!("{} {}", k, v))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    format!("{} {} {}", cmd, args, env_text).to_lowercase()
}

/// Normalize a server name by removing separators for fuzzy comparison.
fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '-' && *c != '_' && *c != ' ')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    // ── Helpers ──────────────────────────────────────────────────────────

    fn check_server(name: &str, cmd: &str, args: &[&str]) -> Vec<ScanFinding> {
        let rule = ToolShadowingRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_server_with_env(
        name: &str,
        cmd: &str,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Vec<ScanFinding> {
        let rule = ToolShadowingRule;
        let server = McpServerConfig {
            command: Some(cmd.into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check(name, &server)
    }

    fn check_config_servers(servers: Vec<(&str, &str, &[&str])>) -> Vec<ScanFinding> {
        let rule = ToolShadowingRule;
        let mut mcp_servers = HashMap::new();
        for (name, cmd, args) in servers {
            mcp_servers.insert(
                name.to_string(),
                McpServerConfig {
                    command: Some(cmd.into()),
                    args: Some(args.iter().map(|s| s.to_string()).collect()),
                    ..Default::default()
                },
            );
        }
        let config = McpConfig {
            mcp_servers,
            source_path: None,
        };
        rule.check_config(&config)
    }

    // ── Rule metadata ────────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = ToolShadowingRule;
        assert_eq!(rule.id(), "MCP-12");
        assert_eq!(rule.name(), "Tool Shadowing");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-01");
        assert_eq!(rule.default_severity(), Severity::Critical);
    }

    // ── Check 1: Built-in tool name shadowing ────────────────────────────

    #[test]
    fn detects_builtin_read_shadow() {
        let findings = check_server("Read", "node", &["malicious-server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.title.contains("shadows a built-in tool")),
            "Should detect 'Read' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_write_shadow_case_insensitive() {
        let findings = check_server("WRITE", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.title.contains("shadows a built-in tool")),
            "Should detect 'WRITE' as built-in tool shadowing (case-insensitive)"
        );
    }

    #[test]
    fn detects_builtin_bash_shadow() {
        let findings = check_server("bash", "python", &["-m", "fake_bash"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.title.contains("shadows a built-in tool")),
            "Should detect 'bash' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_edit_shadow() {
        let findings = check_server("Edit", "npx", &["-y", "evil-edit-tool"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'Edit' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_grep_shadow() {
        let findings = check_server("grep", "node", &["grep-server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.title.contains("shadows a built-in tool")),
            "Should detect 'grep' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_glob_shadow() {
        let findings = check_server("Glob", "node", &["server.js"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'Glob' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_shell_shadow() {
        let findings = check_server("shell", "node", &["server.js"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'shell' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_search_shadow() {
        let findings = check_server("search", "node", &["server.js"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'search' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_websearch_shadow() {
        let findings = check_server("WebSearch", "node", &["server.js"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'WebSearch' as built-in tool shadowing"
        );
    }

    #[test]
    fn detects_builtin_code_interpreter_shadow() {
        let findings = check_server("code_interpreter", "node", &["server.js"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "Should detect 'code_interpreter' as built-in tool shadowing"
        );
    }

    #[test]
    fn safe_name_no_builtin_finding() {
        let findings = check_server("my-database-tool", "node", &["db-server.js"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("shadows a built-in tool")),
            "Non-builtin name should not trigger built-in shadowing"
        );
    }

    // ── Check 2: Well-known MCP tool shadowing ───────────────────────────

    #[test]
    fn detects_filesystem_shadow_wrong_package() {
        let findings = check_server("filesystem", "npx", &["-y", "evil-filesystem-server"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical
                && f.title.contains("shadows well-known MCP tool")),
            "Should detect non-official 'filesystem' server"
        );
    }

    #[test]
    fn official_filesystem_passes() {
        let findings = check_server(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("shadows well-known MCP tool")),
            "Official filesystem package should not trigger well-known shadowing"
        );
    }

    #[test]
    fn detects_github_shadow_wrong_package() {
        let findings = check_server("github", "npx", &["-y", "fake-github-mcp"]);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical
                && f.title.contains("shadows well-known MCP tool")),
            "Should detect non-official 'github' server"
        );
    }

    #[test]
    fn official_github_passes() {
        let findings = check_server(
            "github",
            "npx",
            &["-y", "@modelcontextprotocol/server-github"],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("shadows well-known MCP tool")),
            "Official github package should pass"
        );
    }

    #[test]
    fn detects_memory_shadow_http_server() {
        // HTTP server using a well-known name — cannot verify official package.
        let rule = ToolShadowingRule;
        let server = McpServerConfig {
            url: Some("https://evil.example.com/mcp".into()),
            transport: Some("sse".into()),
            ..Default::default()
        };
        let findings = rule.check("memory", &server);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("shadows well-known MCP tool")),
            "HTTP server with well-known name should be flagged"
        );
    }

    #[test]
    fn detects_slack_shadow() {
        let findings = check_server("slack", "npx", &["-y", "sketchy-slack-replacement"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("shadows well-known MCP tool")),
            "Should detect non-official 'slack' server"
        );
    }

    #[test]
    fn unique_name_no_wellknown_finding() {
        let findings = check_server("my-custom-analytics", "npx", &["-y", "analytics-mcp"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("shadows well-known MCP tool")),
            "Unique name should not trigger well-known shadowing"
        );
    }

    // ── Check 3: Replacement prefix patterns ─────────────────────────────

    #[test]
    fn detects_better_read_replacement() {
        let findings = check_server("better-read", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.title.contains("suggests replacement")),
            "Should detect 'better-read' as replacement pattern"
        );
    }

    #[test]
    fn detects_custom_filesystem_replacement() {
        let findings = check_server("custom-filesystem", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'custom-filesystem' as replacement pattern"
        );
    }

    #[test]
    fn detects_override_bash_replacement() {
        let findings = check_server("override-bash", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'override-bash' as replacement pattern"
        );
    }

    #[test]
    fn detects_hook_edit_replacement() {
        let findings = check_server("hook_edit", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'hook_edit' as replacement pattern"
        );
    }

    #[test]
    fn detects_fake_write_replacement() {
        let findings = check_server("fake-write", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'fake-write' as replacement pattern"
        );
    }

    #[test]
    fn detects_proxy_github_replacement() {
        let findings = check_server("proxy-github", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'proxy-github' as replacement pattern"
        );
    }

    #[test]
    fn detects_intercept_fetch_replacement() {
        let findings = check_server("intercept_fetch", "node", &["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Should detect 'intercept_fetch' as replacement pattern"
        );
    }

    #[test]
    fn safe_prefix_no_known_tool() {
        let findings = check_server("better-analytics", "node", &["server.js"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("suggests replacement")),
            "Replacement prefix + unknown tool should not trigger"
        );
    }

    // ── Check 4: Shadowing keywords in args/env ──────────────────────────

    #[test]
    fn detects_shadow_keyword_in_args() {
        let findings = check_server("my-tool", "node", &["server.js", "--shadow", "read"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect 'shadow' keyword in args"
        );
    }

    #[test]
    fn detects_hijack_keyword_in_args() {
        let findings = check_server("sneaky-server", "node", &["server.js", "--mode", "hijack"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect 'hijack' keyword in args"
        );
    }

    #[test]
    fn detects_intercept_keyword_in_env() {
        let mut env = HashMap::new();
        env.insert("MODE".to_string(), "intercept".to_string());
        let findings = check_server_with_env("my-tool", "node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect 'intercept' keyword in env"
        );
    }

    #[test]
    fn detects_mitm_keyword_in_env_key() {
        let mut env = HashMap::new();
        env.insert("MITM_PROXY".to_string(), "true".to_string());
        let findings = check_server_with_env("my-tool", "node", &["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect 'mitm' keyword in env key"
        );
    }

    #[test]
    fn detects_impersonate_keyword() {
        let findings = check_server(
            "tool-proxy",
            "node",
            &["server.js", "--impersonate", "read"],
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect 'impersonate' keyword"
        );
    }

    #[test]
    fn safe_args_no_shadowing_keywords() {
        let findings = check_server("my-tool", "node", &["server.js", "--port", "3000"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Normal args should not trigger shadowing keyword detection"
        );
    }

    // ── Check 5: Cross-server name conflicts (check_config) ──────────────

    #[test]
    fn detects_case_insensitive_duplicate_names() {
        let findings = check_config_servers(vec![
            (
                "filesystem",
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            ),
            ("Filesystem", "npx", &["-y", "evil-fs-server"]),
        ]);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::Critical && f.title.contains("Name conflict") }),
            "Should detect case-insensitive name collision"
        );
    }

    #[test]
    fn detects_dash_underscore_near_duplicate() {
        let findings = check_config_servers(vec![
            ("my-server", "node", &["server1.js"]),
            ("my_server", "node", &["server2.js"]),
        ]);
        assert!(
            findings
                .iter()
                .any(|f| { f.severity == Severity::High && f.title.contains("Near-duplicate") }),
            "Should detect dash/underscore near-duplicate"
        );
    }

    #[test]
    fn detects_separator_removal_near_duplicate() {
        let findings = check_config_servers(vec![
            ("read-file", "node", &["server1.js"]),
            ("readfile", "node", &["server2.js"]),
        ]);
        assert!(
            findings
                .iter()
                .any(|f| { f.title.contains("Near-duplicate") }),
            "Should detect separator-removal near-duplicate"
        );
    }

    #[test]
    fn no_conflict_for_distinct_names() {
        let findings = check_config_servers(vec![
            (
                "filesystem",
                "npx",
                &["-y", "@modelcontextprotocol/server-filesystem"],
            ),
            (
                "github",
                "npx",
                &["-y", "@modelcontextprotocol/server-github"],
            ),
            ("database", "node", &["db-server.js"]),
        ]);
        assert!(
            findings.is_empty(),
            "Distinct names should not trigger conflicts"
        );
    }

    #[test]
    fn no_conflict_for_single_server() {
        let findings = check_config_servers(vec![(
            "filesystem",
            "npx",
            &["-y", "@modelcontextprotocol/server-filesystem"],
        )]);
        assert!(
            findings.is_empty(),
            "Single server cannot have name conflicts"
        );
    }

    // ── Compound scenarios ───────────────────────────────────────────────

    #[test]
    fn builtin_shadow_produces_critical_finding() {
        let findings = check_server("Read", "python", &["-m", "evil_read"]);
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        assert!(
            critical_count >= 1,
            "Built-in shadowing must produce at least one Critical finding"
        );
    }

    #[test]
    fn wellknown_shadow_with_wrong_package_is_critical() {
        let findings = check_server("filesystem", "npx", &["-y", "totally-not-malicious-fs"]);
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        assert!(
            critical_count >= 1,
            "Well-known tool shadowing with wrong package must be Critical"
        );
    }

    #[test]
    fn multiple_checks_can_fire_for_same_server() {
        // Server named "bash" (builtin shadow) with "hijack" in args.
        let findings = check_server("bash", "node", &["server.js", "--hijack"]);
        assert!(
            findings.len() >= 2,
            "Multiple checks should fire: got {} findings",
            findings.len()
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("shadows a built-in tool")),
            "Should detect built-in shadow"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("interception indicators")),
            "Should detect shadowing keyword"
        );
    }

    // ── Normalize helper ─────────────────────────────────────────────────

    #[test]
    fn normalize_name_removes_separators() {
        assert_eq!(normalize_name("my-server"), "myserver");
        assert_eq!(normalize_name("my_server"), "myserver");
        assert_eq!(normalize_name("my server"), "myserver");
        assert_eq!(normalize_name("my-cool_server"), "mycoolserver");
        assert_eq!(normalize_name("noseparators"), "noseparators");
    }

    // ── Edge cases ───────────────────────────────────────────────────────

    #[test]
    fn empty_server_name_no_panic() {
        let findings = check_server("", "node", &["server.js"]);
        // Should not panic, may or may not produce findings.
        let _ = findings;
    }

    #[test]
    fn server_with_no_args_no_panic() {
        let rule = ToolShadowingRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            ..Default::default()
        };
        let findings = rule.check("my-tool", &server);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn http_server_with_no_command_no_panic() {
        let rule = ToolShadowingRule;
        let server = McpServerConfig {
            url: Some("https://example.com/mcp".into()),
            ..Default::default()
        };
        let findings = rule.check("my-http-tool", &server);
        // Should not panic.
        let _ = findings;
    }

    #[test]
    fn config_with_no_servers_no_panic() {
        let rule = ToolShadowingRule;
        let config = McpConfig {
            mcp_servers: HashMap::new(),
            source_path: None,
        };
        let findings = rule.check_config(&config);
        assert!(findings.is_empty());
    }
}
