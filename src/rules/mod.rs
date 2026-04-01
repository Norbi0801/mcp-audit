//! Security rule engine for MCP configuration scanning.
//!
//! Implements the OWASP MCP Top 10 as static analysis rules that check
//! MCP server configurations for security issues.
//!
//! # Architecture
//!
//! - [`Rule`] — trait that every security rule implements.
//! - [`RuleResult`] — outcome of evaluating a rule: Pass, Fail, or Skip.
//! - [`Category`] — semantic grouping of rules (tool security, transport, etc.).
//! - [`RuleRegistry`] — collects and indexes rules, supports filtering.
//! - [`RuleEngine`] — executes rules against MCP configs, produces [`ScanReport`].

pub mod mcp01_tool_poisoning;
pub mod mcp02_excessive_permissions;
pub mod mcp03_prompt_injection;
pub mod mcp04_insecure_credentials;
pub mod mcp05_server_spoofing;
pub mod mcp06_insecure_dependencies;
pub mod mcp07_command_injection;
pub mod mcp08_data_exfiltration;
pub mod mcp09_insufficient_logging;
pub mod mcp10_unauthorized_access;
pub mod mcp11_denial_of_service;
pub mod mcp12_tool_shadowing;
pub mod mcp13_resource_exposure;
pub mod mcp14_insecure_transport;
pub mod mcp15_tool_injection;
pub mod mcp16_missing_input_validation;
pub mod mcp17_data_leakage;
pub mod mcp18_prompt_injection_vectors;
pub mod mcp19_excessive_tool_permissions;

use crate::monitors::Severity;
use crate::parser::{McpConfig, McpServerConfig};
use crate::scanner::ScanFinding;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

// ── Rule outcome ─────────────────────────────────────────────────────

/// Outcome of evaluating a single rule against a single server.
#[derive(Debug, Clone)]
pub enum RuleResult {
    /// Rule passed — no issues detected.
    Pass,
    /// Rule failed — one or more security findings.
    Fail(Vec<ScanFinding>),
    /// Rule was skipped (not applicable to this server configuration).
    Skip(String),
}

impl RuleResult {
    /// Returns `true` if the result is a `Fail` with at least one finding.
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail(findings) if !findings.is_empty())
    }

    /// Returns `true` if the result is `Pass`.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns `true` if the result is `Skip`.
    pub fn is_skip(&self) -> bool {
        matches!(self, Self::Skip(_))
    }

    /// Extracts findings from a `Fail` result, or returns an empty vec.
    pub fn findings(&self) -> Vec<ScanFinding> {
        match self {
            Self::Fail(findings) => findings.clone(),
            _ => Vec::new(),
        }
    }

    /// Returns the skip reason if this is a `Skip`, otherwise `None`.
    pub fn skip_reason(&self) -> Option<&str> {
        match self {
            Self::Skip(reason) => Some(reason),
            _ => None,
        }
    }
}

// ── Rule categories ──────────────────────────────────────────────────

/// Semantic category for grouping related security rules.
///
/// Categories provide a higher-level classification than individual OWASP IDs,
/// making it easier to focus scans on specific security domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Category {
    /// Tool poisoning, shadowing, injection, and excessive permissions.
    /// Rules: MCP-01, MCP-12, MCP-15, MCP-19.
    ToolSecurity,

    /// Prompt injection and advanced injection vectors.
    /// Rules: MCP-03, MCP-18.
    PromptInjection,

    /// Insecure credentials and data exfiltration/leakage.
    /// Rules: MCP-04, MCP-08, MCP-17.
    DataProtection,

    /// Server spoofing and insecure transport.
    /// Rules: MCP-05, MCP-14.
    Transport,

    /// Command injection and missing input validation.
    /// Rules: MCP-07, MCP-16.
    InputValidation,

    /// Unauthorized access and excessive permissions.
    /// Rules: MCP-02, MCP-10.
    Authentication,

    /// Insecure dependencies, insufficient logging.
    /// Rules: MCP-06, MCP-09.
    Configuration,

    /// Denial of service and resource exposure.
    /// Rules: MCP-11, MCP-13.
    ResourceProtection,
}

impl Category {
    /// Derive category from an OWASP MCP rule ID (e.g., "OWASP-MCP-01").
    pub fn from_owasp_id(owasp_id: &str) -> Self {
        // Extract the numeric suffix.
        let num = owasp_id
            .rsplit('-')
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        match num {
            1 | 12 | 15 | 19 => Self::ToolSecurity,
            3 | 18 => Self::PromptInjection,
            4 | 8 | 17 => Self::DataProtection,
            5 | 14 => Self::Transport,
            7 | 16 => Self::InputValidation,
            2 | 10 => Self::Authentication,
            6 | 9 => Self::Configuration,
            11 | 13 => Self::ResourceProtection,
            _ => Self::Configuration,
        }
    }

    /// All category variants, for iteration.
    pub fn all() -> &'static [Category] {
        &[
            Self::ToolSecurity,
            Self::PromptInjection,
            Self::DataProtection,
            Self::Transport,
            Self::InputValidation,
            Self::Authentication,
            Self::Configuration,
            Self::ResourceProtection,
        ]
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolSecurity => write!(f, "Tool Security"),
            Self::PromptInjection => write!(f, "Prompt Injection"),
            Self::DataProtection => write!(f, "Data Protection"),
            Self::Transport => write!(f, "Transport"),
            Self::InputValidation => write!(f, "Input Validation"),
            Self::Authentication => write!(f, "Authentication"),
            Self::Configuration => write!(f, "Configuration"),
            Self::ResourceProtection => write!(f, "Resource Protection"),
        }
    }
}

// ── Rule trait ────────────────────────────────────────────────────────

/// A security rule that checks an MCP server configuration for vulnerabilities.
pub trait Rule: Send + Sync {
    /// Unique rule identifier (e.g., "MCP-01").
    fn id(&self) -> &'static str;

    /// Human-readable rule name.
    fn name(&self) -> &'static str;

    /// Detailed description of what this rule checks.
    fn description(&self) -> &'static str;

    /// Default severity level for findings from this rule.
    fn default_severity(&self) -> Severity;

    /// OWASP MCP Top 10 category ID.
    fn owasp_id(&self) -> &'static str;

    /// Semantic category for this rule.
    ///
    /// Default implementation derives the category from the OWASP ID.
    fn category(&self) -> Category {
        Category::from_owasp_id(self.owasp_id())
    }

    /// Optional tags for fine-grained filtering (e.g., "npm", "env", "tls").
    ///
    /// Default implementation returns an empty slice.
    fn tags(&self) -> &'static [&'static str] {
        &[]
    }

    /// Check a single server configuration and return any findings.
    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding>;

    /// Evaluate a single server and return a structured [`RuleResult`].
    ///
    /// Default implementation wraps [`check`](Rule::check) — returns `Pass`
    /// if no findings, otherwise `Fail` with the findings.
    fn evaluate(&self, server_name: &str, server: &McpServerConfig) -> RuleResult {
        let findings = self.check(server_name, server);
        if findings.is_empty() {
            RuleResult::Pass
        } else {
            RuleResult::Fail(findings)
        }
    }

    /// Check the entire configuration for cross-server issues.
    ///
    /// Override this for rules that need to compare servers against each other
    /// (e.g., detecting naming conflicts). Default returns no findings.
    fn check_config(&self, _config: &McpConfig) -> Vec<ScanFinding> {
        Vec::new()
    }

    /// Evaluate the entire configuration and return a structured [`RuleResult`].
    ///
    /// Default implementation wraps [`check_config`](Rule::check_config).
    fn evaluate_config(&self, config: &McpConfig) -> RuleResult {
        let findings = self.check_config(config);
        if findings.is_empty() {
            RuleResult::Pass
        } else {
            RuleResult::Fail(findings)
        }
    }
}

// ── Rule Registry ────────────────────────────────────────────────────

/// Central registry that collects, indexes, and filters security rules.
///
/// Provides the "inventory pattern" — a single place to register and
/// query all rules. Supports filtering by severity, category, and ID.
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
    /// Create a new registry pre-loaded with all built-in rules.
    pub fn new() -> Self {
        Self {
            rules: builtin_rules(),
        }
    }

    /// Create an empty registry (useful for testing with mock rules).
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Register a new rule.
    pub fn register(&mut self, rule: Box<dyn Rule>) {
        self.rules.push(rule);
    }

    /// Number of registered rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Look up a rule by its ID (e.g., "MCP-01").
    pub fn get(&self, id: &str) -> Option<&dyn Rule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| &**r)
    }

    /// All registered rules.
    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    /// Filter rules whose default severity is at or above `min`.
    pub fn filter_by_severity(&self, min: Severity) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.default_severity() >= min)
            .map(|r| &**r)
            .collect()
    }

    /// Filter rules belonging to a specific category.
    pub fn filter_by_category(&self, category: Category) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| r.category() == category)
            .map(|r| &**r)
            .collect()
    }

    /// Filter rules by both severity and category.
    pub fn filter(
        &self,
        min_severity: Option<Severity>,
        category: Option<Category>,
    ) -> Vec<&dyn Rule> {
        self.rules
            .iter()
            .filter(|r| {
                if let Some(min) = min_severity {
                    if r.default_severity() < min {
                        return false;
                    }
                }
                if let Some(cat) = category {
                    if r.category() != cat {
                        return false;
                    }
                }
                true
            })
            .map(|r| &**r)
            .collect()
    }

    /// Group rules by category, returning a map of category -> rules.
    pub fn by_category(&self) -> HashMap<Category, Vec<&dyn Rule>> {
        let mut map: HashMap<Category, Vec<&dyn Rule>> = HashMap::new();
        for rule in &self.rules {
            map.entry(rule.category()).or_default().push(&**rule);
        }
        map
    }

    /// Return rule metadata for all registered rules.
    pub fn list_info(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                id: r.id().to_string(),
                name: r.name().to_string(),
                description: r.description().to_string(),
                severity: r.default_severity(),
                owasp_id: r.owasp_id().to_string(),
                category: r.category(),
            })
            .collect()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Scan report ──────────────────────────────────────────────────────

/// Complete scan report for one or more MCP configuration files.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    /// Source file or description.
    pub source: String,
    /// All findings across all servers.
    pub findings: Vec<ScanFinding>,
    /// Number of servers scanned.
    pub servers_scanned: usize,
    /// Number of rules applied.
    pub rules_applied: usize,
    /// Timestamp of scan.
    pub scanned_at: DateTime<Utc>,
    /// Per-server scan results for summary reporting.
    pub per_server: Vec<ServerResult>,
}

/// Result summary for a single scanned server.
#[derive(Debug, Clone, Serialize)]
pub struct ServerResult {
    /// Server name (key from the MCP config).
    pub name: String,
    /// Number of findings for this server.
    pub finding_count: usize,
    /// Whether this server passed (zero findings after filtering).
    pub passed: bool,
}

impl ScanReport {
    /// Returns true if any finding has Critical severity.
    pub fn has_critical(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical)
    }

    /// Returns true if any finding has Critical or High severity.
    pub fn has_critical_or_high(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == Severity::Critical || f.severity == Severity::High)
    }

    /// Count findings by severity.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        let mut counts: HashMap<Severity, usize> = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.severity).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.0.cmp(&a.0));
        sorted
    }

    /// Exit code for the process.
    ///
    /// - `0` — no issues found (clean scan)
    /// - `1` — one or more security findings detected
    ///
    /// Runtime errors (config parse failures, I/O, etc.) use exit code `2`,
    /// which is handled by the CLI entrypoint, not this method.
    pub fn exit_code(&self) -> i32 {
        if self.findings.is_empty() {
            0
        } else {
            1
        }
    }
}

// ── Rule Engine ──────────────────────────────────────────────────────

/// The rule engine that runs all registered rules against MCP configurations.
///
/// Supports filtering by minimum severity and by category. Uses
/// [`RuleRegistry`] internally for rule management.
pub struct RuleEngine {
    registry: RuleRegistry,
    min_severity: Option<Severity>,
    category_filter: Option<Category>,
    /// Specific rule IDs to include (empty = all).
    rule_ids: Vec<String>,
    /// Specific rule IDs to exclude.
    exclude_ids: Vec<String>,
}

impl RuleEngine {
    /// Create a new engine with all built-in rules.
    pub fn new() -> Self {
        Self {
            registry: RuleRegistry::new(),
            min_severity: None,
            category_filter: None,
            rule_ids: Vec::new(),
            exclude_ids: Vec::new(),
        }
    }

    /// Create an engine from a custom registry (useful for testing).
    pub fn with_registry(registry: RuleRegistry) -> Self {
        Self {
            registry,
            min_severity: None,
            category_filter: None,
            rule_ids: Vec::new(),
            exclude_ids: Vec::new(),
        }
    }

    /// Filter results to only include findings at or above this severity.
    pub fn with_min_severity(mut self, min: Severity) -> Self {
        self.min_severity = Some(min);
        self
    }

    /// Filter to only run rules in the specified category.
    pub fn with_category(mut self, category: Category) -> Self {
        self.category_filter = Some(category);
        self
    }

    /// Only run rules with these specific IDs.
    pub fn with_rule_ids(mut self, ids: Vec<String>) -> Self {
        self.rule_ids = ids;
        self
    }

    /// Exclude rules with these specific IDs.
    pub fn without_rule_ids(mut self, ids: Vec<String>) -> Self {
        self.exclude_ids = ids;
        self
    }

    /// Access the underlying registry.
    pub fn registry(&self) -> &RuleRegistry {
        &self.registry
    }

    /// Number of rules that will be executed (after filters).
    pub fn rule_count(&self) -> usize {
        self.active_rules().len()
    }

    /// Returns the set of rules that pass all configured filters.
    fn active_rules(&self) -> Vec<&dyn Rule> {
        self.registry
            .rules()
            .iter()
            .filter(|r| {
                // Category filter.
                if let Some(cat) = self.category_filter {
                    if r.category() != cat {
                        return false;
                    }
                }
                // Include list (empty = include all).
                if !self.rule_ids.is_empty() && !self.rule_ids.iter().any(|id| id == r.id()) {
                    return false;
                }
                // Exclude list.
                if self.exclude_ids.iter().any(|id| id == r.id()) {
                    return false;
                }
                true
            })
            .map(|r| &**r)
            .collect()
    }

    /// Scan a parsed MCP configuration and return a report.
    pub fn scan(&self, config: &McpConfig) -> ScanReport {
        let active = self.active_rules();
        let mut findings = Vec::new();
        let mut per_server = Vec::new();

        // Sort server names for deterministic output.
        let mut server_names: Vec<&String> = config.mcp_servers.keys().collect();
        server_names.sort();

        for server_name in server_names {
            let server_config = &config.mcp_servers[server_name];
            let mut server_finding_count = 0;

            for rule in &active {
                let result = rule.evaluate(server_name, server_config);
                let mut rule_findings = result.findings();

                // Apply severity filter on individual findings.
                if let Some(min) = self.min_severity {
                    rule_findings.retain(|f| f.severity >= min);
                }

                server_finding_count += rule_findings.len();
                findings.extend(rule_findings);
            }

            per_server.push(ServerResult {
                name: server_name.clone(),
                finding_count: server_finding_count,
                passed: server_finding_count == 0,
            });
        }

        // Run config-level cross-server checks.
        for rule in &active {
            let result = rule.evaluate_config(config);
            let mut config_findings = result.findings();

            if let Some(min) = self.min_severity {
                config_findings.retain(|f| f.severity >= min);
            }

            findings.extend(config_findings);
        }

        // Sort by severity (descending), then by rule ID.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        ScanReport {
            source: config
                .source_path
                .clone()
                .unwrap_or_else(|| "<stdin>".to_string()),
            findings,
            servers_scanned: config.mcp_servers.len(),
            rules_applied: active.len(),
            scanned_at: Utc::now(),
            per_server,
        }
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public helpers ───────────────────────────────────────────────────

/// Returns all built-in security rules.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    builtin_rules()
}

/// List all available rule metadata (for documentation / --list-rules).
pub fn list_rules() -> Vec<RuleInfo> {
    RuleRegistry::new().list_info()
}

/// Metadata about a rule, for display/documentation.
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub owasp_id: String,
    pub category: Category,
}

// ── Internal: built-in rule inventory ────────────────────────────────

/// Construct all built-in rules. This is the single registration point;
/// every new rule file must add its struct here.
fn builtin_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(mcp01_tool_poisoning::ToolPoisoningRule),
        Box::new(mcp02_excessive_permissions::ExcessivePermissionsRule),
        Box::new(mcp03_prompt_injection::PromptInjectionRule),
        Box::new(mcp04_insecure_credentials::InsecureCredentialsRule),
        Box::new(mcp05_server_spoofing::ServerSpoofingRule),
        Box::new(mcp06_insecure_dependencies::InsecureDependenciesRule),
        Box::new(mcp07_command_injection::CommandInjectionRule),
        Box::new(mcp08_data_exfiltration::DataExfiltrationRule),
        Box::new(mcp09_insufficient_logging::InsufficientLoggingRule),
        Box::new(mcp10_unauthorized_access::UnauthorizedAccessRule),
        Box::new(mcp11_denial_of_service::DenialOfServiceRule),
        Box::new(mcp12_tool_shadowing::ToolShadowingRule),
        Box::new(mcp13_resource_exposure::ResourceExposureRule),
        Box::new(mcp14_insecure_transport::InsecureTransportRule),
        Box::new(mcp15_tool_injection::ToolInjectionRule),
        Box::new(mcp16_missing_input_validation::MissingInputValidationRule),
        Box::new(mcp17_data_leakage::DataLeakageRule),
        Box::new(mcp18_prompt_injection_vectors::PromptInjectionVectorsRule),
        Box::new(mcp19_excessive_tool_permissions::ExcessiveToolPermissionsRule),
    ]
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::McpConfig;

    // ── Mock rules for testing ───────────────────────────────────────

    /// A mock rule that always passes (returns no findings).
    struct PassingRule;
    impl Rule for PassingRule {
        fn id(&self) -> &'static str {
            "MOCK-PASS"
        }
        fn name(&self) -> &'static str {
            "Always Passes"
        }
        fn description(&self) -> &'static str {
            "A mock rule that always passes."
        }
        fn default_severity(&self) -> Severity {
            Severity::Info
        }
        fn owasp_id(&self) -> &'static str {
            "OWASP-MCP-99"
        }
        fn check(&self, _server_name: &str, _server: &McpServerConfig) -> Vec<ScanFinding> {
            Vec::new()
        }
    }

    /// A mock rule that always fails with one finding.
    struct FailingRule {
        severity: Severity,
    }
    impl Rule for FailingRule {
        fn id(&self) -> &'static str {
            "MOCK-FAIL"
        }
        fn name(&self) -> &'static str {
            "Always Fails"
        }
        fn description(&self) -> &'static str {
            "A mock rule that always produces a finding."
        }
        fn default_severity(&self) -> Severity {
            self.severity
        }
        fn owasp_id(&self) -> &'static str {
            "OWASP-MCP-98"
        }
        fn check(&self, server_name: &str, _server: &McpServerConfig) -> Vec<ScanFinding> {
            vec![ScanFinding {
                rule_id: self.id().to_string(),
                severity: self.severity,
                title: format!("Mock finding on '{}'", server_name),
                description: "This is a mock finding for testing.".to_string(),
            }]
        }
    }

    /// A mock rule that skips (uses evaluate override).
    struct SkippingRule;
    impl Rule for SkippingRule {
        fn id(&self) -> &'static str {
            "MOCK-SKIP"
        }
        fn name(&self) -> &'static str {
            "Always Skips"
        }
        fn description(&self) -> &'static str {
            "A mock rule that always skips."
        }
        fn default_severity(&self) -> Severity {
            Severity::Medium
        }
        fn owasp_id(&self) -> &'static str {
            "OWASP-MCP-97"
        }
        fn check(&self, _server_name: &str, _server: &McpServerConfig) -> Vec<ScanFinding> {
            Vec::new()
        }
        fn evaluate(&self, _server_name: &str, _server: &McpServerConfig) -> RuleResult {
            RuleResult::Skip("Server type not applicable".to_string())
        }
    }

    /// A mock rule with a specific category and severity.
    struct CategorizedRule {
        id: &'static str,
        severity: Severity,
        owasp_id: &'static str,
    }
    impl Rule for CategorizedRule {
        fn id(&self) -> &'static str {
            self.id
        }
        fn name(&self) -> &'static str {
            "Categorized Mock"
        }
        fn description(&self) -> &'static str {
            "A mock rule with configurable category."
        }
        fn default_severity(&self) -> Severity {
            self.severity
        }
        fn owasp_id(&self) -> &'static str {
            self.owasp_id
        }
        fn check(&self, server_name: &str, _server: &McpServerConfig) -> Vec<ScanFinding> {
            vec![ScanFinding {
                rule_id: self.id.to_string(),
                severity: self.severity,
                title: format!("Finding from {} on '{}'", self.id, server_name),
                description: "Categorized mock finding.".to_string(),
            }]
        }
    }

    fn empty_config() -> McpConfig {
        McpConfig::parse(r#"{"mcpServers": {}}"#).unwrap()
    }

    fn single_server_config() -> McpConfig {
        McpConfig::parse(
            r#"{
            "mcpServers": {
                "test-server": { "command": "node", "args": ["server.js"] }
            }
        }"#,
        )
        .unwrap()
    }

    // ── RuleResult tests ─────────────────────────────────────────────

    #[test]
    fn rule_result_pass() {
        let result = RuleResult::Pass;
        assert!(result.is_pass());
        assert!(!result.is_fail());
        assert!(!result.is_skip());
        assert!(result.findings().is_empty());
        assert!(result.skip_reason().is_none());
    }

    #[test]
    fn rule_result_fail() {
        let findings = vec![ScanFinding {
            rule_id: "TEST-01".into(),
            severity: Severity::High,
            title: "Test".into(),
            description: "Test finding".into(),
        }];
        let result = RuleResult::Fail(findings.clone());
        assert!(result.is_fail());
        assert!(!result.is_pass());
        assert!(!result.is_skip());
        assert_eq!(result.findings().len(), 1);
        assert!(result.skip_reason().is_none());
    }

    #[test]
    fn rule_result_fail_empty_is_not_fail() {
        let result = RuleResult::Fail(Vec::new());
        assert!(
            !result.is_fail(),
            "Fail with empty findings is not a failure"
        );
    }

    #[test]
    fn rule_result_skip() {
        let result = RuleResult::Skip("not applicable".to_string());
        assert!(result.is_skip());
        assert!(!result.is_pass());
        assert!(!result.is_fail());
        assert!(result.findings().is_empty());
        assert_eq!(result.skip_reason(), Some("not applicable"));
    }

    // ── Category tests ───────────────────────────────────────────────

    #[test]
    fn category_from_owasp_id() {
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-01"),
            Category::ToolSecurity
        );
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-03"),
            Category::PromptInjection
        );
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-04"),
            Category::DataProtection
        );
        assert_eq!(Category::from_owasp_id("OWASP-MCP-05"), Category::Transport);
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-07"),
            Category::InputValidation
        );
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-10"),
            Category::Authentication
        );
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-06"),
            Category::Configuration
        );
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-11"),
            Category::ResourceProtection
        );
    }

    #[test]
    fn category_unknown_defaults_to_configuration() {
        assert_eq!(
            Category::from_owasp_id("OWASP-MCP-99"),
            Category::Configuration
        );
    }

    #[test]
    fn category_all_returns_all_variants() {
        let all = Category::all();
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn category_display() {
        assert_eq!(Category::ToolSecurity.to_string(), "Tool Security");
        assert_eq!(Category::PromptInjection.to_string(), "Prompt Injection");
        assert_eq!(Category::DataProtection.to_string(), "Data Protection");
        assert_eq!(Category::Transport.to_string(), "Transport");
        assert_eq!(Category::InputValidation.to_string(), "Input Validation");
        assert_eq!(Category::Authentication.to_string(), "Authentication");
        assert_eq!(Category::Configuration.to_string(), "Configuration");
        assert_eq!(
            Category::ResourceProtection.to_string(),
            "Resource Protection"
        );
    }

    // ── Mock rule evaluation tests ───────────────────────────────────

    #[test]
    fn passing_rule_evaluate_returns_pass() {
        let rule = PassingRule;
        let server = McpServerConfig::default();
        let result = rule.evaluate("test", &server);
        assert!(result.is_pass());
    }

    #[test]
    fn failing_rule_evaluate_returns_fail() {
        let rule = FailingRule {
            severity: Severity::High,
        };
        let server = McpServerConfig::default();
        let result = rule.evaluate("test", &server);
        assert!(result.is_fail());
        assert_eq!(result.findings().len(), 1);
        assert_eq!(result.findings()[0].severity, Severity::High);
    }

    #[test]
    fn skipping_rule_evaluate_returns_skip() {
        let rule = SkippingRule;
        let server = McpServerConfig::default();
        let result = rule.evaluate("test", &server);
        assert!(result.is_skip());
        assert_eq!(result.skip_reason(), Some("Server type not applicable"));
    }

    #[test]
    fn rule_default_category_from_owasp_id() {
        let rule = FailingRule {
            severity: Severity::High,
        };
        // owasp_id is "OWASP-MCP-98", unknown number -> Configuration
        assert_eq!(rule.category(), Category::Configuration);
    }

    // ── RuleRegistry tests ───────────────────────────────────────────

    #[test]
    fn registry_new_has_all_builtin_rules() {
        let registry = RuleRegistry::new();
        assert_eq!(registry.len(), 19, "Expected 19 built-in security rules");
    }

    #[test]
    fn registry_empty_has_no_rules() {
        let registry = RuleRegistry::empty();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn registry_register_adds_rule() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(PassingRule));
        assert_eq!(registry.len(), 1);
        assert!(registry.get("MOCK-PASS").is_some());
    }

    #[test]
    fn registry_get_by_id() {
        let registry = RuleRegistry::new();
        let rule = registry.get("MCP-01");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name(), "Tool Poisoning");

        assert!(registry.get("NONEXISTENT").is_none());
    }

    #[test]
    fn registry_rule_ids_are_unique() {
        let registry = RuleRegistry::new();
        let mut ids: Vec<&str> = registry.rules().iter().map(|r| r.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 19, "Rule IDs must be unique");
    }

    #[test]
    fn registry_filter_by_severity() {
        let registry = RuleRegistry::new();

        let critical = registry.filter_by_severity(Severity::Critical);
        assert!(
            !critical.is_empty(),
            "Should have at least one critical rule"
        );
        for r in &critical {
            assert_eq!(r.default_severity(), Severity::Critical);
        }

        let high_plus = registry.filter_by_severity(Severity::High);
        assert!(
            high_plus.len() >= critical.len(),
            "High+ should include critical rules"
        );
    }

    #[test]
    fn registry_filter_by_category() {
        let registry = RuleRegistry::new();

        let tool_sec = registry.filter_by_category(Category::ToolSecurity);
        assert!(!tool_sec.is_empty(), "Should have tool security rules");
        for r in &tool_sec {
            assert_eq!(r.category(), Category::ToolSecurity);
        }

        let transport = registry.filter_by_category(Category::Transport);
        assert!(!transport.is_empty(), "Should have transport rules");
    }

    #[test]
    fn registry_filter_combined() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(CategorizedRule {
            id: "CAT-01",
            severity: Severity::Critical,
            owasp_id: "OWASP-MCP-01", // ToolSecurity
        }));
        registry.register(Box::new(CategorizedRule {
            id: "CAT-02",
            severity: Severity::Low,
            owasp_id: "OWASP-MCP-01", // ToolSecurity
        }));
        registry.register(Box::new(CategorizedRule {
            id: "CAT-03",
            severity: Severity::Critical,
            owasp_id: "OWASP-MCP-05", // Transport
        }));

        // Filter: ToolSecurity + Critical
        let filtered = registry.filter(Some(Severity::Critical), Some(Category::ToolSecurity));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id(), "CAT-01");

        // Filter: severity only
        let critical = registry.filter(Some(Severity::Critical), None);
        assert_eq!(critical.len(), 2);

        // Filter: category only
        let tool = registry.filter(None, Some(Category::ToolSecurity));
        assert_eq!(tool.len(), 2);

        // No filter
        let all = registry.filter(None, None);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn registry_by_category_groups_correctly() {
        let registry = RuleRegistry::new();
        let grouped = registry.by_category();
        assert!(!grouped.is_empty());

        // Every rule must appear in exactly one category.
        let total: usize = grouped.values().map(|v| v.len()).sum();
        assert_eq!(total, 19);
    }

    #[test]
    fn registry_list_info_includes_category() {
        let registry = RuleRegistry::new();
        let infos = registry.list_info();
        assert_eq!(infos.len(), 19);
        for info in &infos {
            assert!(!info.id.is_empty());
            assert!(!info.name.is_empty());
            assert!(!info.description.is_empty());
            assert!(!info.owasp_id.is_empty());
            // Category should be valid (not panic).
            let _ = info.category.to_string();
        }
    }

    // ── RuleEngine tests ─────────────────────────────────────────────

    #[test]
    fn engine_scan_empty_config() {
        let engine = RuleEngine::new();
        let config = empty_config();
        let report = engine.scan(&config);
        assert_eq!(report.servers_scanned, 0);
        assert!(report.findings.is_empty());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn engine_with_mock_registry() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(FailingRule {
            severity: Severity::High,
        }));
        registry.register(Box::new(PassingRule));

        let engine = RuleEngine::with_registry(registry);
        assert_eq!(engine.rule_count(), 2);

        let config = single_server_config();
        let report = engine.scan(&config);

        // One server, one failing rule = 1 finding.
        assert_eq!(report.servers_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn engine_skipping_rule_produces_no_findings() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(SkippingRule));

        let engine = RuleEngine::with_registry(registry);
        let config = single_server_config();
        let report = engine.scan(&config);

        assert!(report.findings.is_empty());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn engine_severity_filter() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(FailingRule {
            severity: Severity::Low,
        }));

        let engine = RuleEngine::with_registry(registry).with_min_severity(Severity::High);
        let config = single_server_config();
        let report = engine.scan(&config);

        assert!(
            report.findings.is_empty(),
            "Low-severity finding should be filtered out"
        );
    }

    #[test]
    fn engine_category_filter() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(CategorizedRule {
            id: "CAT-TOOL",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-01", // ToolSecurity
        }));
        registry.register(Box::new(CategorizedRule {
            id: "CAT-TRANS",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-05", // Transport
        }));

        let engine = RuleEngine::with_registry(registry).with_category(Category::ToolSecurity);
        let config = single_server_config();
        let report = engine.scan(&config);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "CAT-TOOL");
        assert_eq!(report.rules_applied, 1);
    }

    #[test]
    fn engine_rule_id_include_filter() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(CategorizedRule {
            id: "RULE-A",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-01",
        }));
        registry.register(Box::new(CategorizedRule {
            id: "RULE-B",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-05",
        }));

        let engine = RuleEngine::with_registry(registry).with_rule_ids(vec!["RULE-A".to_string()]);
        let config = single_server_config();
        let report = engine.scan(&config);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "RULE-A");
    }

    #[test]
    fn engine_rule_id_exclude_filter() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(CategorizedRule {
            id: "RULE-A",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-01",
        }));
        registry.register(Box::new(CategorizedRule {
            id: "RULE-B",
            severity: Severity::High,
            owasp_id: "OWASP-MCP-05",
        }));

        let engine =
            RuleEngine::with_registry(registry).without_rule_ids(vec!["RULE-A".to_string()]);
        let config = single_server_config();
        let report = engine.scan(&config);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "RULE-B");
    }

    // ── Backward-compatibility tests (migrated from previous version) ──

    #[test]
    fn all_rules_are_registered() {
        let rules = all_rules();
        assert_eq!(rules.len(), 19, "Expected 19 security rules");
    }

    #[test]
    fn rule_ids_are_unique() {
        let rules = all_rules();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 19, "Rule IDs must be unique");
    }

    #[test]
    fn scan_with_severity_filter() {
        let engine = RuleEngine::new().with_min_severity(Severity::High);
        let config = McpConfig::parse(
            r#"{
            "mcpServers": {
                "test": { "command": "sh", "args": ["-c", "echo hello"] }
            }
        }"#,
        )
        .unwrap();
        let report = engine.scan(&config);
        // All findings should be High or Critical.
        for f in &report.findings {
            assert!(
                f.severity >= Severity::High,
                "Finding {} has severity {:?}, expected >= High",
                f.rule_id,
                f.severity
            );
        }
    }

    #[test]
    fn scan_report_severity_counts() {
        let engine = RuleEngine::new();
        let config = McpConfig::parse(
            r#"{
            "mcpServers": {
                "bad": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"],
                    "env": { "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }
                }
            }
        }"#,
        )
        .unwrap();
        let report = engine.scan(&config);
        assert!(
            !report.findings.is_empty(),
            "Should have findings for insecure config"
        );
        let counts = report.severity_counts();
        assert!(!counts.is_empty());
    }

    #[test]
    fn list_rules_returns_metadata() {
        let infos = list_rules();
        assert_eq!(infos.len(), 19);
        for info in &infos {
            assert!(!info.id.is_empty());
            assert!(!info.name.is_empty());
            assert!(!info.description.is_empty());
            assert!(!info.owasp_id.is_empty());
        }
    }

    #[test]
    fn exit_code_zero_when_clean() {
        let engine = RuleEngine::new();
        let config = McpConfig::parse(r#"{"mcpServers": {}}"#).unwrap();
        let report = engine.scan(&config);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_one_for_any_findings() {
        use crate::scanner::ScanFinding;

        // Medium-only findings should still return exit code 1.
        let report = ScanReport {
            source: "<test>".to_string(),
            findings: vec![ScanFinding {
                rule_id: "MCP-09".into(),
                severity: Severity::Medium,
                title: "Medium finding".into(),
                description: "A medium severity issue".into(),
            }],
            servers_scanned: 1,
            rules_applied: 10,
            scanned_at: chrono::Utc::now(),
            per_server: vec![],
        };
        assert_eq!(
            report.exit_code(),
            1,
            "Any finding should produce exit code 1"
        );

        // Low-only findings should also return exit code 1.
        let report_low = ScanReport {
            source: "<test>".to_string(),
            findings: vec![ScanFinding {
                rule_id: "MCP-09".into(),
                severity: Severity::Low,
                title: "Low finding".into(),
                description: "A low severity issue".into(),
            }],
            servers_scanned: 1,
            rules_applied: 10,
            scanned_at: chrono::Utc::now(),
            per_server: vec![],
        };
        assert_eq!(
            report_low.exit_code(),
            1,
            "Low findings should also produce exit code 1"
        );

        // Critical findings should also return exit code 1.
        let report_crit = ScanReport {
            source: "<test>".to_string(),
            findings: vec![ScanFinding {
                rule_id: "MCP-07".into(),
                severity: Severity::Critical,
                title: "Critical finding".into(),
                description: "A critical issue".into(),
            }],
            servers_scanned: 1,
            rules_applied: 10,
            scanned_at: chrono::Utc::now(),
            per_server: vec![],
        };
        assert_eq!(
            report_crit.exit_code(),
            1,
            "Critical findings should produce exit code 1"
        );
    }

    #[test]
    fn scan_findings_sorted_by_severity() {
        let engine = RuleEngine::new();
        let config = McpConfig::parse(
            r#"{
            "mcpServers": {
                "bad": {
                    "command": "sh",
                    "args": ["-c", "eval $INPUT"],
                    "env": { "SECRET_KEY": "sk-abc123def456ghi789jkl012" }
                }
            }
        }"#,
        )
        .unwrap();
        let report = engine.scan(&config);

        // Verify findings are sorted by severity (descending).
        for window in report.findings.windows(2) {
            assert!(
                window[0].severity >= window[1].severity,
                "Findings not sorted: {:?} should come before {:?}",
                window[0].severity,
                window[1].severity
            );
        }
    }

    // ── Engine with builtin rules: full integration ──────────────────

    #[test]
    fn engine_builtin_scan_detects_insecure_server() {
        let engine = RuleEngine::new();
        let config = McpConfig::parse(
            r#"{
            "mcpServers": {
                "dangerous": {
                    "command": "sh",
                    "args": ["-c", "eval $UNTRUSTED"],
                    "env": { "API_KEY": "sk-1234567890abcdef1234567890abcdef" }
                }
            }
        }"#,
        )
        .unwrap();
        let report = engine.scan(&config);

        assert!(
            !report.findings.is_empty(),
            "Should detect issues in dangerous config"
        );
        assert_eq!(report.servers_scanned, 1);
        assert_eq!(report.rules_applied, 19);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn engine_builtin_category_filter_reduces_rules() {
        let engine_all = RuleEngine::new();
        let engine_filtered = RuleEngine::new().with_category(Category::Transport);

        assert!(
            engine_filtered.rule_count() < engine_all.rule_count(),
            "Category filter should reduce rule count"
        );
        assert!(engine_filtered.rule_count() > 0);
    }

    #[test]
    fn engine_multiple_servers_per_server_results() {
        let mut registry = RuleRegistry::empty();
        registry.register(Box::new(FailingRule {
            severity: Severity::Medium,
        }));

        let engine = RuleEngine::with_registry(registry);
        let config = McpConfig::parse(
            r#"{
            "mcpServers": {
                "server-a": { "command": "node", "args": ["a.js"] },
                "server-b": { "command": "node", "args": ["b.js"] }
            }
        }"#,
        )
        .unwrap();
        let report = engine.scan(&config);

        assert_eq!(report.servers_scanned, 2);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.per_server.len(), 2);

        for sr in &report.per_server {
            assert_eq!(sr.finding_count, 1);
            assert!(!sr.passed);
        }
    }
}
