use clap::{Parser, Subcommand, ValueEnum};

/// MCP Security Scanner -- "npm audit" for MCP servers.
#[derive(Debug, Parser)]
#[command(name = "mcp-audit", version, about, long_about = None)]
pub struct Cli {
    /// GitHub personal access token (or set GITHUB_TOKEN env var).
    #[arg(long, env = "GITHUB_TOKEN", global = true, hide_env_values = true)]
    pub github_token: Option<String>,

    /// NVD API key for higher rate limits (or set NVD_API_KEY env var).
    #[arg(long, env = "NVD_API_KEY", global = true, hide_env_values = true)]
    pub nvd_api_key: Option<String>,

    /// Directory for persisted state (watermarks, cache).
    #[arg(long, env = "MCP_SCANNER_STATE_DIR", global = true)]
    pub state_dir: Option<String>,

    /// Output format.
    #[arg(long, short = 'f', global = true, default_value = "table")]
    pub format: FormatArg,

    /// Enable verbose (debug) logging.
    #[arg(long, short = 'v', global = true, default_value_t = false)]
    pub verbose: bool,

    /// Suppress all output except errors.
    #[arg(long, short = 'q', global = true, default_value_t = false)]
    pub quiet: bool,

    /// Disable colored output (also respects NO_COLOR env var).
    #[arg(long, global = true, default_value_t = false)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

// ── Subcommands ────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Poll ecosystem monitors for new events.
    Monitor(MonitorArgs),

    /// Generate a weekly digest report.
    Digest(DigestArgs),

    /// Scan MCP server configurations for security vulnerabilities.
    Scan(ScanArgs),

    /// Initialize a sample MCP scanner configuration.
    Init(InitArgs),

    /// List all available security rules.
    Rules,

    /// Show the current state of all monitors and watermarks.
    Status,

    /// Display or validate configuration.
    Config(ConfigArgs),
}

// ── Monitor ────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct MonitorArgs {
    /// Which source(s) to poll.
    #[arg(long, short = 's', default_value = "all")]
    pub source: SourceFilter,

    /// Only return events after this ISO-8601 timestamp.
    #[arg(long)]
    pub since: Option<String>,

    /// Continuously watch for new events (long-running).
    #[arg(long, default_value_t = false)]
    pub watch: bool,

    /// Polling interval in seconds when --watch is active.
    #[arg(long, default_value_t = 300)]
    pub interval: u64,

    /// Maximum number of results per source.
    #[arg(long, default_value_t = 50)]
    pub max_results: usize,
}

// ── Digest ─────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct DigestArgs {
    /// Generate for the previous ISO week (Mon-Sun).
    #[arg(long)]
    pub week: Option<String>,

    /// Write the digest to a file instead of stdout.
    #[arg(long, short = 'o')]
    pub output: Option<String>,
}

// ── Scan ───────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Path to MCP configuration file to scan (e.g., claude_desktop_config.json).
    /// Auto-detects config files when neither --config, --server, nor --url is given.
    #[arg(long, short = 'c', visible_alias = "source")]
    pub config: Option<String>,

    /// Scan a single stdio server by its full command line.
    /// Example: --server "npx @modelcontextprotocol/server-filesystem /"
    #[arg(long)]
    pub server: Option<String>,

    /// Scan a single HTTP/SSE server by URL.
    /// Example: --url "https://mcp.example.com/sse"
    #[arg(long)]
    pub url: Option<String>,

    /// Minimum severity level to report (filters out lower severities).
    /// Accepts a single value or comma-separated list: --severity high,critical
    #[arg(long)]
    pub severity: Option<String>,

    /// Write the scan report to a file instead of stdout.
    #[arg(long, short = 'o')]
    pub output: Option<String>,
}

// ── Init ──────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Path to write the scanner configuration file.
    #[arg(long, short = 'o', default_value = ".mcp-audit.toml")]
    pub output: String,

    /// Generate CI-friendly configuration (SARIF output, strict thresholds).
    #[arg(long, default_value_t = false)]
    pub ci: bool,

    /// Overwrite the configuration file if it already exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

// ── Config ─────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
pub struct ConfigArgs {
    /// Reveal secret values (tokens, keys) in output.
    #[arg(long, default_value_t = false)]
    pub show_secrets: bool,
}

// ── Shared value enums ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FormatArg {
    Json,
    Table,
    Markdown,
    Sarif,
}

impl From<FormatArg> for crate::config::OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Json => Self::Json,
            FormatArg::Table => Self::Table,
            FormatArg::Markdown => Self::Markdown,
            FormatArg::Sarif => Self::Sarif,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SourceFilter {
    Github,
    Cve,
    Owasp,
    Adoption,
    All,
}

/// Severity filter for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SeverityFilter {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityFilter> for crate::monitors::Severity {
    fn from(f: SeverityFilter) -> Self {
        match f {
            SeverityFilter::Critical => Self::Critical,
            SeverityFilter::High => Self::High,
            SeverityFilter::Medium => Self::Medium,
            SeverityFilter::Low => Self::Low,
            SeverityFilter::Info => Self::Info,
        }
    }
}
