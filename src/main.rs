use anyhow::Context;
use chrono::{DateTime, Utc};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use mcp_audit::cli::{Cli, Command, SourceFilter};
use mcp_audit::config::{AppConfig, OutputFormat};
use mcp_audit::digest;
use mcp_audit::http::RateLimitedClient;
use mcp_audit::monitors::adoption::AdoptionMonitor;
use mcp_audit::monitors::cve::CveMonitor;
use mcp_audit::monitors::github::GitHubMonitor;
use mcp_audit::monitors::owasp::OwaspMonitor;
use mcp_audit::monitors::{Monitor, MonitorEvent, PollOptions};
use mcp_audit::output;
use mcp_audit::parser::McpConfig;
use mcp_audit::rules::RuleEngine;
use mcp_audit::storage::{FileStateStore, StateStore};

#[tokio::main]
async fn main() {
    // Delegate to an inner function so we can map errors to exit code 2.
    let code = match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            2 // exit code 2 = runtime error
        }
    };
    if code != 0 {
        std::process::exit(code);
    }
}

async fn run() -> anyhow::Result<i32> {
    // Load .env if present (silently ignore if missing).
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Disable colors if --no-color flag is set or NO_COLOR env var is present.
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() {
        colored::control::set_override(false);
    }

    // Initialise tracing.
    init_tracing(cli.verbose, cli.quiet);

    let config = build_config(&cli)?;

    match &cli.command {
        Command::Monitor(args) => {
            run_monitor(&config, args).await?;
        }
        Command::Digest(args) => {
            run_digest(&config, args).await?;
        }
        Command::Scan(args) => {
            let exit_code = run_scan(&config, args, cli.no_color)?;
            return Ok(exit_code);
        }
        Command::Init(args) => {
            run_init(args)?;
        }
        Command::Rules => {
            run_list_rules();
        }
        Command::Status => {
            run_status(&config).await?;
        }
        Command::Config(args) => {
            show_config(&config, args.show_secrets);
        }
    }

    Ok(0)
}

// ── Monitor command ─────────────────────────────────────────────────────

async fn run_monitor(config: &AppConfig, args: &mcp_audit::cli::MonitorArgs) -> anyhow::Result<()> {
    let client = RateLimitedClient::new(config);
    let store = FileStateStore::new(config.state_dir()).context("Failed to open state store")?;

    // Parse --since flag.
    let since: Option<DateTime<Utc>> = args
        .since
        .as_deref()
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .with_context(|| format!("Invalid --since timestamp: {s}"))
        })
        .transpose()?;

    // Build monitors based on --source filter.
    let monitors: Vec<Box<dyn Monitor>> = build_monitors(&args.source, client);

    loop {
        let mut all_events: Vec<MonitorEvent> = Vec::new();

        for monitor in &monitors {
            let name = monitor.name();
            tracing::info!(monitor = %name, "Polling");

            // Use watermark from store if --since not provided.
            let effective_since = match since {
                Some(ts) => Some(ts),
                None => store.get_checkpoint(name).await.unwrap_or(None),
            };

            let opts = PollOptions {
                since: effective_since,
                max_results: args.max_results,
            };

            match monitor.poll(&opts).await {
                Ok(events) => {
                    tracing::info!(
                        monitor = %name,
                        events = events.len(),
                        "Poll complete"
                    );
                    if !events.is_empty() {
                        // Update watermark to now.
                        let _ = store.set_checkpoint(name, Utc::now()).await;
                        // Store events.
                        let _ = store.store_events(&events).await;
                        all_events.extend(events);
                    }
                }
                Err(e) => {
                    tracing::error!(monitor = %name, error = %e, "Poll failed");
                }
            }
        }

        // Output results.
        if !all_events.is_empty() {
            all_events.sort_by(|a, b| b.discovered_at.cmp(&a.discovered_at));
            let rendered = output::render_events(&all_events, config.output_format);
            println!("{}", rendered);
        }

        println!("\n{}", output::render_summary(&all_events));

        if !args.watch {
            break;
        }

        tracing::info!(interval_secs = args.interval, "Sleeping until next poll");
        tokio::time::sleep(std::time::Duration::from_secs(args.interval)).await;
    }

    Ok(())
}

// ── Digest command ──────────────────────────────────────────────────────

async fn run_digest(config: &AppConfig, args: &mcp_audit::cli::DigestArgs) -> anyhow::Result<()> {
    let store = FileStateStore::new(config.state_dir()).context("Failed to open state store")?;

    // Load all stored events.
    let events = store
        .get_events(None, None)
        .await
        .context("Failed to load events from store")?;

    if events.is_empty() {
        eprintln!("No events in store. Run `mcp-audit monitor` first to collect data.");
        return Ok(());
    }

    let weekly_digest = digest::build_digest(events, args.week.as_deref(), false);

    let rendered = output::render_digest(&weekly_digest, config.output_format);

    // Write to file or stdout.
    if let Some(ref output_path) = args.output {
        std::fs::write(output_path, &rendered)
            .with_context(|| format!("Failed to write digest to {output_path}"))?;
        eprintln!("Digest written to {}", output_path);
    } else {
        println!("{}", rendered);
    }

    Ok(())
}

// ── Scan command ───────────────────────────────────────────────────────

fn run_scan(
    config: &AppConfig,
    args: &mcp_audit::cli::ScanArgs,
    no_color: bool,
) -> anyhow::Result<i32> {
    use colored::Colorize;
    use indicatif::{ProgressBar, ProgressStyle};

    // Validate mutually exclusive input modes.
    let input_count = [
        args.config.is_some(),
        args.server.is_some(),
        args.url.is_some(),
    ]
    .iter()
    .filter(|&&x| x)
    .count();
    if input_count > 1 {
        anyhow::bail!(
            "Conflicting options: --config, --server, and --url are mutually exclusive.\n\
             Use only one input source at a time."
        );
    }

    // Build the MCP config from the chosen input mode.
    let mcp_config = if let Some(ref server_cmd) = args.server {
        // Mode: single stdio server from command line.
        tracing::info!(command = %server_cmd, "Scanning single server from command line");
        McpConfig::from_server_command(server_cmd)
            .with_context(|| format!("Failed to parse server command: {server_cmd}"))?
    } else if let Some(ref url) = args.url {
        // Mode: single HTTP/SSE server from URL.
        tracing::info!(url = %url, "Scanning single server from URL");
        McpConfig::from_url(url).with_context(|| format!("Failed to parse server URL: {url}"))?
    } else {
        // Mode: config file (explicit path or auto-detect).
        let config_path = match &args.config {
            Some(path) => {
                let p = std::path::PathBuf::from(path);
                if !p.exists() {
                    anyhow::bail!("Configuration file not found: {}", path);
                }
                p
            }
            None => {
                // Auto-detect config files.
                let found = McpConfig::find_config_files();
                if found.is_empty() {
                    eprintln!("{} No MCP configuration files found.", "!".yellow().bold());
                    eprintln!(
                        "  Searched: claude_desktop_config.json, .mcp.json, mcp.json, .mcp/*.json"
                    );
                    eprintln!(
                        "  Tip: Use {} to specify a file, or {} to create one.",
                        "--config <path>".bold(),
                        "mcp-audit init".bold()
                    );
                    return Ok(0);
                }
                if found.len() > 1 {
                    eprintln!("{} Found {} config files:", "i".cyan().bold(), found.len());
                    for f in &found {
                        eprintln!("    {}", f.display());
                    }
                    eprintln!("  Using: {}", found[0].display().to_string().bold());
                }
                found[0].clone()
            }
        };

        tracing::info!(path = %config_path.display(), "Scanning MCP configuration file");

        McpConfig::from_file(&config_path)
            .with_context(|| format!("Failed to parse {}", config_path.display()))?
    };

    if mcp_config.mcp_servers.is_empty() {
        eprintln!(
            "{} No MCP servers found in configuration.",
            "!".yellow().bold()
        );
        return Ok(0);
    }

    // Parse severity filter.
    let min_severity = match &args.severity {
        Some(sev_str) => Some(parse_severity_filter(sev_str)?),
        None => None,
    };

    // Build the rule engine with optional severity filter.
    let mut engine = RuleEngine::new();
    if let Some(sev) = min_severity {
        engine = engine.with_min_severity(sev);
    }

    // Show progress spinner.
    let server_count = mcp_config.mcp_servers.len();
    let rule_count = engine.rule_count();
    let spinner = if !config.verbose && atty::is(atty::Stream::Stderr) {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message(format!(
            "Scanning {} server(s) with {} rules...",
            server_count, rule_count
        ));
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    // Run the scan.
    let report = engine.scan(&mcp_config);
    let exit_code = report.exit_code();

    // Stop spinner.
    if let Some(pb) = spinner {
        let icon = if report.findings.is_empty() {
            "✓".green().bold().to_string()
        } else {
            "✗".red().bold().to_string()
        };
        pb.finish_with_message(format!(
            "{} Scan complete — {} finding(s) across {} server(s)",
            icon,
            report.findings.len(),
            server_count
        ));
    }

    // Render detailed output.
    let rendered = output::render_scan_report_with_opts(&report, config.output_format, no_color);

    // Render summary only for human-readable table format;
    // machine-readable formats (JSON, SARIF, Markdown) must produce clean output.
    let summary = if config.output_format == OutputFormat::Table {
        Some(output::render_scan_summary(&report))
    } else {
        None
    };

    // Write to file or stdout.
    if let Some(ref output_path) = args.output {
        std::fs::write(output_path, &rendered)
            .with_context(|| format!("Failed to write report to {output_path}"))?;
        eprintln!("Report written to {}", output_path);
        // Print summary to stderr so it's visible even when output goes to file.
        if let Some(ref s) = summary {
            eprint!("{}", s);
        }
    } else {
        println!("{}", rendered);
        // Print summary to stderr so it never pollutes machine-readable stdout.
        if let Some(ref s) = summary {
            eprint!("{}", s);
        }
    }

    Ok(exit_code)
}

/// Parse a severity filter string, supporting comma-separated values.
///
/// For comma-separated inputs (e.g., "high,critical"), uses the **lowest** listed
/// severity as the minimum filter threshold, which effectively includes all listed
/// severities and above.
fn parse_severity_filter(input: &str) -> anyhow::Result<mcp_audit::monitors::Severity> {
    use mcp_audit::monitors::Severity;

    let mut min = Severity::Critical;

    for part in input.split(',') {
        let part = part.trim().to_lowercase();
        let sev = match part.as_str() {
            "critical" | "crit" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            "info" => Severity::Info,
            other => anyhow::bail!(
                "Unknown severity '{}'. Valid values: critical, high, medium, low, info",
                other
            ),
        };
        if sev < min {
            min = sev;
        }
    }

    Ok(min)
}

// ── Init command ──────────────────────────────────────────────────────

fn run_init(args: &mcp_audit::cli::InitArgs) -> anyhow::Result<()> {
    use colored::Colorize;
    use mcp_audit::init::{self, ScannerConfig};

    let path = std::path::Path::new(&args.output);

    // Generate configuration (auto-detects MCP sources).
    let config = ScannerConfig::generate(args.ci);

    // Report detected sources.
    if !config.scanner.sources.is_empty() {
        eprintln!(
            "{} Detected MCP configuration {}:",
            "i".cyan().bold(),
            if config.scanner.sources.len() == 1 {
                "file"
            } else {
                "files"
            }
        );
        for src in &config.scanner.sources {
            eprintln!("    {}", src.dimmed());
        }
        eprintln!();
    }

    // Write to disk.
    let written = init::write_config(&config, path, args.force)
        .with_context(|| format!("Failed to write configuration to {}", args.output))?;

    // Success output.
    let mode = if args.ci { "CI" } else { "default" };
    println!(
        "{} Created {} configuration: {}",
        "✓".green().bold(),
        mode,
        written.display()
    );
    println!();
    println!("Next steps:");
    println!("  1. Review {}", args.output);
    println!("  2. Run: {}", "mcp-audit scan".bold());
    println!("  3. Fix any security findings");

    if !args.ci {
        println!();
        println!(
            "For CI/CD integration, re-run with: {}",
            "mcp-audit init --ci".bold()
        );
    }

    Ok(())
}

// ── Rules command ─────────────────────────────────────────────────────

fn run_list_rules() {
    use colored::Colorize;

    let rules = mcp_audit::rules::list_rules();

    println!("{}", "MCP Audit Security Rules".bold().underline());
    println!("{}", "(Based on OWASP MCP Top 10)".dimmed());
    println!();

    for rule in &rules {
        let sev_str = match rule.severity {
            mcp_audit::monitors::Severity::Critical => "CRIT".red().bold().to_string(),
            mcp_audit::monitors::Severity::High => "HIGH".red().to_string(),
            mcp_audit::monitors::Severity::Medium => "MED ".yellow().to_string(),
            mcp_audit::monitors::Severity::Low => "LOW ".cyan().to_string(),
            mcp_audit::monitors::Severity::Info => "INFO".white().to_string(),
        };

        println!(
            "  {} [{}] {} — {}",
            sev_str, rule.id, rule.name, rule.owasp_id
        );
        println!("       {}", rule.description);
        println!();
    }

    println!("{} rules loaded.", rules.len());
}

// ── Status command ──────────────────────────────────────────────────────

async fn run_status(config: &AppConfig) -> anyhow::Result<()> {
    let store = FileStateStore::new(config.state_dir()).context("Failed to open state store")?;

    println!("MCP Audit Status");
    println!("──────────────────");
    println!("  State dir: {}", config.state_dir().display());
    println!();

    // Show checkpoints.
    println!("Monitor Checkpoints:");
    let monitors = [
        "GitHub MCP Ecosystem",
        "NVD CVE Tracker",
        "OWASP MCP Top 10",
        "MCP Adoption Metrics",
    ];
    for name in &monitors {
        let checkpoint = store.get_checkpoint(name).await.unwrap_or(None);
        let status = match checkpoint {
            Some(ts) => ts.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            None => "(never polled)".to_string(),
        };
        println!("  {:<30} {}", name, status);
    }
    println!();

    // Count events per source.
    let all_events = store.get_events(None, None).await.unwrap_or_default();
    println!("Stored Events: {} total", all_events.len());

    let sources = [
        (mcp_audit::monitors::MonitorSource::GitHub, "GitHub"),
        (mcp_audit::monitors::MonitorSource::Cve, "CVE"),
        (mcp_audit::monitors::MonitorSource::Owasp, "OWASP"),
        (mcp_audit::monitors::MonitorSource::Adoption, "Adoption"),
    ];

    for (source, name) in &sources {
        let count = all_events.iter().filter(|e| &e.source == source).count();
        if count > 0 {
            println!("  {:<30} {}", name, count);
        }
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn build_monitors(source: &SourceFilter, client: RateLimitedClient) -> Vec<Box<dyn Monitor>> {
    match source {
        SourceFilter::Github => vec![Box::new(GitHubMonitor::new(client))],
        SourceFilter::Cve => vec![Box::new(CveMonitor::new(client))],
        SourceFilter::Owasp => vec![Box::new(OwaspMonitor::new(client))],
        SourceFilter::Adoption => vec![Box::new(AdoptionMonitor::new(client))],
        SourceFilter::All => vec![
            Box::new(GitHubMonitor::new(client.clone())),
            Box::new(CveMonitor::new(client.clone())),
            Box::new(OwaspMonitor::new(client.clone())),
            Box::new(AdoptionMonitor::new(client)),
        ],
    }
}

fn init_tracing(verbose: bool, quiet: bool) {
    let filter = if quiet {
        EnvFilter::new("error")
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn build_config(cli: &Cli) -> anyhow::Result<AppConfig> {
    let state_dir = cli
        .state_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(AppConfig::default_state_dir);

    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("Failed to create state directory: {}", state_dir.display()))?;

    Ok(AppConfig {
        github_token: cli.github_token.clone(),
        nvd_api_key: cli.nvd_api_key.clone(),
        state_dir,
        output_format: OutputFormat::from(cli.format),
        verbose: cli.verbose,
    })
}

fn show_config(config: &AppConfig, show_secrets: bool) {
    println!("MCP Audit configuration");
    println!("─────────────────────────");
    println!(
        "  GitHub token : {}",
        secret_display(&config.github_token, show_secrets)
    );
    println!(
        "  NVD API key  : {}",
        secret_display(&config.nvd_api_key, show_secrets)
    );
    println!("  State dir    : {}", config.state_dir.display());
    println!("  Output format: {:?}", config.output_format);
    println!("  Verbose      : {}", config.verbose);
}

fn secret_display(value: &Option<String>, show: bool) -> String {
    match value {
        None => "(not set)".to_string(),
        Some(v) if show => v.clone(),
        Some(v) => {
            let len = v.len();
            if len <= 8 {
                "*".repeat(len)
            } else {
                format!("{}...{}", &v[..4], &v[len - 4..])
            }
        }
    }
}
