use std::path::PathBuf;

/// Top-level application configuration, assembled from CLI flags + environment.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub github_token: Option<String>,
    pub nvd_api_key: Option<String>,
    pub state_dir: PathBuf,
    pub output_format: OutputFormat,
    pub verbose: bool,
}

/// Supported output formats for rendering results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    Json,
    #[default]
    Table,
    Markdown,
    Sarif,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "table" => Ok(Self::Table),
            "markdown" | "md" => Ok(Self::Markdown),
            "sarif" => Ok(Self::Sarif),
            _ => Err(format!(
                "Unknown output format: {s}. Expected: json, table, markdown, sarif"
            )),
        }
    }
}

impl AppConfig {
    pub fn state_dir(&self) -> &PathBuf {
        &self.state_dir
    }

    /// Returns the platform-appropriate default state directory (~/.mcp-audit).
    pub fn default_state_dir() -> PathBuf {
        dirs_or_default()
    }
}

fn dirs_or_default() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".mcp-audit")
    } else {
        PathBuf::from(".mcp-audit")
    }
}
