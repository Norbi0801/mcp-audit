//! MCP configuration file parser.
//!
//! Parses MCP server configuration files such as `claude_desktop_config.json`,
//! extracting server definitions for security analysis.
//!
//! Also supports constructing configurations from CLI flags (`--server`, `--url`)
//! for scanning individual servers without a config file.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parsed MCP configuration file (e.g., `claude_desktop_config.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Map of server name to server configuration.
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: HashMap<String, McpServerConfig>,

    /// Source file path (populated after parsing, not from JSON).
    #[serde(skip)]
    pub source_path: Option<String>,
}

/// Configuration for a single MCP server.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpServerConfig {
    /// Command to execute (for stdio transport).
    #[serde(default)]
    pub command: Option<String>,

    /// Arguments for the command.
    #[serde(default)]
    pub args: Option<Vec<String>>,

    /// Environment variables passed to the server process.
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,

    /// URL for HTTP/SSE transport.
    #[serde(default)]
    pub url: Option<String>,

    /// Transport type (stdio, sse, streamable-http).
    #[serde(default)]
    pub transport: Option<String>,

    /// Tool definitions exposed by this MCP server.
    ///
    /// Populated from config manifests or from `tools/list` runtime discovery.
    /// Used by tool-level security rules to detect injection-vulnerable tools.
    #[serde(default)]
    pub tools: Option<Vec<McpToolDefinition>>,
}

/// Definition of a tool exposed by an MCP server.
///
/// Mirrors the MCP protocol `Tool` schema: name, description, and a
/// JSON Schema for input parameters. Used for static analysis of
/// tool-level security issues (injection, missing validation, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpToolDefinition {
    /// Tool name as registered in the MCP server.
    pub name: String,

    /// Human-readable description of the tool's purpose.
    #[serde(default)]
    pub description: Option<String>,

    /// JSON Schema describing the tool's input parameters.
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Option<Value>,
}

impl McpConfig {
    /// Parse an MCP configuration from a file.
    pub fn from_file(path: &Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config = Self::parse(&content)?;
        config.source_path = Some(path.display().to_string());
        Ok(config)
    }

    /// Parse an MCP configuration from a JSON string.
    pub fn parse(content: &str) -> crate::error::Result<Self> {
        let config: Self = serde_json::from_str(content)?;
        Ok(config)
    }

    /// Create a configuration for scanning a single stdio server from a command string.
    ///
    /// Parses `"npx -y @modelcontextprotocol/server-filesystem /"` into a proper
    /// `McpConfig` with one server entry.
    pub fn from_server_command(command_line: &str) -> crate::error::Result<Self> {
        let parts: Vec<&str> = command_line.split_whitespace().collect();
        if parts.is_empty() {
            return Err(crate::error::McpScannerError::Config(
                "Empty server command".into(),
            ));
        }

        let command = parts[0].to_string();
        let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        let server_config = McpServerConfig {
            command: Some(command),
            args: if args.is_empty() { None } else { Some(args) },
            transport: Some("stdio".to_string()),
            ..Default::default()
        };

        let name = Self::derive_server_name_from_command(&parts);
        let mut servers = HashMap::new();
        servers.insert(name, server_config);

        Ok(Self {
            mcp_servers: servers,
            source_path: Some(format!("cli: {}", command_line)),
        })
    }

    /// Create a configuration for scanning a single HTTP/SSE server from a URL.
    pub fn from_url(url_str: &str) -> crate::error::Result<Self> {
        let parsed = url::Url::parse(url_str).map_err(|e| {
            crate::error::McpScannerError::Config(format!("Invalid URL '{}': {}", url_str, e))
        })?;

        let transport = if url_str.contains("/sse") {
            "sse"
        } else {
            "streamable-http"
        };

        let server_config = McpServerConfig {
            url: Some(url_str.to_string()),
            transport: Some(transport.to_string()),
            ..Default::default()
        };

        let name = parsed.host_str().unwrap_or("remote-server").to_string();
        let mut servers = HashMap::new();
        servers.insert(name, server_config);

        Ok(Self {
            mcp_servers: servers,
            source_path: Some(format!("cli: {}", url_str)),
        })
    }

    /// Derive a meaningful server name from the command-line parts.
    ///
    /// Prefers npm package names (e.g., `@modelcontextprotocol/server-filesystem`)
    /// over the bare command name.
    fn derive_server_name_from_command(parts: &[&str]) -> String {
        // Look for an npm-scoped package (@scope/name).
        for part in parts {
            if part.starts_with('@') && part.contains('/') {
                return part.to_string();
            }
        }
        // Look for a part that looks like an MCP server package.
        for part in parts {
            if part.contains("mcp-server") || part.contains("mcp_server") {
                return part.to_string();
            }
        }
        // Fall back to the command + first meaningful arg.
        if parts.len() > 1 {
            // Skip flags like -y, --, etc.
            for part in &parts[1..] {
                if !part.starts_with('-') {
                    return format!("{}/{}", parts[0], part);
                }
            }
        }
        parts[0].to_string()
    }

    /// Search for MCP configuration files in common locations.
    ///
    /// Checks the current directory, `.mcp/` subdirectory, and platform-specific
    /// Claude Desktop configuration paths.
    pub fn find_config_files() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory.
        let local_configs = ["claude_desktop_config.json", ".mcp.json", "mcp.json"];
        for name in &local_configs {
            let p = Path::new(name);
            if p.exists() {
                paths.push(p.to_path_buf());
            }
        }

        // .mcp/ subdirectory.
        let mcp_dir = Path::new(".mcp");
        if mcp_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(mcp_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().is_some_and(|e| e == "json") {
                        paths.push(p);
                    }
                }
            }
        }

        // Platform-specific Claude Desktop locations.
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let home = Path::new(&home);
            let platform_configs = [
                // Linux
                home.join(".config/Claude/claude_desktop_config.json"),
                // macOS
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                // Windows
                home.join("AppData/Roaming/Claude/claude_desktop_config.json"),
            ];
            for p in &platform_configs {
                if p.exists() {
                    paths.push(p.clone());
                }
            }
        }

        paths
    }
}

impl McpServerConfig {
    /// Returns true if this server uses stdio transport.
    pub fn is_stdio(&self) -> bool {
        self.command.is_some()
    }

    /// Returns true if this server uses HTTP/SSE transport.
    pub fn is_http(&self) -> bool {
        self.url.is_some()
    }

    /// Returns the full command line as a single string (command + args).
    pub fn command_line(&self) -> Option<String> {
        let cmd = self.command.as_deref()?;
        match &self.args {
            Some(args) if !args.is_empty() => Some(format!("{} {}", cmd, args.join(" "))),
            _ => Some(cmd.to_string()),
        }
    }

    /// Returns all arguments combined as a single string.
    pub fn args_string(&self) -> String {
        self.args.as_ref().map(|a| a.join(" ")).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_config() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                }
            }
        }"#;

        let config = McpConfig::parse(json).unwrap();
        assert_eq!(config.mcp_servers.len(), 1);

        let fs = &config.mcp_servers["filesystem"];
        assert_eq!(fs.command.as_deref(), Some("npx"));
        assert_eq!(fs.args.as_ref().unwrap().len(), 3);
        assert!(fs.is_stdio());
        assert!(!fs.is_http());
    }

    #[test]
    fn parse_http_server() {
        let json = r#"{
            "mcpServers": {
                "remote": {
                    "url": "https://api.example.com/mcp",
                    "transport": "sse"
                }
            }
        }"#;

        let config = McpConfig::parse(json).unwrap();
        let remote = &config.mcp_servers["remote"];
        assert!(remote.is_http());
        assert!(!remote.is_stdio());
        assert_eq!(remote.url.as_deref(), Some("https://api.example.com/mcp"));
    }

    #[test]
    fn parse_config_with_env() {
        let json = r#"{
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {
                        "API_KEY": "sk-1234567890",
                        "DEBUG": "true"
                    }
                }
            }
        }"#;

        let config = McpConfig::parse(json).unwrap();
        let server = &config.mcp_servers["my-server"];
        let env = server.env.as_ref().unwrap();
        assert_eq!(env.get("API_KEY").unwrap(), "sk-1234567890");
        assert_eq!(env.get("DEBUG").unwrap(), "true");
    }

    #[test]
    fn parse_multiple_servers() {
        let json = r#"{
            "mcpServers": {
                "server1": { "command": "npx", "args": ["-y", "pkg1"] },
                "server2": { "url": "http://localhost:8080" },
                "server3": { "command": "python", "args": ["-m", "mcp_server"] }
            }
        }"#;

        let config = McpConfig::parse(json).unwrap();
        assert_eq!(config.mcp_servers.len(), 3);
    }

    #[test]
    fn parse_empty_config() {
        let json = r#"{ "mcpServers": {} }"#;
        let config = McpConfig::parse(json).unwrap();
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn parse_config_missing_mcp_servers() {
        let json = r#"{}"#;
        let config = McpConfig::parse(json).unwrap();
        assert!(config.mcp_servers.is_empty());
    }

    #[test]
    fn command_line_with_args() {
        let server = McpServerConfig {
            command: Some("npx".into()),
            args: Some(vec!["-y".into(), "pkg".into()]),
            ..Default::default()
        };
        assert_eq!(server.command_line(), Some("npx -y pkg".to_string()));
    }

    #[test]
    fn command_line_no_args() {
        let server = McpServerConfig {
            command: Some("node".into()),
            args: None,
            ..Default::default()
        };
        assert_eq!(server.command_line(), Some("node".to_string()));
    }

    #[test]
    fn command_line_http_server() {
        let server = McpServerConfig {
            url: Some("https://example.com".into()),
            ..Default::default()
        };
        assert!(server.command_line().is_none());
    }

    // ── from_server_command tests ─────────────────────────────────────

    #[test]
    fn from_server_command_npx_package() {
        let config =
            McpConfig::from_server_command("npx -y @modelcontextprotocol/server-filesystem /tmp")
                .unwrap();
        assert_eq!(config.mcp_servers.len(), 1);

        let (name, server) = config.mcp_servers.iter().next().unwrap();
        assert_eq!(name, "@modelcontextprotocol/server-filesystem");
        assert_eq!(server.command.as_deref(), Some("npx"));
        assert_eq!(
            server.args.as_ref().unwrap(),
            &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        );
        assert!(server.is_stdio());
        assert!(!server.is_http());
        assert!(config.source_path.as_ref().unwrap().starts_with("cli:"));
    }

    #[test]
    fn from_server_command_python() {
        let config = McpConfig::from_server_command("python -m mcp_server").unwrap();
        assert_eq!(config.mcp_servers.len(), 1);

        let (name, server) = config.mcp_servers.iter().next().unwrap();
        assert_eq!(name, "mcp_server");
        assert_eq!(server.command.as_deref(), Some("python"));
    }

    #[test]
    fn from_server_command_bare_command() {
        let config = McpConfig::from_server_command("my-mcp-tool").unwrap();
        let (name, server) = config.mcp_servers.iter().next().unwrap();
        assert_eq!(name, "my-mcp-tool");
        assert_eq!(server.command.as_deref(), Some("my-mcp-tool"));
        assert!(server.args.is_none());
    }

    #[test]
    fn from_server_command_empty_fails() {
        let result = McpConfig::from_server_command("");
        assert!(result.is_err());
    }

    // ── from_url tests ───────────────────────────────────────────────

    #[test]
    fn from_url_sse_endpoint() {
        let config = McpConfig::from_url("https://mcp.example.com/sse").unwrap();
        assert_eq!(config.mcp_servers.len(), 1);

        let (name, server) = config.mcp_servers.iter().next().unwrap();
        assert_eq!(name, "mcp.example.com");
        assert_eq!(server.url.as_deref(), Some("https://mcp.example.com/sse"));
        assert_eq!(server.transport.as_deref(), Some("sse"));
        assert!(server.is_http());
        assert!(!server.is_stdio());
    }

    #[test]
    fn from_url_streamable_http() {
        let config = McpConfig::from_url("https://api.example.com/mcp").unwrap();
        let (_, server) = config.mcp_servers.iter().next().unwrap();
        assert_eq!(server.transport.as_deref(), Some("streamable-http"));
    }

    #[test]
    fn from_url_invalid_fails() {
        let result = McpConfig::from_url("not a url");
        assert!(result.is_err());
    }
}
