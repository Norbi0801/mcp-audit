//! MCP server connection module.
//!
//! Connects to MCP servers via stdio or HTTP transport, performs the MCP
//! initialization handshake, and discovers available tools, resources, and
//! prompts. Designed for security scanning — read-only introspection.
//!
//! # Supported Transports
//!
//! - **Stdio**: Spawns a child process and communicates via stdin/stdout
//!   using newline-delimited JSON-RPC 2.0 messages.
//! - **Streamable HTTP**: POSTs JSON-RPC messages to an HTTP endpoint
//!   (MCP 2025-03-26 specification). Handles both JSON and SSE responses.
//! - **SSE (legacy)**: Opens a GET-based Server-Sent Events stream, then
//!   POSTs requests to the discovered endpoint.
//!
//! # Example
//!
//! ```no_run
//! use mcp_audit::connection::{McpClient, DEFAULT_TIMEOUT};
//!
//! # async fn example() -> mcp_audit::error::Result<()> {
//! let client = McpClient::connect_stdio(
//!     "npx",
//!     &["-y".into(), "@modelcontextprotocol/server-filesystem".into(), "/tmp".into()],
//!     None,
//!     DEFAULT_TIMEOUT,
//! ).await?;
//!
//! println!("Server: {} v{}", client.server_info().name, client.server_info().version);
//! for tool in client.tools() {
//!     println!("  Tool: {} — {:?}", tool.name, tool.description);
//! }
//!
//! client.disconnect().await?;
//! # Ok(())
//! # }
//! ```

pub mod protocol;
pub(crate) mod transport;

use std::collections::HashMap;
use std::time::Duration;

use serde::Serialize;
use tracing::{debug, info, warn};

use crate::error::{McpScannerError, Result};
use crate::parser::McpServerConfig;
use protocol::*;
pub use protocol::{PromptArgument, PromptInfo, ResourceInfo, ServerCapabilities, ToolInfo};
use transport::Transport;

/// Default timeout for MCP server connections (30 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of pages to fetch for paginated list results.
const MAX_PAGES: usize = 10;

/// Comprehensive information about a connected MCP server.
///
/// Populated during the initialization handshake by querying the server's
/// capabilities and listing all available tools, resources, and prompts.
#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    /// Server name as reported during initialization.
    pub name: String,
    /// Server version as reported during initialization.
    pub version: String,
    /// Protocol version negotiated during initialization.
    pub protocol_version: String,
    /// Server capabilities advertised during initialization.
    pub capabilities: ServerCapabilities,
    /// Tools exposed by the server.
    pub tools: Vec<ToolInfo>,
    /// Resources exposed by the server.
    pub resources: Vec<ResourceInfo>,
    /// Prompts exposed by the server.
    pub prompts: Vec<PromptInfo>,
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            version: "unknown".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ServerCapabilities::default(),
            tools: Vec::new(),
            resources: Vec::new(),
            prompts: Vec::new(),
        }
    }
}

/// HTTP transport variant for MCP connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpTransportType {
    /// Modern streamable HTTP transport (MCP 2025-03-26).
    StreamableHttp,
    /// Legacy Server-Sent Events transport.
    Sse,
}

/// MCP client for connecting to and introspecting MCP servers.
///
/// Connects to an MCP server, performs the protocol initialization handshake,
/// and discovers available tools, resources, and prompts. All data is fetched
/// eagerly during connection — accessor methods return cached results.
pub struct McpClient {
    transport: Transport,
    info: ServerInfo,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl McpClient {
    /// Connect to an MCP server via stdio transport (spawn process).
    ///
    /// # Arguments
    ///
    /// * `command` — Executable to spawn (e.g., `"npx"`, `"python"`).
    /// * `args` — Arguments for the command.
    /// * `env` — Optional environment variables for the child process.
    /// * `timeout` — Timeout for individual protocol operations.
    pub async fn connect_stdio(
        command: &str,
        args: &[String],
        env: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Self> {
        info!(command = command, "Connecting to MCP server via stdio");

        let transport = transport::StdioTransport::new(command, args, env, timeout).await?;
        let mut client = Self {
            transport: Transport::Stdio(transport),
            info: ServerInfo::default(),
        };

        client.initialize().await?;
        Ok(client)
    }

    /// Connect to an MCP server via HTTP transport.
    ///
    /// # Arguments
    ///
    /// * `url` — Endpoint URL (e.g., `"https://api.example.com/mcp"`).
    /// * `transport_type` — [`HttpTransportType::StreamableHttp`] or [`HttpTransportType::Sse`].
    /// * `timeout` — Timeout for individual protocol operations.
    pub async fn connect_http(
        url: &str,
        transport_type: HttpTransportType,
        timeout: Duration,
    ) -> Result<Self> {
        info!(
            url = url,
            transport = ?transport_type,
            "Connecting to MCP server via HTTP"
        );

        let transport = match transport_type {
            HttpTransportType::StreamableHttp => {
                Transport::Http(transport::HttpTransport::new(url, timeout)?)
            }
            HttpTransportType::Sse => {
                Transport::Sse(transport::SseTransport::new(url, timeout).await?)
            }
        };

        let mut client = Self {
            transport,
            info: ServerInfo::default(),
        };

        client.initialize().await?;
        Ok(client)
    }

    /// Connect to an MCP server based on its parsed configuration.
    ///
    /// Automatically selects the appropriate transport:
    /// - If `config.command` is set → stdio transport.
    /// - If `config.url` is set → HTTP transport (SSE if `transport == "sse"`,
    ///   otherwise streamable HTTP).
    pub async fn from_server_config(config: &McpServerConfig, timeout: Duration) -> Result<Self> {
        if config.is_stdio() {
            let command = config.command.as_deref().ok_or_else(|| {
                McpScannerError::Config("Stdio server missing command".to_string())
            })?;
            let args = config.args.as_deref().unwrap_or(&[]);
            Self::connect_stdio(command, args, config.env.as_ref(), timeout).await
        } else if config.is_http() {
            let url = config
                .url
                .as_deref()
                .ok_or_else(|| McpScannerError::Config("HTTP server missing URL".to_string()))?;
            let transport_type = match config.transport.as_deref() {
                Some("sse") => HttpTransportType::Sse,
                _ => HttpTransportType::StreamableHttp,
            };
            Self::connect_http(url, transport_type, timeout).await
        } else {
            Err(McpScannerError::Config(
                "Server config has neither command nor URL".to_string(),
            ))
        }
    }

    /// Get the server information collected during initialization.
    pub fn server_info(&self) -> &ServerInfo {
        &self.info
    }

    /// Get the tools exposed by the server.
    pub fn tools(&self) -> &[ToolInfo] {
        &self.info.tools
    }

    /// Get the resources exposed by the server.
    pub fn resources(&self) -> &[ResourceInfo] {
        &self.info.resources
    }

    /// Get the prompts exposed by the server.
    pub fn prompts(&self) -> &[PromptInfo] {
        &self.info.prompts
    }

    /// Disconnect from the MCP server and release resources.
    ///
    /// For stdio transport, this closes stdin and waits for the child process
    /// to exit (with a 5-second grace period before killing).
    pub async fn disconnect(mut self) -> Result<()> {
        info!(
            server = %self.info.name,
            "Disconnecting from MCP server"
        );
        self.transport.close().await
    }

    // ── Private: Initialization Flow ────────────────────────────────

    /// Perform the full MCP initialization handshake:
    /// 1. Send `initialize` request → receive server capabilities.
    /// 2. Send `notifications/initialized` notification.
    /// 3. Fetch tools, resources, and prompts based on capabilities.
    async fn initialize(&mut self) -> Result<()> {
        // Step 1: Initialize.
        let init_params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities {},
            client_info: Implementation {
                name: CLIENT_NAME.to_string(),
                version: CLIENT_VERSION.to_string(),
            },
        };

        debug!("Sending initialize request");
        let result = self
            .transport
            .send_request("initialize", Some(serde_json::to_value(&init_params)?))
            .await?;

        let init_result: InitializeResult =
            serde_json::from_value(result).map_err(|e| McpScannerError::Protocol {
                message: format!("Failed to parse initialize result: {e}"),
            })?;

        // Populate server info.
        self.info.protocol_version = init_result.protocol_version;
        self.info.capabilities = init_result.capabilities.clone();
        if let Some(server_info) = init_result.server_info {
            self.info.name = server_info.name;
            self.info.version = server_info.version;
        }

        info!(
            name = %self.info.name,
            version = %self.info.version,
            protocol = %self.info.protocol_version,
            "MCP server initialized"
        );

        // Step 2: Confirm initialization.
        debug!("Sending initialized notification");
        self.transport
            .send_notification("notifications/initialized", None)
            .await?;

        // Step 3: Discover capabilities.
        if init_result.capabilities.tools.is_some() {
            debug!("Fetching tool definitions");
            match self.fetch_tools().await {
                Ok(tools) => {
                    info!(count = tools.len(), "Discovered tools");
                    self.info.tools = tools;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to fetch tools");
                }
            }
        }

        if init_result.capabilities.resources.is_some() {
            debug!("Fetching resource definitions");
            match self.fetch_resources().await {
                Ok(resources) => {
                    info!(count = resources.len(), "Discovered resources");
                    self.info.resources = resources;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to fetch resources");
                }
            }
        }

        if init_result.capabilities.prompts.is_some() {
            debug!("Fetching prompt definitions");
            match self.fetch_prompts().await {
                Ok(prompts) => {
                    info!(count = prompts.len(), "Discovered prompts");
                    self.info.prompts = prompts;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to fetch prompts");
                }
            }
        }

        Ok(())
    }

    /// Fetch all tools with pagination support.
    async fn fetch_tools(&mut self) -> Result<Vec<ToolInfo>> {
        let mut all_tools = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => serde_json::json!({"cursor": c}),
                None => serde_json::json!({}),
            };

            let result = self
                .transport
                .send_request("tools/list", Some(params))
                .await?;

            let list: ToolsListResult =
                serde_json::from_value(result).map_err(|e| McpScannerError::Protocol {
                    message: format!("Failed to parse tools/list result: {e}"),
                })?;

            all_tools.extend(list.tools);

            match list.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }

        Ok(all_tools)
    }

    /// Fetch all resources with pagination support.
    async fn fetch_resources(&mut self) -> Result<Vec<ResourceInfo>> {
        let mut all_resources = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => serde_json::json!({"cursor": c}),
                None => serde_json::json!({}),
            };

            let result = self
                .transport
                .send_request("resources/list", Some(params))
                .await?;

            let list: ResourcesListResult =
                serde_json::from_value(result).map_err(|e| McpScannerError::Protocol {
                    message: format!("Failed to parse resources/list result: {e}"),
                })?;

            all_resources.extend(list.resources);

            match list.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }

        Ok(all_resources)
    }

    /// Fetch all prompts with pagination support.
    async fn fetch_prompts(&mut self) -> Result<Vec<PromptInfo>> {
        let mut all_prompts = Vec::new();
        let mut cursor: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => serde_json::json!({"cursor": c}),
                None => serde_json::json!({}),
            };

            let result = self
                .transport
                .send_request("prompts/list", Some(params))
                .await?;

            let list: PromptsListResult =
                serde_json::from_value(result).map_err(|e| McpScannerError::Protocol {
                    message: format!("Failed to parse prompts/list result: {e}"),
                })?;

            all_prompts.extend(list.prompts);

            match list.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }

        Ok(all_prompts)
    }

    /// Create a client with a mock transport for testing.
    #[cfg(test)]
    pub(crate) fn with_mock(responses: Vec<serde_json::Value>) -> Self {
        Self {
            transport: Transport::Mock(transport::MockTransport::new(responses)),
            info: ServerInfo::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test Helpers ────────────────────────────────────────────────

    fn mock_initialize_response() -> serde_json::Value {
        serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
                "resources": {},
                "prompts": {}
            },
            "serverInfo": {
                "name": "test-server",
                "version": "1.0.0"
            }
        })
    }

    fn mock_tools_response() -> serde_json::Value {
        serde_json::json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file from disk",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write content to a file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path", "content"]
                    }
                }
            ]
        })
    }

    fn mock_resources_response() -> serde_json::Value {
        serde_json::json!({
            "resources": [
                {
                    "uri": "file:///tmp",
                    "name": "Temp Directory",
                    "description": "Temporary file storage",
                    "mimeType": "inode/directory"
                }
            ]
        })
    }

    fn mock_prompts_response() -> serde_json::Value {
        serde_json::json!({
            "prompts": [
                {
                    "name": "summarize",
                    "description": "Summarize text content",
                    "arguments": [
                        {
                            "name": "text",
                            "description": "Text to summarize",
                            "required": true
                        },
                        {
                            "name": "max_length",
                            "description": "Maximum summary length",
                            "required": false
                        }
                    ]
                }
            ]
        })
    }

    // ── McpClient Initialization Tests ──────────────────────────────

    #[tokio::test]
    async fn client_full_initialization() {
        let mut client = McpClient::with_mock(vec![
            mock_initialize_response(),
            mock_tools_response(),
            mock_resources_response(),
            mock_prompts_response(),
        ]);

        client.initialize().await.unwrap();

        assert_eq!(client.server_info().name, "test-server");
        assert_eq!(client.server_info().version, "1.0.0");
        assert_eq!(client.server_info().protocol_version, "2024-11-05");

        // Tools.
        assert_eq!(client.tools().len(), 2);
        assert_eq!(client.tools()[0].name, "read_file");
        assert_eq!(
            client.tools()[0].description.as_deref(),
            Some("Read a file from disk")
        );
        assert_eq!(client.tools()[1].name, "write_file");

        // Resources.
        assert_eq!(client.resources().len(), 1);
        assert_eq!(client.resources()[0].uri, "file:///tmp");
        assert_eq!(client.resources()[0].name, "Temp Directory");
        assert_eq!(
            client.resources()[0].mime_type.as_deref(),
            Some("inode/directory")
        );

        // Prompts.
        assert_eq!(client.prompts().len(), 1);
        assert_eq!(client.prompts()[0].name, "summarize");
        let args = client.prompts()[0].arguments.as_ref().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "text");
        assert_eq!(args[0].required, Some(true));
        assert_eq!(args[1].name, "max_length");
        assert_eq!(args[1].required, Some(false));
    }

    #[tokio::test]
    async fn client_no_capabilities() {
        let init_response = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": {
                "name": "minimal-server",
                "version": "0.1.0"
            }
        });

        let mut client = McpClient::with_mock(vec![init_response]);
        client.initialize().await.unwrap();

        assert_eq!(client.server_info().name, "minimal-server");
        assert_eq!(client.server_info().version, "0.1.0");
        assert!(client.tools().is_empty());
        assert!(client.resources().is_empty());
        assert!(client.prompts().is_empty());
    }

    #[tokio::test]
    async fn client_tools_only() {
        let init_response = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "tools-only",
                "version": "1.0.0"
            }
        });

        let mut client = McpClient::with_mock(vec![init_response, mock_tools_response()]);

        client.initialize().await.unwrap();

        assert_eq!(client.tools().len(), 2);
        assert!(client.resources().is_empty());
        assert!(client.prompts().is_empty());
    }

    #[tokio::test]
    async fn client_paginated_tools() {
        let init_response = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "paginated", "version": "1.0.0"}
        });

        let page1 = serde_json::json!({
            "tools": [{"name": "tool1", "inputSchema": {"type": "object"}}],
            "nextCursor": "page2"
        });

        let page2 = serde_json::json!({
            "tools": [{"name": "tool2", "inputSchema": {"type": "object"}}]
        });

        let mut client = McpClient::with_mock(vec![init_response, page1, page2]);
        client.initialize().await.unwrap();

        assert_eq!(client.tools().len(), 2);
        assert_eq!(client.tools()[0].name, "tool1");
        assert_eq!(client.tools()[1].name, "tool2");
    }

    #[tokio::test]
    async fn client_no_server_info() {
        let init_response = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {}
        });

        let mut client = McpClient::with_mock(vec![init_response]);
        client.initialize().await.unwrap();

        // Should use defaults when serverInfo is missing.
        assert_eq!(client.server_info().name, "unknown");
        assert_eq!(client.server_info().version, "unknown");
    }

    #[tokio::test]
    async fn client_handles_tools_fetch_failure_gracefully() {
        let init_response = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": "flaky", "version": "1.0.0"}
        });

        // Only one response (for initialize), tools/list will fail.
        // But we also need to handle resources/list, so provide one more mock.
        // Mock returns error for tools/list (no more responses), then the
        // resources/list also fails because no more responses.
        let mut client = McpClient::with_mock(vec![init_response]);

        // Should not panic — failures are logged as warnings.
        client.initialize().await.unwrap();

        // Tools and resources should be empty due to fetch failure.
        assert!(client.tools().is_empty());
        assert!(client.resources().is_empty());
    }

    // ── ServerInfo Tests ────────────────────────────────────────────

    #[test]
    fn server_info_default_values() {
        let info = ServerInfo::default();
        assert_eq!(info.name, "unknown");
        assert_eq!(info.version, "unknown");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(info.tools.is_empty());
        assert!(info.resources.is_empty());
        assert!(info.prompts.is_empty());
    }

    #[test]
    fn server_info_serializable() {
        let info = ServerInfo {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities::default(),
            tools: vec![ToolInfo {
                name: "test_tool".to_string(),
                description: Some("A test tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
            }],
            resources: vec![],
            prompts: vec![],
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test_tool"));
        assert!(json.contains("A test tool"));
    }

    // ── from_server_config Tests ────────────────────────────────────

    #[test]
    fn config_detection_stdio() {
        let config = McpServerConfig {
            command: Some("npx".to_string()),
            args: Some(vec!["-y".to_string(), "test-server".to_string()]),
            transport: Some("stdio".to_string()),
            ..Default::default()
        };

        assert!(config.is_stdio());
        assert!(!config.is_http());
    }

    #[test]
    fn config_detection_http() {
        let config = McpServerConfig {
            url: Some("https://example.com/mcp".to_string()),
            transport: Some("streamable-http".to_string()),
            ..Default::default()
        };

        assert!(!config.is_stdio());
        assert!(config.is_http());
    }

    #[test]
    fn config_detection_sse() {
        let config = McpServerConfig {
            url: Some("https://example.com/sse".to_string()),
            transport: Some("sse".to_string()),
            ..Default::default()
        };

        assert!(config.is_http());
    }

    #[tokio::test]
    async fn from_server_config_no_command_or_url_fails() {
        let config = McpServerConfig::default();
        let result = McpClient::from_server_config(&config, DEFAULT_TIMEOUT).await;
        assert!(result.is_err());
    }

    // ── Disconnect Tests ────────────────────────────────────────────

    #[tokio::test]
    async fn disconnect_does_not_panic() {
        let client = McpClient::with_mock(vec![]);
        client.disconnect().await.unwrap();
    }

    // ── HttpTransportType Tests ─────────────────────────────────────

    #[test]
    fn http_transport_type_equality() {
        assert_eq!(
            HttpTransportType::StreamableHttp,
            HttpTransportType::StreamableHttp
        );
        assert_eq!(HttpTransportType::Sse, HttpTransportType::Sse);
        assert_ne!(HttpTransportType::StreamableHttp, HttpTransportType::Sse);
    }
}
