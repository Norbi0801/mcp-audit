//! Transport layer for MCP server communication.
//!
//! Provides transport implementations for the three MCP transport types:
//! - **Stdio**: Spawn a child process and communicate via stdin/stdout.
//! - **Streamable HTTP**: POST JSON-RPC messages to an HTTP endpoint.
//! - **SSE (legacy)**: Open a Server-Sent Events stream, then POST messages.
//!
//! All transports implement the same interface via the [`Transport`] enum,
//! enabling the [`super::McpClient`] to work uniformly across transport types.

use std::collections::HashMap;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tracing::{debug, warn};

use super::protocol::{JsonRpcNotification, JsonRpcRequest, JsonRpcResponse};
use crate::error::{McpScannerError, Result};

// ── Transport Enum ──────────────────────────────────────────────────

/// Transport abstraction for MCP server communication.
///
/// Uses enum dispatch instead of trait objects to avoid `async_trait` dependency
/// while keeping the interface clean and testable.
pub(crate) enum Transport {
    /// Standard I/O transport (spawn child process).
    Stdio(StdioTransport),
    /// Streamable HTTP transport (modern, MCP 2025-03-26).
    Http(HttpTransport),
    /// Server-Sent Events transport (legacy).
    Sse(SseTransport),
    /// Mock transport for testing.
    #[cfg(test)]
    Mock(MockTransport),
}

impl Transport {
    /// Send a JSON-RPC request and wait for the response.
    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        match self {
            Transport::Stdio(t) => t.send_request(method, params).await,
            Transport::Http(t) => t.send_request(method, params).await,
            Transport::Sse(t) => t.send_request(method, params).await,
            #[cfg(test)]
            Transport::Mock(t) => t.send_request(method, params).await,
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        match self {
            Transport::Stdio(t) => t.send_notification(method, params).await,
            Transport::Http(t) => t.send_notification(method, params).await,
            Transport::Sse(t) => t.send_notification(method, params).await,
            #[cfg(test)]
            Transport::Mock(t) => t.send_notification(method, params).await,
        }
    }

    /// Close the transport connection and clean up resources.
    pub async fn close(&mut self) -> Result<()> {
        match self {
            Transport::Stdio(t) => t.close().await,
            Transport::Http(t) => t.close().await,
            Transport::Sse(t) => t.close().await,
            #[cfg(test)]
            Transport::Mock(t) => t.close().await,
        }
    }
}

// ── Stdio Transport ─────────────────────────────────────────────────

/// Transport that communicates with an MCP server via stdin/stdout of a
/// spawned child process.
///
/// Messages are newline-delimited JSON (one JSON-RPC message per line).
pub(crate) struct StdioTransport {
    child: Child,
    stdin: tokio::io::BufWriter<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    timeout: Duration,
}

impl StdioTransport {
    /// Spawn a child process and create a new stdio transport.
    pub async fn new(
        command: &str,
        args: &[String],
        env: Option<&HashMap<String, String>>,
        timeout: Duration,
    ) -> Result<Self> {
        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        if let Some(env_vars) = env {
            for (k, v) in env_vars {
                cmd.env(k, v);
            }
        }

        debug!(command = command, args = ?args, "Spawning MCP server process");

        let mut child = cmd.spawn().map_err(|e| McpScannerError::ProcessSpawn {
            command: command.to_string(),
            reason: e.to_string(),
        })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpScannerError::ConnectionFailed {
                reason: "Failed to capture stdin of spawned process".to_string(),
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpScannerError::ConnectionFailed {
                reason: "Failed to capture stdout of spawned process".to_string(),
            })?;

        Ok(Self {
            child,
            stdin: tokio::io::BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
            next_id: 1,
            timeout,
        })
    }

    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(id, method, params);
        let mut request_json = serde_json::to_string(&request)?;
        request_json.push('\n');

        debug!(
            id = id,
            method = method,
            "Sending JSON-RPC request via stdio"
        );

        // Write request to stdin.
        tokio::time::timeout(self.timeout, async {
            self.stdin.write_all(request_json.as_bytes()).await?;
            self.stdin.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: self.timeout.as_secs(),
            context: format!("writing request for {method}"),
        })?
        .map_err(|e| McpScannerError::ConnectionFailed {
            reason: format!("Failed to write to stdin: {e}"),
        })?;

        // Read response lines until we find a matching JSON-RPC response.
        let response = tokio::time::timeout(self.timeout, async {
            let mut line = String::new();
            loop {
                line.clear();
                let bytes_read = self.stdout.read_line(&mut line).await.map_err(|e| {
                    McpScannerError::ConnectionFailed {
                        reason: format!("Failed to read from stdout: {e}"),
                    }
                })?;

                if bytes_read == 0 {
                    // Process closed stdout — check exit status for diagnostics.
                    let exit_info = match self.child.try_wait() {
                        Ok(Some(status)) => format!(" (process exited with {status})"),
                        _ => String::new(),
                    };
                    return Err(McpScannerError::ConnectionFailed {
                        reason: format!("MCP server closed stdout unexpectedly{exit_info}"),
                    });
                }

                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                // Try to parse as a JSON-RPC response.
                match serde_json::from_str::<JsonRpcResponse>(trimmed) {
                    Ok(response) if response.id == Some(id) => {
                        return extract_result(response);
                    }
                    Ok(response) => {
                        debug!(
                            expected_id = id,
                            got_id = ?response.id,
                            "Skipping response with non-matching ID"
                        );
                    }
                    Err(_) => {
                        // Not a JSON-RPC response — server log output or notification.
                        debug!(line = trimmed, "Skipping non-response line from stdout");
                    }
                }
            }
        })
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: self.timeout.as_secs(),
            context: format!("waiting for response to {method}"),
        })??;

        Ok(response)
    }

    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        let notification = JsonRpcNotification::new(method, params);
        let mut json = serde_json::to_string(&notification)?;
        json.push('\n');

        debug!(method = method, "Sending JSON-RPC notification via stdio");

        tokio::time::timeout(self.timeout, async {
            self.stdin.write_all(json.as_bytes()).await?;
            self.stdin.flush().await?;
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: self.timeout.as_secs(),
            context: format!("writing notification {method}"),
        })?
        .map_err(|e| McpScannerError::ConnectionFailed {
            reason: format!("Failed to write notification: {e}"),
        })?;

        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        debug!("Closing stdio transport");

        // Give the process a chance to exit gracefully.
        let wait_result = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;

        match wait_result {
            Ok(Ok(status)) => {
                debug!(status = %status, "MCP server process exited");
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Error waiting for MCP server process");
            }
            Err(_) => {
                warn!("MCP server process did not exit in 5s, killing");
                let _ = self.child.kill().await;
            }
        }

        Ok(())
    }
}

// ── HTTP Transport (Streamable HTTP) ────────────────────────────────

/// Transport that communicates with an MCP server via HTTP POST requests.
///
/// Implements the modern "Streamable HTTP" transport (MCP 2025-03-26):
/// each JSON-RPC message is sent as a POST request, and the response may
/// be either direct JSON or a Server-Sent Events stream.
pub(crate) struct HttpTransport {
    client: reqwest::Client,
    endpoint: String,
    session_id: Option<String>,
    next_id: u64,
    timeout: Duration,
}

impl HttpTransport {
    /// Create a new HTTP transport for the given endpoint URL.
    pub fn new(url: &str, timeout: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .build()
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("Failed to create HTTP client: {e}"),
            })?;

        Ok(Self {
            client,
            endpoint: url.to_string(),
            session_id: None,
            next_id: 1,
            timeout,
        })
    }

    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(id, method, params);

        debug!(
            id = id,
            method = method,
            endpoint = %self.endpoint,
            "Sending JSON-RPC request via HTTP"
        );

        let mut http_req = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            http_req = http_req.header("Mcp-Session-Id", session_id);
        }

        let response = tokio::time::timeout(self.timeout, http_req.json(&request).send())
            .await
            .map_err(|_| McpScannerError::ConnectionTimeout {
                timeout_secs: self.timeout.as_secs(),
                context: format!("HTTP request for {method}"),
            })?
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("HTTP request failed: {e}"),
            })?;

        // Extract session ID from response headers if present.
        if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(sid) = session_id.to_str() {
                self.session_id = Some(sid.to_string());
            }
        }

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(McpScannerError::ConnectionFailed {
                reason: format!("HTTP {status} from MCP server: {body}"),
            });
        }

        // Handle both JSON and SSE response content types.
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if content_type.contains("text/event-stream") {
            self.parse_sse_response(response, id).await
        } else {
            let json_response: JsonRpcResponse =
                response
                    .json()
                    .await
                    .map_err(|e| McpScannerError::Protocol {
                        message: format!("Failed to parse JSON-RPC response: {e}"),
                    })?;
            extract_result(json_response)
        }
    }

    /// Parse an SSE-formatted response to extract the JSON-RPC result.
    async fn parse_sse_response(
        &self,
        mut response: reqwest::Response,
        expected_id: u64,
    ) -> Result<serde_json::Value> {
        let mut parser = SseParser::new();

        while let Some(chunk) = tokio::time::timeout(self.timeout, response.chunk())
            .await
            .map_err(|_| McpScannerError::ConnectionTimeout {
                timeout_secs: self.timeout.as_secs(),
                context: "reading SSE response".to_string(),
            })?
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("Failed to read SSE chunk: {e}"),
            })?
        {
            let text = String::from_utf8_lossy(&chunk);
            parser.feed(&text);

            for event in parser.drain_events() {
                if event.event_type.as_deref() == Some("message") || event.event_type.is_none() {
                    if let Ok(json_response) = serde_json::from_str::<JsonRpcResponse>(&event.data)
                    {
                        if json_response.id == Some(expected_id) {
                            return extract_result(json_response);
                        }
                    }
                }
            }
        }

        Err(McpScannerError::ConnectionFailed {
            reason: "SSE stream ended without matching response".to_string(),
        })
    }

    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        let notification = JsonRpcNotification::new(method, params);

        debug!(method = method, "Sending JSON-RPC notification via HTTP");

        let mut http_req = self
            .client
            .post(&self.endpoint)
            .header("Content-Type", "application/json");

        if let Some(ref session_id) = self.session_id {
            http_req = http_req.header("Mcp-Session-Id", session_id);
        }

        let response = tokio::time::timeout(self.timeout, http_req.json(&notification).send())
            .await
            .map_err(|_| McpScannerError::ConnectionTimeout {
                timeout_secs: self.timeout.as_secs(),
                context: format!("HTTP notification for {method}"),
            })?
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("HTTP notification failed: {e}"),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(McpScannerError::ConnectionFailed {
                reason: format!("HTTP {status} for notification: {body}"),
            });
        }

        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        debug!("Closing HTTP transport");
        Ok(())
    }
}

// ── SSE Transport (Legacy) ──────────────────────────────────────────

/// Transport that communicates using the legacy Server-Sent Events protocol.
///
/// Flow:
/// 1. Opens a GET connection to the SSE endpoint.
/// 2. Waits for an `endpoint` event containing the POST URL.
/// 3. Sends JSON-RPC requests as POST to that URL.
/// 4. Reads responses from the SSE event stream.
pub(crate) struct SseTransport {
    client: reqwest::Client,
    base_url: String,
    post_endpoint: Option<String>,
    event_stream: Option<reqwest::Response>,
    sse_parser: SseParser,
    pending_events: Vec<SseEvent>,
    next_id: u64,
    timeout: Duration,
}

impl SseTransport {
    /// Open an SSE connection and wait for the endpoint event.
    pub async fn new(url: &str, timeout: Duration) -> Result<Self> {
        // Client for SSE stream — no request timeout (stream is long-lived).
        let stream_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("Failed to create HTTP client: {e}"),
            })?;

        debug!(url = url, "Opening SSE connection");

        let response = tokio::time::timeout(
            timeout,
            stream_client
                .get(url)
                .header("Accept", "text/event-stream")
                .send(),
        )
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: timeout.as_secs(),
            context: "opening SSE connection".to_string(),
        })?
        .map_err(|e| McpScannerError::ConnectionFailed {
            reason: format!("Failed to open SSE stream: {e}"),
        })?;

        if !response.status().is_success() {
            let status = response.status();
            return Err(McpScannerError::ConnectionFailed {
                reason: format!("SSE endpoint returned HTTP {status}"),
            });
        }

        // Client for POST requests — with user-specified timeout.
        let post_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(timeout)
            .build()
            .map_err(|e| McpScannerError::ConnectionFailed {
                reason: format!("Failed to create POST client: {e}"),
            })?;

        let mut transport = Self {
            client: post_client,
            base_url: url.to_string(),
            post_endpoint: None,
            event_stream: Some(response),
            sse_parser: SseParser::new(),
            pending_events: Vec::new(),
            next_id: 1,
            timeout,
        };

        transport.wait_for_endpoint().await?;

        Ok(transport)
    }

    /// Read SSE events until we receive the `endpoint` event.
    async fn wait_for_endpoint(&mut self) -> Result<()> {
        debug!("Waiting for endpoint event from SSE stream");

        let response =
            self.event_stream
                .as_mut()
                .ok_or_else(|| McpScannerError::ConnectionFailed {
                    reason: "SSE stream not available".to_string(),
                })?;

        let deadline = tokio::time::Instant::now() + self.timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(McpScannerError::ConnectionTimeout {
                    timeout_secs: self.timeout.as_secs(),
                    context: "waiting for SSE endpoint event".to_string(),
                });
            }

            let chunk = tokio::time::timeout(remaining, response.chunk())
                .await
                .map_err(|_| McpScannerError::ConnectionTimeout {
                    timeout_secs: self.timeout.as_secs(),
                    context: "waiting for SSE endpoint event".to_string(),
                })?
                .map_err(|e| McpScannerError::ConnectionFailed {
                    reason: format!("SSE stream error: {e}"),
                })?;

            let chunk = chunk.ok_or_else(|| McpScannerError::ConnectionFailed {
                reason: "SSE stream ended before endpoint event".to_string(),
            })?;

            let text = String::from_utf8_lossy(&chunk);
            self.sse_parser.feed(&text);

            for event in self.sse_parser.drain_events() {
                if event.event_type.as_deref() == Some("endpoint") {
                    let endpoint = event.data.trim().to_string();

                    // Resolve relative URL against the base.
                    let post_url =
                        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
                            endpoint
                        } else {
                            let base = url::Url::parse(&self.base_url).map_err(|e| {
                                McpScannerError::ConnectionFailed {
                                    reason: format!("Invalid base URL: {e}"),
                                }
                            })?;
                            base.join(&endpoint)
                                .map_err(|e| McpScannerError::ConnectionFailed {
                                    reason: format!("Failed to resolve endpoint URL: {e}"),
                                })?
                                .to_string()
                        };

                    debug!(endpoint = %post_url, "Received SSE endpoint");
                    self.post_endpoint = Some(post_url);
                    return Ok(());
                }

                // Buffer other events for later processing.
                self.pending_events.push(event);
            }
        }
    }

    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let post_endpoint =
            self.post_endpoint
                .as_ref()
                .ok_or_else(|| McpScannerError::ConnectionFailed {
                    reason: "SSE endpoint not established".to_string(),
                })?;

        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest::new(id, method, params);

        debug!(
            id = id,
            method = method,
            endpoint = %post_endpoint,
            "Sending JSON-RPC request via SSE transport"
        );

        // POST the request (server typically returns 202 Accepted).
        let _post_response = tokio::time::timeout(
            self.timeout,
            self.client
                .post(post_endpoint)
                .header("Content-Type", "application/json")
                .json(&request)
                .send(),
        )
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: self.timeout.as_secs(),
            context: format!("POSTing request for {method}"),
        })?
        .map_err(|e| McpScannerError::ConnectionFailed {
            reason: format!("POST request failed: {e}"),
        })?;

        // Check pending (buffered) events first.
        if let Some(pos) = self.pending_events.iter().position(|event| {
            (event.event_type.as_deref() == Some("message") || event.event_type.is_none())
                && serde_json::from_str::<JsonRpcResponse>(&event.data)
                    .ok()
                    .is_some_and(|r| r.id == Some(id))
        }) {
            let event = self.pending_events.remove(pos);
            let response: JsonRpcResponse =
                serde_json::from_str(&event.data).map_err(|e| McpScannerError::Protocol {
                    message: format!("Failed to parse buffered response: {e}"),
                })?;
            return extract_result(response);
        }

        // Read from SSE stream until we get the matching response.
        let response =
            self.event_stream
                .as_mut()
                .ok_or_else(|| McpScannerError::ConnectionFailed {
                    reason: "SSE stream not available".to_string(),
                })?;

        let deadline = tokio::time::Instant::now() + self.timeout;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(McpScannerError::ConnectionTimeout {
                    timeout_secs: self.timeout.as_secs(),
                    context: format!("waiting for SSE response to {method}"),
                });
            }

            let chunk = tokio::time::timeout(remaining, response.chunk())
                .await
                .map_err(|_| McpScannerError::ConnectionTimeout {
                    timeout_secs: self.timeout.as_secs(),
                    context: format!("waiting for SSE response to {method}"),
                })?
                .map_err(|e| McpScannerError::ConnectionFailed {
                    reason: format!("SSE stream error: {e}"),
                })?;

            let chunk = chunk.ok_or_else(|| McpScannerError::ConnectionFailed {
                reason: "SSE stream ended while waiting for response".to_string(),
            })?;

            let text = String::from_utf8_lossy(&chunk);
            self.sse_parser.feed(&text);

            for event in self.sse_parser.drain_events() {
                if event.event_type.as_deref() == Some("message") || event.event_type.is_none() {
                    if let Ok(json_response) = serde_json::from_str::<JsonRpcResponse>(&event.data)
                    {
                        if json_response.id == Some(id) {
                            return extract_result(json_response);
                        }
                    }
                }
                // Buffer non-matching events.
                self.pending_events.push(event);
            }
        }
    }

    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        let post_endpoint =
            self.post_endpoint
                .as_ref()
                .ok_or_else(|| McpScannerError::ConnectionFailed {
                    reason: "SSE endpoint not established".to_string(),
                })?;

        let notification = JsonRpcNotification::new(method, params);

        debug!(
            method = method,
            "Sending JSON-RPC notification via SSE transport"
        );

        let response = tokio::time::timeout(
            self.timeout,
            self.client
                .post(post_endpoint)
                .header("Content-Type", "application/json")
                .json(&notification)
                .send(),
        )
        .await
        .map_err(|_| McpScannerError::ConnectionTimeout {
            timeout_secs: self.timeout.as_secs(),
            context: format!("sending notification {method}"),
        })?
        .map_err(|e| McpScannerError::ConnectionFailed {
            reason: format!("Notification POST failed: {e}"),
        })?;

        let status = response.status();
        if !status.is_success() && status.as_u16() != 202 {
            let body = response.text().await.unwrap_or_default();
            return Err(McpScannerError::ConnectionFailed {
                reason: format!("Notification returned HTTP {status}: {body}"),
            });
        }

        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        debug!("Closing SSE transport");
        self.event_stream = None;
        Ok(())
    }
}

// ── SSE Event Parser ────────────────────────────────────────────────

/// Parsed Server-Sent Event.
#[derive(Debug, Clone)]
pub(crate) struct SseEvent {
    /// Event type (from `event:` field). `None` for unnamed events.
    pub event_type: Option<String>,
    /// Event data (from `data:` field(s), joined with newlines).
    pub data: String,
}

/// Incremental parser for Server-Sent Events streams.
///
/// Handles chunked input, multiple events, comments, and both
/// `\n` and `\r\n` line endings per the SSE specification.
pub(crate) struct SseParser {
    buffer: String,
    events: Vec<SseEvent>,
}

impl SseParser {
    /// Create a new SSE parser.
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            events: Vec::new(),
        }
    }

    /// Feed raw SSE text into the parser.
    ///
    /// Parsed events are accumulated internally — call [`drain_events`] to
    /// retrieve them.
    pub fn feed(&mut self, text: &str) {
        self.buffer.push_str(text);
        self.parse_buffer();
    }

    /// Drain all fully parsed events from the parser.
    pub fn drain_events(&mut self) -> Vec<SseEvent> {
        std::mem::take(&mut self.events)
    }

    fn parse_buffer(&mut self) {
        // Normalize line endings: \r\n → \n, bare \r → \n.
        let normalized = self.buffer.replace("\r\n", "\n").replace('\r', "\n");
        self.buffer = normalized;

        // Events are delimited by double newlines.
        while let Some(pos) = self.buffer.find("\n\n") {
            let event_text = self.buffer[..pos].to_string();
            self.buffer = self.buffer[pos + 2..].to_string();

            if let Some(event) = Self::parse_single_event(&event_text) {
                self.events.push(event);
            }
        }
    }

    fn parse_single_event(text: &str) -> Option<SseEvent> {
        let mut event_type = None;
        let mut data_lines: Vec<&str> = Vec::new();

        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            // Lines starting with ':' are comments.
            if line.starts_with(':') {
                continue;
            }
            if let Some(value) = line.strip_prefix("event:") {
                event_type = Some(value.trim_start_matches(' ').to_string());
            } else if let Some(value) = line.strip_prefix("data:") {
                data_lines.push(value.strip_prefix(' ').unwrap_or(value));
            } else if line.strip_prefix("id:").is_some() || line.strip_prefix("retry:").is_some() {
                // Parsed but not used by the scanner.
            }
        }

        if data_lines.is_empty() {
            return None;
        }

        Some(SseEvent {
            event_type,
            data: data_lines.join("\n"),
        })
    }
}

// ── Shared Helpers ──────────────────────────────────────────────────

/// Extract the result value from a JSON-RPC response, or convert the
/// error into an [`McpScannerError`].
fn extract_result(response: JsonRpcResponse) -> Result<serde_json::Value> {
    if let Some(error) = response.error {
        return Err(McpScannerError::JsonRpcError {
            code: error.code,
            message: error.message,
        });
    }

    response.result.ok_or_else(|| McpScannerError::Protocol {
        message: "Response contains neither result nor error".to_string(),
    })
}

// ── Mock Transport (test-only) ──────────────────────────────────────

/// Mock transport that returns pre-configured responses, for unit testing
/// the [`super::McpClient`] logic without real I/O.
#[cfg(test)]
pub(crate) struct MockTransport {
    pub responses: std::collections::VecDeque<serde_json::Value>,
    pub requests: Vec<(String, Option<serde_json::Value>)>,
    pub notifications: Vec<(String, Option<serde_json::Value>)>,
}

#[cfg(test)]
impl MockTransport {
    pub fn new(responses: Vec<serde_json::Value>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            notifications: Vec::new(),
        }
    }

    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.requests.push((method.to_string(), params));
        self.responses
            .pop_front()
            .ok_or_else(|| McpScannerError::ConnectionFailed {
                reason: "Mock: no more responses queued".to_string(),
            })
    }

    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<()> {
        self.notifications.push((method.to_string(), params));
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::protocol::JsonRpcError as ProtoJsonRpcError;

    // ── SSE Parser Tests ────────────────────────────────────────────

    #[test]
    fn sse_parse_simple_event() {
        let mut parser = SseParser::new();
        parser.feed("event: message\ndata: {\"hello\":\"world\"}\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("message"));
        assert_eq!(events[0].data, "{\"hello\":\"world\"}");
    }

    #[test]
    fn sse_parse_endpoint_event() {
        let mut parser = SseParser::new();
        parser.feed("event: endpoint\ndata: /messages?sessionId=abc123\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("endpoint"));
        assert_eq!(events[0].data, "/messages?sessionId=abc123");
    }

    #[test]
    fn sse_parse_multiline_data() {
        let mut parser = SseParser::new();
        parser.feed("event: msg\ndata: line1\ndata: line2\ndata: line3\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "line1\nline2\nline3");
    }

    #[test]
    fn sse_parse_multiple_events() {
        let mut parser = SseParser::new();
        parser.feed("event: a\ndata: first\n\nevent: b\ndata: second\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type.as_deref(), Some("a"));
        assert_eq!(events[0].data, "first");
        assert_eq!(events[1].event_type.as_deref(), Some("b"));
        assert_eq!(events[1].data, "second");
    }

    #[test]
    fn sse_parse_incremental_feed() {
        let mut parser = SseParser::new();

        parser.feed("event: msg\n");
        assert!(parser.drain_events().is_empty());

        parser.feed("data: hello\n");
        assert!(parser.drain_events().is_empty());

        parser.feed("\n");
        let events = parser.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn sse_parse_with_comments() {
        let mut parser = SseParser::new();
        parser.feed(": this is a comment\nevent: test\ndata: value\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("test"));
        assert_eq!(events[0].data, "value");
    }

    #[test]
    fn sse_parse_crlf_line_endings() {
        let mut parser = SseParser::new();
        parser.feed("event: test\r\ndata: value\r\n\r\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("test"));
        assert_eq!(events[0].data, "value");
    }

    #[test]
    fn sse_skip_event_without_data() {
        let mut parser = SseParser::new();
        parser.feed("event: ping\n\nevent: msg\ndata: hello\n\n");
        let events = parser.drain_events();

        // Only the event with data should be returned.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_deref(), Some("msg"));
    }

    #[test]
    fn sse_event_without_type() {
        let mut parser = SseParser::new();
        parser.feed("data: just data\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert!(events[0].event_type.is_none());
        assert_eq!(events[0].data, "just data");
    }

    #[test]
    fn sse_parse_data_with_no_space_after_colon() {
        let mut parser = SseParser::new();
        parser.feed("data:no-space\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "no-space");
    }

    #[test]
    fn sse_parse_empty_data() {
        let mut parser = SseParser::new();
        parser.feed("data:\n\n");
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "");
    }

    #[test]
    fn sse_parse_large_chunked_json() {
        let mut parser = SseParser::new();
        let json = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "tool1", "inputSchema": {"type": "object"}},
                    {"name": "tool2", "inputSchema": {"type": "object"}}
                ]
            }
        });
        let json_str = serde_json::to_string(&json).unwrap();
        let full = format!("event: message\ndata: {json_str}\n\n");

        // Feed in small chunks to simulate network fragmentation.
        for chunk in full.as_bytes().chunks(10) {
            parser.feed(&String::from_utf8_lossy(chunk));
        }
        let events = parser.drain_events();

        assert_eq!(events.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&events[0].data).unwrap();
        assert_eq!(parsed["result"]["tools"][0]["name"], "tool1");
    }

    // ── extract_result Tests ────────────────────────────────────────

    #[test]
    fn extract_result_success() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: Some(serde_json::json!({"tools": []})),
            error: None,
        };
        let result = extract_result(response).unwrap();
        assert_eq!(result, serde_json::json!({"tools": []}));
    }

    #[test]
    fn extract_result_error() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: None,
            error: Some(ProtoJsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: None,
            }),
        };
        let err = extract_result(response).unwrap_err();
        match err {
            McpScannerError::JsonRpcError { code, message } => {
                assert_eq!(code, -32601);
                assert_eq!(message, "Method not found");
            }
            other => panic!("Expected JsonRpcError, got: {other:?}"),
        }
    }

    #[test]
    fn extract_result_neither() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            result: None,
            error: None,
        };
        let err = extract_result(response).unwrap_err();
        assert!(matches!(err, McpScannerError::Protocol { .. }));
    }

    // ── MockTransport Tests ─────────────────────────────────────────

    #[tokio::test]
    async fn mock_transport_returns_responses_in_order() {
        let mut mock = MockTransport::new(vec![
            serde_json::json!({"first": true}),
            serde_json::json!({"second": true}),
        ]);

        let r1 = mock.send_request("method1", None).await.unwrap();
        let r2 = mock.send_request("method2", None).await.unwrap();

        assert_eq!(r1, serde_json::json!({"first": true}));
        assert_eq!(r2, serde_json::json!({"second": true}));
        assert_eq!(mock.requests.len(), 2);
        assert_eq!(mock.requests[0].0, "method1");
        assert_eq!(mock.requests[1].0, "method2");
    }

    #[tokio::test]
    async fn mock_transport_records_notifications() {
        let mut mock = MockTransport::new(vec![]);

        mock.send_notification("notifications/initialized", None)
            .await
            .unwrap();

        assert_eq!(mock.notifications.len(), 1);
        assert_eq!(mock.notifications[0].0, "notifications/initialized");
    }

    #[tokio::test]
    async fn mock_transport_error_when_empty() {
        let mut mock = MockTransport::new(vec![]);
        let result = mock.send_request("any", None).await;
        assert!(result.is_err());
    }
}
