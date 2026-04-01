use thiserror::Error;

/// Central error type for the MCP Audit.
#[derive(Debug, Error)]
pub enum McpScannerError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Rate limited by {api} — retry after {retry_after_secs}s")]
    RateLimited { api: String, retry_after_secs: u64 },

    #[error("JSON parse error: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("GitHub API error (HTTP {status}): {message}")]
    GitHubApi { status: u16, message: String },

    #[error("NVD API error (HTTP {status}): {message}")]
    NvdApi { status: u16, message: String },

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Storage I/O error: {0}")]
    Storage(#[from] std::io::Error),

    #[error("Empty result from {monitor}: {reason}")]
    EmptyResult { monitor: String, reason: String },

    #[error("LemonSqueezy API error (HTTP {status}): {message}")]
    BillingApi { status: u16, message: String },

    #[error("Webhook signature verification failed: {reason}")]
    WebhookSignature { reason: String },

    #[error("Usage limit exceeded: {limit_type} — {current}/{limit} on {plan} plan")]
    UsageLimitExceeded {
        limit_type: String,
        current: u32,
        limit: u32,
        plan: String,
    },

    #[error("MCP connection timeout after {timeout_secs}s: {context}")]
    ConnectionTimeout { timeout_secs: u64, context: String },

    #[error("Failed to spawn MCP server process '{command}': {reason}")]
    ProcessSpawn { command: String, reason: String },

    #[error("MCP protocol error: {message}")]
    Protocol { message: String },

    #[error("MCP server returned error (code {code}): {message}")]
    JsonRpcError { code: i64, message: String },

    #[error("MCP connection failed: {reason}")]
    ConnectionFailed { reason: String },
}

pub type Result<T> = std::result::Result<T, McpScannerError>;
