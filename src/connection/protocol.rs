//! MCP protocol types and JSON-RPC 2.0 message definitions.
//!
//! Implements the minimal subset of the Model Context Protocol needed for
//! security scanning: initialization, tool/resource/prompt discovery.
//! Based on MCP specification 2024-11-05.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Current MCP protocol version supported by the scanner.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Scanner client name sent during initialization.
pub const CLIENT_NAME: &str = "mcp-audit";

/// Scanner client version sent during initialization.
pub const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

// ── JSON-RPC 2.0 ────────────────────────────────────────────────────

/// JSON-RPC 2.0 request message.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    /// Create a new JSON-RPC 2.0 request.
    pub fn new(id: u64, method: &str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params,
        }
    }
}

/// JSON-RPC 2.0 response message.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub result: Option<Value>,
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

/// JSON-RPC 2.0 notification (no id, no response expected).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    /// Create a new JSON-RPC 2.0 notification.
    pub fn new(method: &str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        }
    }
}

// ── MCP Protocol Types ──────────────────────────────────────────────

/// Parameters for the `initialize` request.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    pub client_info: Implementation,
}

/// Client capabilities advertised during initialization.
///
/// Empty for the scanner — we only perform read-only introspection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientCapabilities {}

/// Implementation info (name + version) for client or server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Implementation {
    pub name: String,
    pub version: String,
}

/// Result of the `initialize` request.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(default)]
    pub server_info: Option<Implementation>,
}

/// Server capabilities advertised during initialization.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServerCapabilities {
    #[serde(default)]
    pub tools: Option<ToolsCapability>,
    #[serde(default)]
    pub resources: Option<ResourcesCapability>,
    #[serde(default)]
    pub prompts: Option<PromptsCapability>,
    #[serde(default)]
    pub logging: Option<Value>,
}

/// Capability descriptor for the `tools` capability.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default)]
    pub list_changed: Option<bool>,
}

/// Capability descriptor for the `resources` capability.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    #[serde(default)]
    pub subscribe: Option<bool>,
    #[serde(default)]
    pub list_changed: Option<bool>,
}

/// Capability descriptor for the `prompts` capability.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PromptsCapability {
    #[serde(default)]
    pub list_changed: Option<bool>,
}

// ── Tool / Resource / Prompt Definitions ────────────────────────────

/// Tool definition as returned by `tools/list`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    /// Tool name as registered in the MCP server.
    pub name: String,

    /// Human-readable description of the tool's purpose.
    #[serde(default)]
    pub description: Option<String>,

    /// JSON Schema describing the tool's input parameters.
    #[serde(default = "default_object_schema")]
    pub input_schema: Value,
}

fn default_object_schema() -> Value {
    serde_json::json!({"type": "object"})
}

/// Result of `tools/list`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsListResult {
    #[serde(default)]
    pub tools: Vec<ToolInfo>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Resource definition as returned by `resources/list`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// URI identifying the resource.
    pub uri: String,

    /// Human-readable resource name.
    pub name: String,

    /// Description of the resource.
    #[serde(default)]
    pub description: Option<String>,

    /// MIME type of the resource content.
    #[serde(default)]
    pub mime_type: Option<String>,
}

/// Result of `resources/list`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesListResult {
    #[serde(default)]
    pub resources: Vec<ResourceInfo>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Prompt definition as returned by `prompts/list`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptInfo {
    /// Prompt name.
    pub name: String,

    /// Description of the prompt's purpose.
    #[serde(default)]
    pub description: Option<String>,

    /// Arguments the prompt accepts.
    #[serde(default)]
    pub arguments: Option<Vec<PromptArgument>>,
}

/// Argument definition for a prompt.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,

    /// Description of the argument.
    #[serde(default)]
    pub description: Option<String>,

    /// Whether the argument is required.
    #[serde(default)]
    pub required: Option<bool>,
}

/// Result of `prompts/list`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptsListResult {
    #[serde(default)]
    pub prompts: Vec<PromptInfo>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_jsonrpc_request_with_params() {
        let req = JsonRpcRequest::new(1, "initialize", Some(serde_json::json!({"key": "value"})));
        let json = serde_json::to_value(&req).unwrap();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "initialize");
        assert_eq!(json["params"]["key"], "value");
    }

    #[test]
    fn serialize_jsonrpc_request_without_params() {
        let req = JsonRpcRequest::new(42, "tools/list", None);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["method"], "tools/list");
        // params should be omitted entirely
        assert!(parsed.get("params").is_none());
    }

    #[test]
    fn deserialize_jsonrpc_response_success() {
        let json = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.id, Some(1));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn deserialize_jsonrpc_response_error() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid Request"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();

        assert_eq!(resp.id, Some(1));
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "Invalid Request");
        assert!(err.data.is_none());
    }

    #[test]
    fn deserialize_jsonrpc_response_error_with_data() {
        let json = r#"{"jsonrpc":"2.0","id":5,"error":{"code":-32601,"message":"Method not found","data":"details"}}"#;
        let resp: JsonRpcResponse = serde_json::from_str(json).unwrap();

        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.data, Some(Value::String("details".to_string())));
    }

    #[test]
    fn serialize_jsonrpc_notification() {
        let notif = JsonRpcNotification::new("notifications/initialized", None);
        let json = serde_json::to_value(&notif).unwrap();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "notifications/initialized");
        assert!(json.get("id").is_none());
        assert!(json.get("params").is_none());
    }

    #[test]
    fn serialize_initialize_params_camel_case() {
        let params = InitializeParams {
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: ClientCapabilities {},
            client_info: Implementation {
                name: "test-client".to_string(),
                version: "0.1.0".to_string(),
            },
        };

        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(json["clientInfo"]["name"], "test-client");
        assert_eq!(json["clientInfo"]["version"], "0.1.0");
        // Verify camelCase (not snake_case)
        assert!(json.get("protocol_version").is_none());
        assert!(json.get("client_info").is_none());
    }

    #[test]
    fn deserialize_initialize_result_full() {
        let json = r#"{
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": true},
                "resources": {"subscribe": false, "listChanged": true},
                "prompts": {}
            },
            "serverInfo": {
                "name": "test-server",
                "version": "2.0.0"
            }
        }"#;

        let result: InitializeResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.protocol_version, "2024-11-05");
        assert!(result.capabilities.tools.is_some());
        assert_eq!(
            result.capabilities.tools.as_ref().unwrap().list_changed,
            Some(true)
        );
        assert!(result.capabilities.resources.is_some());
        assert!(result.capabilities.prompts.is_some());
        let info = result.server_info.unwrap();
        assert_eq!(info.name, "test-server");
        assert_eq!(info.version, "2.0.0");
    }

    #[test]
    fn deserialize_initialize_result_minimal() {
        let json = r#"{
            "protocolVersion": "2024-11-05",
            "capabilities": {}
        }"#;

        let result: InitializeResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.protocol_version, "2024-11-05");
        assert!(result.capabilities.tools.is_none());
        assert!(result.capabilities.resources.is_none());
        assert!(result.capabilities.prompts.is_none());
        assert!(result.server_info.is_none());
    }

    #[test]
    fn deserialize_tools_list_result() {
        let json = r#"{
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file from disk",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"]
                    }
                },
                {
                    "name": "list_dir",
                    "inputSchema": {"type": "object"}
                }
            ]
        }"#;

        let result: ToolsListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.tools.len(), 2);
        assert_eq!(result.tools[0].name, "read_file");
        assert_eq!(
            result.tools[0].description.as_deref(),
            Some("Read a file from disk")
        );
        assert_eq!(result.tools[1].name, "list_dir");
        assert!(result.tools[1].description.is_none());
        assert!(result.next_cursor.is_none());
    }

    #[test]
    fn deserialize_tools_list_with_cursor() {
        let json = r#"{
            "tools": [{"name": "tool1", "inputSchema": {"type": "object"}}],
            "nextCursor": "page2token"
        }"#;

        let result: ToolsListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.next_cursor.as_deref(), Some("page2token"));
    }

    #[test]
    fn deserialize_minimal_tool_defaults() {
        let json = r#"{"name": "simple_tool"}"#;
        let tool: ToolInfo = serde_json::from_str(json).unwrap();

        assert_eq!(tool.name, "simple_tool");
        assert!(tool.description.is_none());
        assert_eq!(tool.input_schema, serde_json::json!({"type": "object"}));
    }

    #[test]
    fn deserialize_resources_list_result() {
        let json = r#"{
            "resources": [
                {
                    "uri": "file:///tmp",
                    "name": "Temp Directory",
                    "description": "Temporary file storage",
                    "mimeType": "inode/directory"
                },
                {
                    "uri": "file:///home",
                    "name": "Home"
                }
            ]
        }"#;

        let result: ResourcesListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.resources.len(), 2);
        assert_eq!(result.resources[0].uri, "file:///tmp");
        assert_eq!(
            result.resources[0].mime_type.as_deref(),
            Some("inode/directory")
        );
        assert!(result.resources[1].description.is_none());
        assert!(result.resources[1].mime_type.is_none());
    }

    #[test]
    fn deserialize_prompts_list_result() {
        let json = r#"{
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
                            "description": "Maximum length",
                            "required": false
                        }
                    ]
                }
            ]
        }"#;

        let result: PromptsListResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.prompts.len(), 1);
        assert_eq!(result.prompts[0].name, "summarize");
        let args = result.prompts[0].arguments.as_ref().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0].name, "text");
        assert_eq!(args[0].required, Some(true));
        assert_eq!(args[1].required, Some(false));
    }

    #[test]
    fn deserialize_prompt_no_arguments() {
        let json = r#"{"name": "greeting", "description": "Say hello"}"#;
        let prompt: PromptInfo = serde_json::from_str(json).unwrap();

        assert_eq!(prompt.name, "greeting");
        assert!(prompt.arguments.is_none());
    }

    #[test]
    fn server_capabilities_default_all_none() {
        let caps = ServerCapabilities::default();
        assert!(caps.tools.is_none());
        assert!(caps.resources.is_none());
        assert!(caps.prompts.is_none());
        assert!(caps.logging.is_none());
    }

    #[test]
    fn roundtrip_server_capabilities() {
        let caps = ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: Some(true),
            }),
            resources: None,
            prompts: Some(PromptsCapability { list_changed: None }),
            logging: None,
        };

        let json = serde_json::to_string(&caps).unwrap();
        let deserialized: ServerCapabilities = serde_json::from_str(&json).unwrap();

        assert!(deserialized.tools.is_some());
        assert!(deserialized.resources.is_none());
        assert!(deserialized.prompts.is_some());
    }
}
