//! Integration tests for the MCP server connection module.
//!
//! Uses `wiremock` to simulate an MCP server over HTTP and tests the full
//! initialization + discovery flow.

use std::time::Duration;

use mcp_audit::connection::{HttpTransportType, McpClient, DEFAULT_TIMEOUT};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// Mock MCP server responder that routes JSON-RPC requests to appropriate
/// responses based on the `method` field in the request body.
struct McpMockResponder {
    init_result: serde_json::Value,
    tools: Vec<serde_json::Value>,
    resources: Vec<serde_json::Value>,
    prompts: Vec<serde_json::Value>,
}

impl McpMockResponder {
    fn full_server() -> Self {
        Self {
            init_result: serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "wiremock-mcp-server",
                    "version": "1.0.0"
                }
            }),
            tools: vec![
                serde_json::json!({
                    "name": "read_file",
                    "description": "Read file contents",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"}
                        },
                        "required": ["path"]
                    }
                }),
                serde_json::json!({
                    "name": "write_file",
                    "description": "Write content to file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path", "content"]
                    }
                }),
            ],
            resources: vec![serde_json::json!({
                "uri": "file:///workspace",
                "name": "Workspace",
                "description": "Project workspace",
                "mimeType": "inode/directory"
            })],
            prompts: vec![serde_json::json!({
                "name": "code_review",
                "description": "Review code for issues",
                "arguments": [
                    {
                        "name": "code",
                        "description": "Source code to review",
                        "required": true
                    }
                ]
            })],
        }
    }

    fn tools_only() -> Self {
        Self {
            init_result: serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "tools-only-server",
                    "version": "0.5.0"
                }
            }),
            tools: vec![serde_json::json!({
                "name": "calculator",
                "description": "Perform calculations",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "expression": {"type": "string"}
                    },
                    "required": ["expression"]
                }
            })],
            resources: vec![],
            prompts: vec![],
        }
    }

    fn minimal() -> Self {
        Self {
            init_result: serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {
                    "name": "minimal-server",
                    "version": "0.1.0"
                }
            }),
            tools: vec![],
            resources: vec![],
            prompts: vec![],
        }
    }
}

impl wiremock::Respond for McpMockResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();

        let rpc_method = body["method"].as_str().unwrap_or("");
        let id = body.get("id").cloned();

        match rpc_method {
            "initialize" => {
                let mut resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": self.init_result,
                });
                if let Some(id) = id {
                    resp["id"] = id;
                }
                ResponseTemplate::new(200).set_body_json(resp)
            }
            "tools/list" => {
                let mut resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {"tools": self.tools},
                });
                if let Some(id) = id {
                    resp["id"] = id;
                }
                ResponseTemplate::new(200).set_body_json(resp)
            }
            "resources/list" => {
                let mut resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {"resources": self.resources},
                });
                if let Some(id) = id {
                    resp["id"] = id;
                }
                ResponseTemplate::new(200).set_body_json(resp)
            }
            "prompts/list" => {
                let mut resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": {"prompts": self.prompts},
                });
                if let Some(id) = id {
                    resp["id"] = id;
                }
                ResponseTemplate::new(200).set_body_json(resp)
            }
            "notifications/initialized" => {
                // Notification — just acknowledge.
                ResponseTemplate::new(200)
            }
            _ => {
                let mut resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", rpc_method)
                    },
                });
                if let Some(id) = id {
                    resp["id"] = id;
                }
                ResponseTemplate::new(200).set_body_json(resp)
            }
        }
    }
}

// ── Integration Tests ───────────────────────────────────────────────

#[tokio::test]
async fn http_connect_full_server() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(McpMockResponder::full_server())
        .mount(&mock_server)
        .await;

    let client = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await
    .unwrap();

    // Verify server info.
    assert_eq!(client.server_info().name, "wiremock-mcp-server");
    assert_eq!(client.server_info().version, "1.0.0");
    assert_eq!(client.server_info().protocol_version, "2024-11-05");

    // Verify tools.
    assert_eq!(client.tools().len(), 2);
    assert_eq!(client.tools()[0].name, "read_file");
    assert_eq!(
        client.tools()[0].description.as_deref(),
        Some("Read file contents")
    );
    assert_eq!(client.tools()[1].name, "write_file");

    // Verify tool input schema.
    let schema = &client.tools()[0].input_schema;
    assert_eq!(schema["type"], "object");
    assert!(schema["properties"]["path"]["type"] == "string");

    // Verify resources.
    assert_eq!(client.resources().len(), 1);
    assert_eq!(client.resources()[0].uri, "file:///workspace");
    assert_eq!(client.resources()[0].name, "Workspace");

    // Verify prompts.
    assert_eq!(client.prompts().len(), 1);
    assert_eq!(client.prompts()[0].name, "code_review");
    let args = client.prompts()[0].arguments.as_ref().unwrap();
    assert_eq!(args.len(), 1);
    assert_eq!(args[0].name, "code");
    assert_eq!(args[0].required, Some(true));

    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn http_connect_tools_only_server() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(McpMockResponder::tools_only())
        .mount(&mock_server)
        .await;

    let client = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(client.server_info().name, "tools-only-server");
    assert_eq!(client.tools().len(), 1);
    assert_eq!(client.tools()[0].name, "calculator");
    assert!(client.resources().is_empty());
    assert!(client.prompts().is_empty());

    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn http_connect_minimal_server() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(McpMockResponder::minimal())
        .mount(&mock_server)
        .await;

    let client = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await
    .unwrap();

    assert_eq!(client.server_info().name, "minimal-server");
    assert!(client.tools().is_empty());
    assert!(client.resources().is_empty());
    assert!(client.prompts().is_empty());

    client.disconnect().await.unwrap();
}

#[tokio::test]
async fn http_connect_timeout() {
    let mock_server = MockServer::start().await;

    // Simulate a slow server that takes 10 seconds to respond.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "slow", "version": "1.0.0"}
                    }
                }))
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&mock_server)
        .await;

    let result = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        Duration::from_millis(500), // Very short timeout.
    )
    .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    // Should be either a connection timeout or HTTP error.
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("timeout") || err_msg.contains("Timeout") || err_msg.contains("failed"),
        "Expected timeout-related error, got: {err_msg}"
    );
}

#[tokio::test]
async fn http_connect_server_error() {
    let mock_server = MockServer::start().await;

    // Simulate a server that returns 500 Internal Server Error.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let result = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("500") || err_msg.contains("Internal"),
        "Expected 500 error, got: {err_msg}"
    );
}

#[tokio::test]
async fn http_connect_jsonrpc_error_response() {
    let mock_server = MockServer::start().await;

    // Server responds with a JSON-RPC error to the initialize request.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32603,
                "message": "Server not ready"
            }
        })))
        .mount(&mock_server)
        .await;

    let result = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Server not ready"),
        "Expected JSON-RPC error message, got: {err_msg}"
    );
}

#[tokio::test]
async fn http_connect_unreachable_server() {
    // Try to connect to a port that's not listening.
    let result = McpClient::connect_http(
        "http://127.0.0.1:1",
        HttpTransportType::StreamableHttp,
        Duration::from_secs(2),
    )
    .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn server_info_is_serializable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(McpMockResponder::full_server())
        .mount(&mock_server)
        .await;

    let client = McpClient::connect_http(
        &mock_server.uri(),
        HttpTransportType::StreamableHttp,
        DEFAULT_TIMEOUT,
    )
    .await
    .unwrap();

    // ServerInfo should be serializable to JSON for scan output.
    let json = serde_json::to_value(client.server_info()).unwrap();
    assert_eq!(json["name"], "wiremock-mcp-server");
    assert_eq!(json["version"], "1.0.0");
    assert!(json["tools"].is_array());
    assert_eq!(json["tools"].as_array().unwrap().len(), 2);

    client.disconnect().await.unwrap();
}
