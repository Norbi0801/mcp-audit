//! MCP-11: Denial of Service
//!
//! Detects MCP server configurations that expose the client to denial-of-service
//! risks: missing timeouts, unbounded response sizes, uninterruptible streams,
//! and resource subscriptions without unsubscribe capability.

use super::Rule;
use crate::monitors::Severity;
use crate::parser::McpServerConfig;
use crate::scanner::ScanFinding;

// ── Timeout detection ────────────────────────────────────────────────────

/// Environment variables that indicate a timeout is configured.
const TIMEOUT_ENV_VARS: &[&str] = &[
    "TIMEOUT",
    "REQUEST_TIMEOUT",
    "RESPONSE_TIMEOUT",
    "CONNECTION_TIMEOUT",
    "MCP_TIMEOUT",
    "EXECUTION_TIMEOUT",
    "TOOL_TIMEOUT",
    "READ_TIMEOUT",
    "WRITE_TIMEOUT",
    "IDLE_TIMEOUT",
    "KEEPALIVE_TIMEOUT",
    "SOCKET_TIMEOUT",
    "HTTP_TIMEOUT",
    "CLIENT_TIMEOUT",
    "SERVER_TIMEOUT",
    "OPERATION_TIMEOUT",
];

/// Command-line arguments that indicate a timeout is configured.
const TIMEOUT_ARGS: &[&str] = &[
    "--timeout",
    "--request-timeout",
    "--response-timeout",
    "--connection-timeout",
    "--execution-timeout",
    "--tool-timeout",
    "--read-timeout",
    "--write-timeout",
    "--idle-timeout",
    "-t", // common short form for timeout
];

// ── Response size limit detection ────────────────────────────────────────

/// Environment variables that indicate a response size limit is configured.
const SIZE_LIMIT_ENV_VARS: &[&str] = &[
    "MAX_RESPONSE_SIZE",
    "MAX_BODY_SIZE",
    "BODY_SIZE_LIMIT",
    "MAX_PAYLOAD_SIZE",
    "MAX_MESSAGE_SIZE",
    "MAX_OUTPUT_SIZE",
    "RESPONSE_SIZE_LIMIT",
    "MAX_CONTENT_LENGTH",
    "MAX_BUFFER_SIZE",
    "MAX_RESULT_SIZE",
    "PAYLOAD_LIMIT",
    "SIZE_LIMIT",
    "MAX_TOKENS",
    "OUTPUT_LIMIT",
];

/// Command-line arguments that indicate a response size limit is configured.
const SIZE_LIMIT_ARGS: &[&str] = &[
    "--max-response-size",
    "--max-body-size",
    "--body-limit",
    "--max-payload",
    "--max-message-size",
    "--max-output-size",
    "--max-content-length",
    "--max-buffer-size",
    "--size-limit",
    "--payload-limit",
    "--max-tokens",
    "--output-limit",
    "--max-result-size",
];

// ── Stream cancellation detection ────────────────────────────────────────

/// Transport types that involve persistent streaming connections.
const STREAMING_TRANSPORTS: &[&str] = &["sse", "streamable-http", "websocket", "ws"];

/// URL path segments that indicate a streaming endpoint.
const STREAMING_URL_INDICATORS: &[&str] = &[
    "/sse",
    "/stream",
    "/events",
    "/subscribe",
    "/ws",
    "/websocket",
];

/// Environment variables or arguments that indicate stream cancellation support.
const CANCEL_ENV_VARS: &[&str] = &[
    "ENABLE_CANCELLATION",
    "CANCEL_ENABLED",
    "STREAM_TIMEOUT",
    "MAX_STREAM_DURATION",
    "SSE_TIMEOUT",
    "STREAM_IDLE_TIMEOUT",
    "MAX_STREAM_TIME",
    "STREAM_KEEPALIVE_TIMEOUT",
    "WS_TIMEOUT",
    "WEBSOCKET_TIMEOUT",
    "MAX_EVENTS",
    "MAX_STREAM_EVENTS",
    "EVENT_LIMIT",
];

/// Command-line arguments that indicate stream cancellation / bounding support.
const CANCEL_ARGS: &[&str] = &[
    "--enable-cancellation",
    "--cancel",
    "--stream-timeout",
    "--max-stream-duration",
    "--sse-timeout",
    "--stream-idle-timeout",
    "--max-events",
    "--event-limit",
    "--max-stream-events",
    "--ws-timeout",
    "--websocket-timeout",
];

// ── Subscription detection ───────────────────────────────────────────────

/// Arguments and env vars that indicate resource subscription support.
const SUBSCRIBE_INDICATORS: &[&str] = &[
    "--subscribe",
    "--enable-subscriptions",
    "--watch",
    "--notify",
    "--pubsub",
    "--enable-watch",
    "--live",
    "--realtime",
];

/// Environment variables that indicate subscription support.
const SUBSCRIBE_ENV_INDICATORS: &[&str] = &[
    "ENABLE_SUBSCRIPTIONS",
    "SUBSCRIPTIONS_ENABLED",
    "ENABLE_WATCH",
    "WATCH_ENABLED",
    "ENABLE_NOTIFY",
    "PUBSUB_ENABLED",
    "REALTIME_ENABLED",
    "ENABLE_LIVE",
];

/// Arguments / env vars that indicate unsubscribe capability.
const UNSUBSCRIBE_INDICATORS: &[&str] = &[
    "--unsubscribe",
    "--enable-unsubscribe",
    "--allow-unsubscribe",
    "--subscription-ttl",
    "--max-subscriptions",
    "--subscription-limit",
    "--subscription-timeout",
    "--max-watchers",
];

/// Environment variables that indicate unsubscribe / subscription management.
const UNSUBSCRIBE_ENV_INDICATORS: &[&str] = &[
    "ENABLE_UNSUBSCRIBE",
    "UNSUBSCRIBE_ENABLED",
    "SUBSCRIPTION_TTL",
    "MAX_SUBSCRIPTIONS",
    "SUBSCRIPTION_LIMIT",
    "SUBSCRIPTION_TIMEOUT",
    "MAX_WATCHERS",
    "WATCHER_LIMIT",
];

pub struct DenialOfServiceRule;

impl super::Rule for DenialOfServiceRule {
    fn id(&self) -> &'static str {
        "MCP-11"
    }

    fn name(&self) -> &'static str {
        "Denial of Service"
    }

    fn description(&self) -> &'static str {
        "Detects MCP server configurations that expose clients to denial-of-service \
         risks: missing timeouts, unbounded response sizes, infinite streams without \
         cancellation, and resource subscriptions without unsubscribe capability."
    }

    fn default_severity(&self) -> Severity {
        Severity::Medium
    }

    fn owasp_id(&self) -> &'static str {
        "OWASP-MCP-11"
    }

    fn check(&self, server_name: &str, server: &McpServerConfig) -> Vec<ScanFinding> {
        let mut findings = Vec::new();

        self.check_missing_timeout(server_name, server, &mut findings);
        self.check_missing_size_limit(server_name, server, &mut findings);
        self.check_unbounded_streams(server_name, server, &mut findings);
        self.check_subscription_without_unsubscribe(server_name, server, &mut findings);

        findings
    }
}

impl DenialOfServiceRule {
    /// Check 1: No timeout configuration — server can block the client indefinitely.
    fn check_missing_timeout(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let has_timeout_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                TIMEOUT_ENV_VARS.iter().any(|tv| upper.contains(tv))
            })
        });

        let args = server.args.as_deref().unwrap_or(&[]);
        let has_timeout_arg = args
            .iter()
            .any(|a| TIMEOUT_ARGS.iter().any(|ta| a.starts_with(ta)));

        if !has_timeout_env && !has_timeout_arg {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!("No timeout configured for server '{}'", server_name),
                description: "Server has no timeout configuration. A malicious or buggy tool \
                     can block the client indefinitely by never returning a response. \
                     Configure a request timeout (e.g., --timeout, REQUEST_TIMEOUT) \
                     to limit how long the client waits for each tool invocation."
                    .to_string(),
            });
        }
    }

    /// Check 2: No response size limit — tool can exhaust client memory.
    fn check_missing_size_limit(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let has_size_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                SIZE_LIMIT_ENV_VARS.iter().any(|sv| upper.contains(sv))
            })
        });

        let args = server.args.as_deref().unwrap_or(&[]);
        let has_size_arg = args
            .iter()
            .any(|a| SIZE_LIMIT_ARGS.iter().any(|sa| a.starts_with(sa)));

        if !has_size_env && !has_size_arg {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!("No response size limit for server '{}'", server_name),
                description: "Server has no response size limit. A tool can return arbitrarily \
                     large payloads, exhausting client memory and causing a denial of \
                     service. Configure a maximum response size (e.g., --max-response-size, \
                     MAX_RESPONSE_SIZE) to bound tool output."
                    .to_string(),
            });
        }
    }

    /// Check 3: Streaming transport without cancellation — infinite streams block the client.
    fn check_unbounded_streams(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let is_streaming = self.is_streaming_server(server);

        if !is_streaming {
            return;
        }

        // Check for cancellation / stream bounding configuration.
        let has_cancel_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                CANCEL_ENV_VARS.iter().any(|cv| upper.contains(cv))
            })
        });

        let args = server.args.as_deref().unwrap_or(&[]);
        let has_cancel_arg = args
            .iter()
            .any(|a| CANCEL_ARGS.iter().any(|ca| a.starts_with(ca)));

        // Also accept generic timeout as partial mitigation for streams.
        let has_timeout_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                TIMEOUT_ENV_VARS.iter().any(|tv| upper.contains(tv))
            })
        });
        let has_timeout_arg = args
            .iter()
            .any(|a| TIMEOUT_ARGS.iter().any(|ta| a.starts_with(ta)));

        if !has_cancel_env && !has_cancel_arg && !has_timeout_env && !has_timeout_arg {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!(
                    "Streaming server '{}' has no cancellation mechanism",
                    server_name
                ),
                description:
                    "Server uses a streaming transport (SSE, WebSocket, or streamable-http) \
                     without any cancellation or stream-bounding configuration. An infinite \
                     stream can block the client forever and consume unbounded resources. \
                     Configure --enable-cancellation, a stream timeout (STREAM_TIMEOUT), \
                     or an event limit (MAX_EVENTS)."
                        .to_string(),
            });
        }
    }

    /// Check 4: Resource subscription without unsubscribe — leaked subscriptions exhaust resources.
    fn check_subscription_without_unsubscribe(
        &self,
        server_name: &str,
        server: &McpServerConfig,
        findings: &mut Vec<ScanFinding>,
    ) {
        let args = server.args.as_deref().unwrap_or(&[]);

        // Detect subscription support from args.
        let has_subscribe_arg = args
            .iter()
            .any(|a| SUBSCRIBE_INDICATORS.iter().any(|si| a.starts_with(si)));

        // Detect subscription support from env.
        let has_subscribe_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                SUBSCRIBE_ENV_INDICATORS.iter().any(|si| upper.contains(si))
            })
        });

        if !has_subscribe_arg && !has_subscribe_env {
            return; // No subscriptions detected — nothing to check.
        }

        // Check for unsubscribe / subscription management.
        let has_unsubscribe_arg = args
            .iter()
            .any(|a| UNSUBSCRIBE_INDICATORS.iter().any(|ui| a.starts_with(ui)));

        let has_unsubscribe_env = server.env.as_ref().is_some_and(|env| {
            env.keys().any(|k| {
                let upper = k.to_uppercase();
                UNSUBSCRIBE_ENV_INDICATORS
                    .iter()
                    .any(|ui| upper.contains(ui))
            })
        });

        if !has_unsubscribe_arg && !has_unsubscribe_env {
            findings.push(ScanFinding {
                rule_id: self.id().to_string(),
                severity: Severity::Medium,
                title: format!(
                    "Subscription without unsubscribe in server '{}'",
                    server_name
                ),
                description: "Server supports resource subscriptions but has no unsubscribe or \
                     subscription management configuration. Without the ability to \
                     unsubscribe or limit subscriptions, leaked subscriptions accumulate \
                     and exhaust server and client resources. Configure a subscription \
                     TTL (SUBSCRIPTION_TTL), a limit (MAX_SUBSCRIPTIONS), or enable \
                     unsubscribe (--enable-unsubscribe)."
                    .to_string(),
            });
        }
    }

    /// Determine if the server uses a streaming transport.
    fn is_streaming_server(&self, server: &McpServerConfig) -> bool {
        // Check explicit transport field.
        if let Some(transport) = &server.transport {
            let lower = transport.to_lowercase();
            if STREAMING_TRANSPORTS.iter().any(|st| lower == *st) {
                return true;
            }
        }

        // Check URL for streaming indicators.
        if let Some(url) = &server.url {
            let lower = url.to_lowercase();
            if STREAMING_URL_INDICATORS.iter().any(|si| lower.contains(si)) {
                return true;
            }
        }

        // Check args for streaming-related flags.
        let args = server.args.as_deref().unwrap_or(&[]);
        let args_lower: Vec<String> = args.iter().map(|a| a.to_lowercase()).collect();
        if args_lower.iter().any(|a| {
            a.contains("--sse")
                || a.contains("--stream")
                || a.contains("--websocket")
                || a.contains("--ws")
                || a.contains("--transport=sse")
                || a.contains("--transport=websocket")
                || a.contains("--transport=streamable-http")
        }) {
            return true;
        }

        // Check env for transport configuration.
        if let Some(env) = &server.env {
            for (key, value) in env {
                let key_upper = key.to_uppercase();
                let value_lower = value.to_lowercase();
                if (key_upper.contains("TRANSPORT") || key_upper.contains("PROTOCOL"))
                    && (STREAMING_TRANSPORTS.iter().any(|st| value_lower == *st)
                        || value_lower.contains("stream"))
                {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use std::collections::HashMap;

    fn check_with_env(args: &[&str], env: HashMap<String, String>) -> Vec<ScanFinding> {
        let rule = DenialOfServiceRule;
        let server = McpServerConfig {
            command: Some("node".into()),
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    fn check_args_only(args: &[&str]) -> Vec<ScanFinding> {
        check_with_env(args, HashMap::new())
    }

    fn check_http_server(
        url: &str,
        transport: Option<&str>,
        args: &[&str],
        env: HashMap<String, String>,
    ) -> Vec<ScanFinding> {
        let rule = DenialOfServiceRule;
        let server = McpServerConfig {
            args: Some(args.iter().map(|s| s.to_string()).collect()),
            env: Some(env),
            url: Some(url.to_string()),
            transport: transport.map(|s| s.to_string()),
            ..Default::default()
        };
        rule.check("test-server", &server)
    }

    // ── Rule metadata ────────────────────────────────────────────────────

    #[test]
    fn rule_metadata() {
        let rule = DenialOfServiceRule;
        assert_eq!(rule.id(), "MCP-11");
        assert_eq!(rule.name(), "Denial of Service");
        assert_eq!(rule.owasp_id(), "OWASP-MCP-11");
        assert_eq!(rule.default_severity(), Severity::Medium);
    }

    // ── Check 1: Missing timeout ─────────────────────────────────────────

    #[test]
    fn detects_missing_timeout() {
        let findings = check_args_only(&["server.js", "--port", "3000"]);
        assert!(
            findings.iter().any(|f| f.title.contains("No timeout")),
            "Should detect missing timeout configuration"
        );
    }

    #[test]
    fn timeout_env_var_passes() {
        let mut env = HashMap::new();
        env.insert("REQUEST_TIMEOUT".into(), "30000".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("No timeout")),
            "Server with REQUEST_TIMEOUT should not get timeout warning"
        );
    }

    #[test]
    fn timeout_arg_passes() {
        let findings = check_args_only(&["server.js", "--timeout", "30000"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("No timeout")),
            "Server with --timeout should not get timeout warning"
        );
    }

    #[test]
    fn partial_timeout_env_var_matches() {
        let mut env = HashMap::new();
        env.insert("MCP_TOOL_TIMEOUT".into(), "5000".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("No timeout")),
            "Env var containing TIMEOUT should suppress the warning"
        );
    }

    // ── Check 2: Missing response size limit ─────────────────────────────

    #[test]
    fn detects_missing_size_limit() {
        let findings = check_args_only(&["server.js"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("No response size limit")),
            "Should detect missing response size limit"
        );
    }

    #[test]
    fn size_limit_env_var_passes() {
        let mut env = HashMap::new();
        env.insert("MAX_RESPONSE_SIZE".into(), "10485760".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No response size limit")),
            "Server with MAX_RESPONSE_SIZE should not get size limit warning"
        );
    }

    #[test]
    fn size_limit_arg_passes() {
        let findings = check_args_only(&["server.js", "--max-response-size", "10485760"]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No response size limit")),
            "Server with --max-response-size should not get size limit warning"
        );
    }

    #[test]
    fn max_tokens_env_passes() {
        let mut env = HashMap::new();
        env.insert("MAX_TOKENS".into(), "4096".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("No response size limit")),
            "Server with MAX_TOKENS should not get size limit warning"
        );
    }

    // ── Check 3: Streaming without cancellation ──────────────────────────

    #[test]
    fn detects_unbounded_sse_stream() {
        let findings = check_http_server(
            "https://mcp.example.com/sse",
            Some("sse"),
            &[],
            HashMap::new(),
        );
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "SSE server without cancellation should be flagged"
        );
    }

    #[test]
    fn detects_streaming_by_url_path() {
        let findings =
            check_http_server("https://mcp.example.com/stream", None, &[], HashMap::new());
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "Server with /stream URL should be detected as streaming"
        );
    }

    #[test]
    fn detects_streaming_by_transport_env() {
        let mut env = HashMap::new();
        env.insert("TRANSPORT".into(), "sse".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "Server with TRANSPORT=sse env should be detected as streaming"
        );
    }

    #[test]
    fn detects_streaming_by_arg() {
        let findings = check_args_only(&["server.js", "--sse"]);
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "Server with --sse arg should be detected as streaming"
        );
    }

    #[test]
    fn streaming_with_cancellation_passes() {
        let mut env = HashMap::new();
        env.insert("ENABLE_CANCELLATION".into(), "true".into());
        let findings = check_http_server("https://mcp.example.com/sse", Some("sse"), &[], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("no cancellation")),
            "SSE server with ENABLE_CANCELLATION should not get stream warning"
        );
    }

    #[test]
    fn streaming_with_stream_timeout_passes() {
        let mut env = HashMap::new();
        env.insert("STREAM_TIMEOUT".into(), "60000".into());
        let findings = check_http_server("https://mcp.example.com/sse", Some("sse"), &[], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("no cancellation")),
            "SSE server with STREAM_TIMEOUT should not get stream warning"
        );
    }

    #[test]
    fn streaming_with_generic_timeout_passes() {
        let mut env = HashMap::new();
        env.insert("REQUEST_TIMEOUT".into(), "30000".into());
        let findings = check_http_server("https://mcp.example.com/sse", Some("sse"), &[], env);
        assert!(
            !findings.iter().any(|f| f.title.contains("no cancellation")),
            "SSE server with generic timeout should not get stream warning"
        );
    }

    #[test]
    fn streaming_with_cancel_arg_passes() {
        let findings = check_http_server(
            "https://mcp.example.com/sse",
            Some("sse"),
            &["--enable-cancellation"],
            HashMap::new(),
        );
        assert!(
            !findings.iter().any(|f| f.title.contains("no cancellation")),
            "SSE server with --enable-cancellation should not get stream warning"
        );
    }

    #[test]
    fn non_streaming_server_no_stream_warning() {
        let findings = check_args_only(&["server.js", "--port", "3000"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("no cancellation")),
            "Non-streaming server should not get stream cancellation warning"
        );
    }

    #[test]
    fn websocket_transport_detected() {
        let findings = check_http_server(
            "https://mcp.example.com/ws",
            Some("websocket"),
            &[],
            HashMap::new(),
        );
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "WebSocket server without cancellation should be flagged"
        );
    }

    #[test]
    fn streamable_http_detected() {
        let findings = check_http_server(
            "https://mcp.example.com/mcp",
            Some("streamable-http"),
            &[],
            HashMap::new(),
        );
        assert!(
            findings.iter().any(|f| f.title.contains("no cancellation")),
            "streamable-http server without cancellation should be flagged"
        );
    }

    // ── Check 4: Subscription without unsubscribe ────────────────────────

    #[test]
    fn detects_subscription_without_unsubscribe() {
        let findings = check_args_only(&["server.js", "--enable-subscriptions"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with subscriptions but no unsubscribe should be flagged"
        );
    }

    #[test]
    fn detects_watch_without_unsubscribe() {
        let findings = check_args_only(&["server.js", "--watch"]);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with --watch but no unsubscribe should be flagged"
        );
    }

    #[test]
    fn detects_subscribe_env_without_unsubscribe() {
        let mut env = HashMap::new();
        env.insert("ENABLE_SUBSCRIPTIONS".into(), "true".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with ENABLE_SUBSCRIPTIONS env but no unsubscribe should be flagged"
        );
    }

    #[test]
    fn subscription_with_unsubscribe_passes() {
        let findings = check_args_only(&[
            "server.js",
            "--enable-subscriptions",
            "--enable-unsubscribe",
        ]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with both subscribe and unsubscribe should not be flagged"
        );
    }

    #[test]
    fn subscription_with_ttl_passes() {
        let mut env = HashMap::new();
        env.insert("ENABLE_SUBSCRIPTIONS".into(), "true".into());
        env.insert("SUBSCRIPTION_TTL".into(), "3600".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with subscription TTL should not be flagged"
        );
    }

    #[test]
    fn subscription_with_max_subscriptions_passes() {
        let findings = check_args_only(&[
            "server.js",
            "--enable-subscriptions",
            "--max-subscriptions",
            "100",
        ]);
        assert!(
            !findings
                .iter()
                .any(|f| f.title.contains("Subscription without unsubscribe")),
            "Server with --max-subscriptions should not be flagged"
        );
    }

    #[test]
    fn no_subscription_no_warning() {
        let findings = check_args_only(&["server.js", "--port", "3000"]);
        assert!(
            !findings.iter().any(|f| f.title.contains("Subscription")),
            "Server without subscriptions should not get subscription warning"
        );
    }

    // ── Combined scenarios ───────────────────────────────────────────────

    #[test]
    fn fully_configured_server_has_no_findings() {
        let mut env = HashMap::new();
        env.insert("REQUEST_TIMEOUT".into(), "30000".into());
        env.insert("MAX_RESPONSE_SIZE".into(), "10485760".into());
        let findings = check_with_env(&["server.js"], env);
        assert!(
            findings.is_empty(),
            "Fully configured server should have no DoS findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn bare_server_has_timeout_and_size_findings() {
        let findings = check_args_only(&["server.js"]);
        let has_timeout = findings.iter().any(|f| f.title.contains("No timeout"));
        let has_size = findings
            .iter()
            .any(|f| f.title.contains("No response size limit"));
        assert!(has_timeout, "Bare server should trigger timeout warning");
        assert!(has_size, "Bare server should trigger size limit warning");
    }

    #[test]
    fn all_findings_have_medium_severity() {
        let findings = check_args_only(&["server.js", "--enable-subscriptions"]);
        for f in &findings {
            assert_eq!(
                f.severity,
                Severity::Medium,
                "All DoS findings should be Medium severity, got {:?} for '{}'",
                f.severity,
                f.title
            );
        }
    }

    #[test]
    fn streaming_server_with_all_protections() {
        let mut env = HashMap::new();
        env.insert("REQUEST_TIMEOUT".into(), "30000".into());
        env.insert("MAX_RESPONSE_SIZE".into(), "10485760".into());
        env.insert("ENABLE_CANCELLATION".into(), "true".into());
        let findings = check_http_server("https://mcp.example.com/sse", Some("sse"), &[], env);
        assert!(
            findings.is_empty(),
            "Streaming server with all protections should have no findings, got: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn http_server_without_streaming_only_gets_basic_findings() {
        let findings = check_http_server("https://api.example.com/mcp", None, &[], HashMap::new());
        // Should get timeout and size limit findings but NOT stream cancellation.
        let has_timeout = findings.iter().any(|f| f.title.contains("No timeout"));
        let has_size = findings
            .iter()
            .any(|f| f.title.contains("No response size limit"));
        let has_cancel = findings.iter().any(|f| f.title.contains("no cancellation"));
        assert!(has_timeout, "HTTP server should get timeout warning");
        assert!(has_size, "HTTP server should get size limit warning");
        assert!(
            !has_cancel,
            "Non-streaming HTTP server should not get cancel warning"
        );
    }
}
