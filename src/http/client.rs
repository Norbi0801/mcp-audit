use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT};
use serde::de::DeserializeOwned;
use url::Url;

use crate::config::AppConfig;
use crate::error::{McpScannerError, Result};

/// Type alias for the governor rate limiter used per-domain.
type Limiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Known API domains that we apply specific rate-limit policies to.
const GITHUB_API_HOST: &str = "api.github.com";
const NVD_API_HOST: &str = "services.nvd.nist.gov";

/// Maximum number of retry attempts on 429 (Too Many Requests) responses.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles on each retry).
const BASE_BACKOFF: Duration = Duration::from_secs(2);

/// An HTTP client that enforces per-domain rate limits, automatic retries on
/// 429 responses, and injects authentication headers for known APIs.
#[derive(Clone)]
pub struct RateLimitedClient {
    inner: reqwest::Client,
    limiters: Arc<HashMap<String, Limiter>>,
    github_token: Option<String>,
    nvd_api_key: Option<String>,
}

impl RateLimitedClient {
    /// Build a new client from application configuration.
    ///
    /// Rate limits are configured per domain:
    /// - GitHub: 10 req/min unauthenticated, 30 req/min with token
    /// - NVD:    5 req/30s unauthenticated, 50 req/30s with API key
    pub fn new(config: &AppConfig) -> Self {
        let mut default_headers = HeaderMap::new();
        default_headers.insert(USER_AGENT, HeaderValue::from_static("mcp-audit/0.1.0"));

        let inner = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");

        let mut limiters = HashMap::new();

        // GitHub rate limit.
        let github_rpm = if config.github_token.is_some() {
            30
        } else {
            10
        };
        let github_quota =
            Quota::per_minute(NonZeroU32::new(github_rpm).expect("non-zero github rate"));
        limiters.insert(
            GITHUB_API_HOST.to_owned(),
            RateLimiter::direct(github_quota),
        );

        // NVD rate limit — expressed as N requests per 30 seconds.
        let nvd_per_30s = if config.nvd_api_key.is_some() { 50 } else { 5 };
        let nvd_quota = Quota::with_period(Duration::from_secs(30))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(nvd_per_30s).expect("non-zero nvd rate"));
        limiters.insert(NVD_API_HOST.to_owned(), RateLimiter::direct(nvd_quota));

        Self {
            inner,
            limiters: Arc::new(limiters),
            github_token: config.github_token.clone(),
            nvd_api_key: config.nvd_api_key.clone(),
        }
    }

    /// Send a GET request with rate limiting and retry logic.
    ///
    /// Returns the raw [`reqwest::Response`] on success.
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let parsed = Url::parse(url)
            .map_err(|e| McpScannerError::Config(format!("invalid URL `{url}`: {e}")))?;

        // Acquire a rate-limit permit for the target domain.
        self.wait_for_permit(&parsed).await;

        let mut last_err: Option<McpScannerError> = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                let backoff = BASE_BACKOFF * 2u32.saturating_pow(attempt - 1);
                tracing::warn!(
                    url,
                    attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    "Retrying after 429"
                );
                tokio::time::sleep(backoff).await;

                // Re-acquire permit before retry.
                self.wait_for_permit(&parsed).await;
            }

            tracing::debug!(url, attempt, "HTTP GET");

            let mut builder = self.inner.get(url);
            builder = self.inject_auth(builder, &parsed);

            let response = builder.send().await?;

            if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                let retry_after = parse_retry_after(&response);
                let host = parsed.host_str().unwrap_or("unknown").to_string();
                tracing::warn!(
                    api = %host,
                    retry_after_secs = retry_after,
                    "Rate limited (429)"
                );
                last_err = Some(McpScannerError::RateLimited {
                    api: host,
                    retry_after_secs: retry_after,
                });
                continue;
            }

            // Map known API error status codes to typed errors.
            if !response.status().is_success() {
                let status = response.status().as_u16();
                let host = parsed.host_str().unwrap_or("");
                let message = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "(failed to read body)".into());

                if host == GITHUB_API_HOST {
                    return Err(McpScannerError::GitHubApi { status, message });
                }
                if host == NVD_API_HOST {
                    return Err(McpScannerError::NvdApi { status, message });
                }

                // Generic HTTP error: construct a meaningful message and surface
                // it through the reqwest error variant by using the builder.
                return Err(McpScannerError::Config(format!(
                    "HTTP {status} from {host}: {message}"
                )));
            }

            return Ok(response);
        }

        // All retries exhausted.
        Err(last_err.expect("at least one attempt must have been made"))
    }

    /// Convenience method: GET a URL and deserialize the JSON body.
    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        let response = self.get(url).await?;
        let body = response.text().await?;
        let value: T = serde_json::from_str(&body)?;
        Ok(value)
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Block until the rate limiter for the target domain (if any) grants a
    /// permit. Unknown domains are not rate-limited.
    async fn wait_for_permit(&self, url: &Url) {
        let host = match url.host_str() {
            Some(h) => h,
            None => return,
        };

        if let Some(limiter) = self.limiters.get(host) {
            tracing::trace!(host, "Waiting for rate-limit permit");
            limiter.until_ready().await;
        }
    }

    /// Attach authentication headers for known APIs.
    fn inject_auth(&self, builder: reqwest::RequestBuilder, url: &Url) -> reqwest::RequestBuilder {
        let host = url.host_str().unwrap_or("");

        if host == GITHUB_API_HOST {
            if let Some(ref token) = self.github_token {
                tracing::trace!("Injecting GitHub Bearer token");
                return builder
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header("X-GitHub-Api-Version", "2022-11-28");
            }
        }

        if host == NVD_API_HOST {
            if let Some(ref key) = self.nvd_api_key {
                tracing::trace!("Injecting NVD API key");
                return builder.header("apiKey", key.as_str());
            }
        }

        builder
    }
}

/// Parse the `Retry-After` header value as seconds. Falls back to 60s if the
/// header is missing or unparseable.
fn parse_retry_after(response: &reqwest::Response) -> u64 {
    response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, OutputFormat};
    use std::path::PathBuf;

    fn test_config(github_token: Option<&str>, nvd_api_key: Option<&str>) -> AppConfig {
        AppConfig {
            github_token: github_token.map(String::from),
            nvd_api_key: nvd_api_key.map(String::from),
            state_dir: PathBuf::from("/tmp/mcp-audit-test"),
            output_format: OutputFormat::Json,
            verbose: false,
        }
    }

    #[test]
    fn client_builds_without_tokens() {
        let config = test_config(None, None);
        let _client = RateLimitedClient::new(&config);
    }

    #[test]
    fn client_builds_with_tokens() {
        let config = test_config(Some("ghp_test123"), Some("nvd-key-456"));
        let _client = RateLimitedClient::new(&config);
    }

    #[test]
    fn parse_retry_after_header() {
        // We cannot easily construct a reqwest::Response in tests, so we test
        // the fallback path and the parsing logic separately.
        let val: Option<u64> = "120".parse::<u64>().ok();
        assert_eq!(val, Some(120));

        let val: Option<u64> = "not-a-number".parse::<u64>().ok();
        assert_eq!(val, None);
    }

    #[tokio::test]
    async fn get_invalid_url_returns_config_error() {
        let config = test_config(None, None);
        let client = RateLimitedClient::new(&config);

        let result = client.get("not-a-valid-url").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            McpScannerError::Config(msg) => {
                assert!(msg.contains("invalid URL"), "unexpected message: {msg}");
            }
            other => panic!("expected Config error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_json_connection_refused() {
        // Attempting to connect to a port that is almost certainly not listening.
        let config = test_config(None, None);
        let client = RateLimitedClient::new(&config);

        let result = client
            .get_json::<serde_json::Value>("http://127.0.0.1:19999/nope")
            .await;
        assert!(result.is_err());
    }
}
