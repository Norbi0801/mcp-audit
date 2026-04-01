//! HTTP client utilities — shared reqwest client builder, rate-limit-aware wrapper,
//! retry logic, and user-agent configuration.

mod client;

pub use client::RateLimitedClient;
