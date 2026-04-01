pub mod adoption;
pub mod cve;
pub mod github;
pub mod owasp;

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

/// A single event discovered by a monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub id: String,
    pub source: MonitorSource,
    pub title: String,
    pub description: String,
    pub url: String,
    pub discovered_at: DateTime<Utc>,
    pub severity: Option<Severity>,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Which monitor produced the event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitorSource {
    GitHub,
    Cve,
    Owasp,
    Adoption,
}

impl std::fmt::Display for MonitorSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitHub => write!(f, "GitHub"),
            Self::Cve => write!(f, "CVE"),
            Self::Owasp => write!(f, "OWASP"),
            Self::Adoption => write!(f, "Adoption"),
        }
    }
}

/// Severity levels aligned with CVSS qualitative ratings.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

/// Options passed to [`Monitor::poll`].
#[derive(Debug, Clone)]
pub struct PollOptions {
    pub since: Option<DateTime<Utc>>,
    pub max_results: usize,
}

impl Default for PollOptions {
    fn default() -> Self {
        Self {
            since: None,
            max_results: 50,
        }
    }
}

/// Core trait for all ecosystem monitors. Object-safe with boxed futures.
pub trait Monitor: Send + Sync {
    /// The source identifier for events produced by this monitor.
    fn source(&self) -> MonitorSource;

    /// Human-readable name for this monitor.
    fn name(&self) -> &str;

    /// Poll for new events. Returns a boxed future for object safety.
    fn poll(
        &self,
        opts: &PollOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>>;
}
