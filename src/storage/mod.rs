//! Persistent state storage — watermark tracking, event deduplication,
//! and local JSON-file cache for offline operation.

mod file_store;

use chrono::{DateTime, Utc};
use std::future::Future;
use std::pin::Pin;

use crate::error::Result;
use crate::monitors::{MonitorEvent, MonitorSource};

pub use file_store::FileStateStore;

/// Abstraction over persistent state storage.
///
/// All methods return boxed futures so the trait is object-safe and can be used
/// behind `Arc<dyn StateStore>`.
#[allow(clippy::type_complexity)]
pub trait StateStore: Send + Sync {
    /// Retrieve the last-polled checkpoint timestamp for a named monitor.
    fn get_checkpoint(
        &self,
        monitor: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<DateTime<Utc>>>> + Send + '_>>;

    /// Persist a checkpoint timestamp for a named monitor.
    fn set_checkpoint(
        &self,
        monitor: &str,
        ts: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Append events to the store, grouped by their `discovered_at` date.
    fn store_events(
        &self,
        events: &[MonitorEvent],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Query stored events, optionally filtered by source and/or a minimum
    /// timestamp.
    fn get_events(
        &self,
        source: Option<MonitorSource>,
        since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>>;
}

/// In-memory state store for testing. Data lives only as long as the instance.
#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    checkpoints: tokio::sync::RwLock<std::collections::HashMap<String, DateTime<Utc>>>,
    events: tokio::sync::RwLock<Vec<MonitorEvent>>,
}

impl InMemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for InMemoryStateStore {
    fn get_checkpoint(
        &self,
        monitor: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<DateTime<Utc>>>> + Send + '_>> {
        let monitor = monitor.to_owned();
        Box::pin(async move {
            let map = self.checkpoints.read().await;
            Ok(map.get(&monitor).copied())
        })
    }

    fn set_checkpoint(
        &self,
        monitor: &str,
        ts: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let monitor = monitor.to_owned();
        Box::pin(async move {
            let mut map = self.checkpoints.write().await;
            map.insert(monitor, ts);
            Ok(())
        })
    }

    fn store_events(
        &self,
        events: &[MonitorEvent],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let events = events.to_vec();
        Box::pin(async move {
            let mut store = self.events.write().await;
            store.extend(events);
            Ok(())
        })
    }

    fn get_events(
        &self,
        source: Option<MonitorSource>,
        since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        Box::pin(async move {
            let store = self.events.read().await;
            let filtered = store
                .iter()
                .filter(|e| {
                    if let Some(src) = source {
                        if e.source != src {
                            return false;
                        }
                    }
                    if let Some(ts) = since {
                        if e.discovered_at < ts {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect();
            Ok(filtered)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_event(source: MonitorSource, title: &str) -> MonitorEvent {
        MonitorEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source,
            title: title.to_owned(),
            description: String::new(),
            url: String::new(),
            discovered_at: Utc::now(),
            severity: None,
            tags: vec![],
            metadata: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn in_memory_checkpoint_roundtrip() {
        let store = InMemoryStateStore::new();
        let now = Utc::now();

        assert!(store.get_checkpoint("gh").await.unwrap().is_none());

        store.set_checkpoint("gh", now).await.unwrap();
        let got = store.get_checkpoint("gh").await.unwrap();
        assert_eq!(got, Some(now));
    }

    #[tokio::test]
    async fn in_memory_checkpoint_overwrite() {
        let store = InMemoryStateStore::new();
        let t1 = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t2 = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        store.set_checkpoint("cve", t1).await.unwrap();
        store.set_checkpoint("cve", t2).await.unwrap();
        assert_eq!(store.get_checkpoint("cve").await.unwrap(), Some(t2));
    }

    #[tokio::test]
    async fn in_memory_store_and_query_events() {
        let store = InMemoryStateStore::new();

        let e1 = make_event(MonitorSource::GitHub, "gh event");
        let e2 = make_event(MonitorSource::Cve, "cve event");
        store.store_events(&[e1, e2]).await.unwrap();

        let all = store.get_events(None, None).await.unwrap();
        assert_eq!(all.len(), 2);

        let gh = store
            .get_events(Some(MonitorSource::GitHub), None)
            .await
            .unwrap();
        assert_eq!(gh.len(), 1);
        assert_eq!(gh[0].title, "gh event");
    }

    #[tokio::test]
    async fn in_memory_filter_by_since() {
        let store = InMemoryStateStore::new();

        let old = MonitorEvent {
            id: "old".into(),
            source: MonitorSource::Cve,
            title: "old".into(),
            description: String::new(),
            url: String::new(),
            discovered_at: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            severity: None,
            tags: vec![],
            metadata: serde_json::Value::Null,
        };
        let recent = make_event(MonitorSource::Cve, "recent");
        store.store_events(&[old, recent]).await.unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let filtered = store.get_events(None, Some(since)).await.unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].title, "recent");
    }

    #[tokio::test]
    async fn in_memory_combined_filter() {
        let store = InMemoryStateStore::new();

        let old_gh = MonitorEvent {
            id: "old-gh".into(),
            source: MonitorSource::GitHub,
            title: "old gh".into(),
            description: String::new(),
            url: String::new(),
            discovered_at: chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            severity: None,
            tags: vec![],
            metadata: serde_json::Value::Null,
        };
        let new_gh = make_event(MonitorSource::GitHub, "new gh");
        let new_cve = make_event(MonitorSource::Cve, "new cve");
        store
            .store_events(&[old_gh, new_gh, new_cve])
            .await
            .unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let result = store
            .get_events(Some(MonitorSource::GitHub), Some(since))
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].title, "new gh");
    }
}
