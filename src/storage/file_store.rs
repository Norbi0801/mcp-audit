use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::Result;
use crate::monitors::{MonitorEvent, MonitorSource};

use super::StateStore;

/// File name for the checkpoint map.
const CHECKPOINTS_FILE: &str = "checkpoints.json";

/// Subdirectory for date-partitioned event files.
const EVENTS_DIR: &str = "events";

/// Persisted map of monitor name to last-polled timestamp.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CheckpointMap(HashMap<String, DateTime<Utc>>);

/// File-based state store that persists checkpoints and events as JSON files.
///
/// Layout on disk:
/// ```text
/// {state_dir}/
///   checkpoints.json        — { "github": "2026-03-20T...", ... }
///   events/
///     2026-03-20.json       — [ MonitorEvent, ... ]
///     2026-03-21.json
/// ```
///
/// All writes are atomic: data is serialized to a `.tmp` sibling and then
/// renamed into place, so a crash mid-write never corrupts the file.
///
/// Thread safety is provided by a [`tokio::sync::RwLock`] — multiple readers
/// can proceed concurrently, but writers acquire exclusive access.
pub struct FileStateStore {
    state_dir: PathBuf,
    lock: RwLock<()>,
}

impl std::fmt::Debug for FileStateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileStateStore")
            .field("state_dir", &self.state_dir)
            .finish()
    }
}

impl FileStateStore {
    /// Create a new file-based state store rooted at `state_dir`.
    ///
    /// The directory (and the `events/` subdirectory) will be created if they
    /// do not already exist.
    pub fn new(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir.join(EVENTS_DIR))?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            lock: RwLock::new(()),
        })
    }

    // ── Path helpers ─────────────────────────────────────────────────

    fn checkpoints_path(&self) -> PathBuf {
        self.state_dir.join(CHECKPOINTS_FILE)
    }

    fn events_dir(&self) -> PathBuf {
        self.state_dir.join(EVENTS_DIR)
    }

    fn events_path_for_date(&self, date: &str) -> PathBuf {
        self.events_dir().join(format!("{date}.json"))
    }

    // ── Low-level I/O (call only while holding the lock) ─────────────

    fn read_checkpoints(&self) -> Result<CheckpointMap> {
        let path = self.checkpoints_path();
        if !path.exists() {
            return Ok(CheckpointMap::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let map: CheckpointMap = serde_json::from_str(&data)?;
        Ok(map)
    }

    fn write_checkpoints(&self, map: &CheckpointMap) -> Result<()> {
        atomic_write_json(&self.checkpoints_path(), map)
    }

    fn read_events_file(&self, date: &str) -> Result<Vec<MonitorEvent>> {
        let path = self.events_path_for_date(date);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&path)?;
        let events: Vec<MonitorEvent> = serde_json::from_str(&data)?;
        Ok(events)
    }

    fn write_events_file(&self, date: &str, events: &[MonitorEvent]) -> Result<()> {
        atomic_write_json(&self.events_path_for_date(date), events)
    }

    /// List all event date files in the events directory (YYYY-MM-DD).
    fn list_event_dates(&self) -> Result<Vec<String>> {
        let dir = self.events_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut dates = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(date) = name.strip_suffix(".json") {
                dates.push(date.to_owned());
            }
        }
        dates.sort();
        Ok(dates)
    }
}

impl StateStore for FileStateStore {
    fn get_checkpoint(
        &self,
        monitor: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<DateTime<Utc>>>> + Send + '_>> {
        let monitor = monitor.to_owned();
        Box::pin(async move {
            let _guard = self.lock.read().await;
            let map = self.read_checkpoints()?;
            Ok(map.0.get(&monitor).copied())
        })
    }

    fn set_checkpoint(
        &self,
        monitor: &str,
        ts: DateTime<Utc>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let monitor = monitor.to_owned();
        Box::pin(async move {
            let _guard = self.lock.write().await;
            let mut map = self.read_checkpoints()?;
            map.0.insert(monitor, ts);
            self.write_checkpoints(&map)?;
            Ok(())
        })
    }

    fn store_events(
        &self,
        events: &[MonitorEvent],
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let events = events.to_vec();
        Box::pin(async move {
            if events.is_empty() {
                return Ok(());
            }

            let _guard = self.lock.write().await;

            // Group incoming events by date.
            let mut by_date: HashMap<String, Vec<MonitorEvent>> = HashMap::new();
            for event in events {
                let date = format!(
                    "{:04}-{:02}-{:02}",
                    event.discovered_at.year(),
                    event.discovered_at.month(),
                    event.discovered_at.day(),
                );
                by_date.entry(date).or_default().push(event);
            }

            // For each date, load existing events, merge, and write back.
            for (date, new_events) in &by_date {
                let mut existing = self.read_events_file(date)?;
                existing.extend(new_events.iter().cloned());
                self.write_events_file(date, &existing)?;
            }

            Ok(())
        })
    }

    fn get_events(
        &self,
        source: Option<MonitorSource>,
        since: Option<DateTime<Utc>>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<MonitorEvent>>> + Send + '_>> {
        Box::pin(async move {
            let _guard = self.lock.read().await;

            let dates = self.list_event_dates()?;

            // If we have a `since` filter we can skip date files that are
            // strictly before the since date.
            let since_date_str =
                since.map(|ts| format!("{:04}-{:02}-{:02}", ts.year(), ts.month(), ts.day()));

            let mut result = Vec::new();

            for date in &dates {
                // Quick date-level pruning: skip entire files that are before
                // the since date.
                if let Some(ref cutoff) = since_date_str {
                    if date.as_str() < cutoff.as_str() {
                        continue;
                    }
                }

                let events = self.read_events_file(date)?;
                for event in events {
                    if let Some(src) = source {
                        if event.source != src {
                            continue;
                        }
                    }
                    if let Some(ts) = since {
                        if event.discovered_at < ts {
                            continue;
                        }
                    }
                    result.push(event);
                }
            }

            Ok(result)
        })
    }
}

/// Serialize `value` as pretty-printed JSON and write it atomically to `path`.
///
/// Writes to a `.tmp` file first and then renames, so a crash during the write
/// will never leave a half-written target file.
fn atomic_write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<()> {
    let tmp_path = path.with_extension("json.tmp");
    let data = serde_json::to_string_pretty(value).map_err(crate::error::McpScannerError::Parse)?;
    std::fs::write(&tmp_path, data.as_bytes())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitors::Severity;
    use tempfile::TempDir;

    fn make_event(source: MonitorSource, title: &str) -> MonitorEvent {
        MonitorEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source,
            title: title.to_owned(),
            description: "test".into(),
            url: "https://example.com".into(),
            discovered_at: Utc::now(),
            severity: Some(Severity::Medium),
            tags: vec!["test".into()],
            metadata: serde_json::json!({}),
        }
    }

    fn make_event_at(source: MonitorSource, title: &str, ts: &str) -> MonitorEvent {
        let dt = chrono::DateTime::parse_from_rfc3339(ts)
            .unwrap()
            .with_timezone(&Utc);
        MonitorEvent {
            id: uuid::Uuid::new_v4().to_string(),
            source,
            title: title.to_owned(),
            description: "test".into(),
            url: "https://example.com".into(),
            discovered_at: dt,
            severity: Some(Severity::Low),
            tags: vec![],
            metadata: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn checkpoint_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();
        let now = Utc::now();

        assert!(store.get_checkpoint("gh").await.unwrap().is_none());

        store.set_checkpoint("gh", now).await.unwrap();
        let got = store.get_checkpoint("gh").await.unwrap();
        assert_eq!(got, Some(now));
    }

    #[tokio::test]
    async fn checkpoint_persists_across_instances() {
        let tmp = TempDir::new().unwrap();
        let now = Utc::now();

        {
            let store = FileStateStore::new(tmp.path()).unwrap();
            store.set_checkpoint("cve", now).await.unwrap();
        }

        // New instance, same directory.
        let store2 = FileStateStore::new(tmp.path()).unwrap();
        assert_eq!(store2.get_checkpoint("cve").await.unwrap(), Some(now));
    }

    #[tokio::test]
    async fn checkpoint_overwrite() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        let t1 = chrono::DateTime::parse_from_rfc3339("2025-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let t2 = chrono::DateTime::parse_from_rfc3339("2026-03-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        store.set_checkpoint("gh", t1).await.unwrap();
        store.set_checkpoint("gh", t2).await.unwrap();
        assert_eq!(store.get_checkpoint("gh").await.unwrap(), Some(t2));
    }

    #[tokio::test]
    async fn store_and_retrieve_events() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        let e1 = make_event(MonitorSource::GitHub, "gh event");
        let e2 = make_event(MonitorSource::Cve, "cve event");
        store.store_events(&[e1.clone(), e2.clone()]).await.unwrap();

        let all = store.get_events(None, None).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn filter_events_by_source() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        let e1 = make_event(MonitorSource::GitHub, "gh");
        let e2 = make_event(MonitorSource::Cve, "cve");
        let e3 = make_event(MonitorSource::GitHub, "gh2");
        store.store_events(&[e1, e2, e3]).await.unwrap();

        let gh = store
            .get_events(Some(MonitorSource::GitHub), None)
            .await
            .unwrap();
        assert_eq!(gh.len(), 2);

        let cve = store
            .get_events(Some(MonitorSource::Cve), None)
            .await
            .unwrap();
        assert_eq!(cve.len(), 1);
    }

    #[tokio::test]
    async fn filter_events_by_since() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        let old = make_event_at(MonitorSource::Cve, "old", "2025-01-15T10:00:00Z");
        let recent = make_event_at(MonitorSource::Cve, "recent", "2026-03-20T12:00:00Z");
        store.store_events(&[old, recent]).await.unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let filtered = store.get_events(None, Some(since)).await.unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].title, "recent");
    }

    #[tokio::test]
    async fn events_grouped_by_date() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        let e1 = make_event_at(MonitorSource::GitHub, "day1", "2026-03-20T08:00:00Z");
        let e2 = make_event_at(MonitorSource::GitHub, "day2", "2026-03-21T09:00:00Z");
        store.store_events(&[e1, e2]).await.unwrap();

        // Verify two separate date files exist.
        let dates = store.list_event_dates().unwrap();
        assert_eq!(dates.len(), 2);
        assert!(dates.contains(&"2026-03-20".to_string()));
        assert!(dates.contains(&"2026-03-21".to_string()));
    }

    #[tokio::test]
    async fn store_empty_events_is_noop() {
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        store.store_events(&[]).await.unwrap();

        let dates = store.list_event_dates().unwrap();
        assert!(dates.is_empty());
    }

    #[tokio::test]
    async fn events_persist_across_instances() {
        let tmp = TempDir::new().unwrap();

        {
            let store = FileStateStore::new(tmp.path()).unwrap();
            let e = make_event(MonitorSource::Owasp, "owasp finding");
            store.store_events(&[e]).await.unwrap();
        }

        let store2 = FileStateStore::new(tmp.path()).unwrap();
        let all = store2.get_events(None, None).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].title, "owasp finding");
    }

    #[tokio::test]
    async fn atomic_write_no_corruption() {
        // Verify that the .tmp extension is used — the target file should exist
        // but the .tmp should not after a successful write.
        let tmp = TempDir::new().unwrap();
        let store = FileStateStore::new(tmp.path()).unwrap();

        store.set_checkpoint("test", Utc::now()).await.unwrap();

        let checkpoint_path = tmp.path().join("checkpoints.json");
        let tmp_path = tmp.path().join("checkpoints.json.tmp");
        assert!(checkpoint_path.exists());
        assert!(!tmp_path.exists());
    }
}
