//! Experimental, uncompressed output store for comparison with Fjall.
//!
//! Reuses the reference schema and wall-clock maintenance policy. GC measures live table pages,
//! not reusable free pages or the file's high-water mark. No daemon configuration selects redb.

#![expect(
    clippy::significant_drop_tightening,
    reason = "database guards must outlive redb's owned transactions to exclude compaction"
)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use atuin_client::history::{CommandCapture, HistoryId};
use atuin_client::settings::DiskUsageLimit;
use eyre::Result;
use parking_lot::RwLock;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};

use super::fjall::ActiveSchema;
use super::fjall::schema::Schema as _;
use super::maintenance::{MaintainedStore, Maintenance, resolve_budget};
use super::{CaptureError, DeleteOutputError, GetOutputError, StorageError};

const OUTPUT: TableDefinition<&[u8; 16], &[u8]> = TableDefinition::new(ActiveSchema::NAME);

struct RedbBackendInner {
    /* Every transaction holds a read guard through completion. Compaction's write guard gives
     * redb exclusive mutable access without racing the flusher, GC, or foreground operations. */
    db: RwLock<Database>,
    dirty: AtomicBool,
}

#[derive(Clone)]
pub(in crate::output_capture) struct RedbBackend {
    inner: Arc<RedbBackendInner>,
    maintenance: Option<Arc<Maintenance>>,
}

impl RedbBackend {
    pub(in crate::output_capture) fn open(path: &Path, limit: DiskUsageLimit) -> Result<Self> {
        let mut backend = Self::open_for_benchmark(path)?;
        backend.maintenance =
            Some(Arc::new(Maintenance::spawn(backend.inner.clone(), resolve_budget(path, limit)?)));
        Ok(backend)
    }

    pub(in crate::output_capture) fn open_for_benchmark(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let db = Database::create(path.join("output.redb"))?;
        let tx = db.begin_write()?;
        tx.open_table(OUTPUT)?;
        tx.commit()?;
        Ok(Self {
            inner: Arc::new(RedbBackendInner {
                db: RwLock::new(db),
                dirty: AtomicBool::new(false),
            }),
            maintenance: None,
        })
    }

    pub(in crate::output_capture) async fn stop_maintenance(&mut self) {
        Maintenance::shutdown(self.maintenance.take()).await;
    }

    pub(in crate::output_capture) fn persist(&self) -> Result<()> {
        self.inner.persist().map_err(|error| eyre::eyre!(error))
    }

    pub(in crate::output_capture) fn compact(&self) -> Result<()> {
        self.inner.db.write().compact()?;
        Ok(())
    }

    pub(in crate::output_capture) fn entries(&self) -> Result<Vec<(HistoryId, u64)>> {
        let db = self.inner.db.read();
        let tx = db.begin_read()?;
        let table = tx.open_table(OUTPUT)?;
        table
            .iter()?
            .map(|entry| {
                let (key, value) = entry?;
                Ok((HistoryId::from_bytes(*key.value()), u64::try_from(value.value().len())?))
            })
            .collect()
    }

    /// Evict oldest records until their serialized values total at least `bytes`.
    /// Like Fjall's reclaim, the result is logical bytes removed, not physical bytes freed.
    pub(in crate::output_capture) async fn reclaim(
        &self,
        bytes: u64,
    ) -> Result<u64, DeleteOutputError> {
        self.inner.clone().reclaim_oldest(bytes).await
    }
}

impl MaintainedStore for RedbBackendInner {
    fn dirty(&self) -> &AtomicBool {
        &self.dirty
    }

    fn persist(&self) -> Result<(), StorageError> {
        /* An immediate commit also persists all preceding non-durable commits. */
        let db = self.db.read();
        let mut tx = db.begin_write()?;
        tx.set_durability(Durability::Immediate)?;
        tx.commit()?;
        Ok(())
    }

    fn estimated_disk_space(&self) -> Result<u64, StorageError> {
        let db = self.db.read();
        let tx = db.begin_read()?;
        let stats = tx.open_table(OUTPUT)?.stats()?;
        /* Include live keys, values, indexes and within-page fragmentation. Exclude free pages,
         * obsolete copy-on-write pages and file preallocation: deletion cannot shrink those. */
        Ok(stats
            .stored_bytes()
            .saturating_add(stats.metadata_bytes())
            .saturating_add(stats.fragmented_bytes()))
    }

    async fn reclaim_oldest(self: Arc<Self>, bytes: u64) -> Result<u64, DeleteOutputError> {
        if bytes == 0 {
            return Ok(0);
        }
        tokio::task::spawn_blocking(move || {
            let db = self.db.read();
            let mut tx = db.begin_write().map_err(delete_error)?;
            tx.set_durability(Durability::None).map_err(delete_error)?;
            let mut removed = 0_u64;
            {
                let mut table = tx.open_table(OUTPUT).map_err(delete_error)?;
                while removed < bytes {
                    let Some((_, value)) = table.pop_first().map_err(delete_error)? else {
                        break;
                    };
                    removed = removed
                        .saturating_add(u64::try_from(value.value().len()).unwrap_or(u64::MAX));
                }
            }
            tx.commit().map_err(delete_error)?;
            self.dirty.store(true, Ordering::Release);
            Ok(removed)
        })
        .await
        .expect("output-capture reclaim task panicked")
    }
}

impl RedbBackend {
    pub(in crate::output_capture) async fn capture(
        &self,
        id: HistoryId,
        capture: CommandCapture,
    ) -> Result<(), CaptureError> {
        let key = ActiveSchema::serialize_key(id).expect("history id serialization is infallible");
        let value = ActiveSchema::serialize_value(capture)
            .map_err(|err| CaptureError::Serialize(Box::new(err)))?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let db = inner.db.read();
            let mut tx = db.begin_write().map_err(capture_error)?;
            tx.set_durability(Durability::None).map_err(capture_error)?;
            {
                let mut table = tx.open_table(OUTPUT).map_err(capture_error)?;
                if table.get(&key).map_err(capture_error)?.is_some() {
                    return Err(CaptureError::AlreadyExists);
                }
                table.insert(&key, value.as_slice()).map_err(capture_error)?;
            }
            tx.commit().map_err(capture_error)?;
            inner.dirty.store(true, Ordering::Release);
            Ok(())
        })
        .await
        .expect("output-capture write task panicked")
    }

    pub(in crate::output_capture) async fn get(
        &self,
        id: HistoryId,
    ) -> Result<Option<CommandCapture>, GetOutputError> {
        let key = ActiveSchema::serialize_key(id).expect("history id serialization is infallible");
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let db = inner.db.read();
            let tx = db.begin_read().map_err(get_error)?;
            let table = tx.open_table(OUTPUT).map_err(get_error)?;
            table
                .get(&key)
                .map_err(get_error)?
                .map(|value| {
                    ActiveSchema::deserialize_value(value.value().to_vec()).map_err(get_error)
                })
                .transpose()
        })
        .await
        .expect("output-capture read task panicked")
    }

    pub(in crate::output_capture) async fn remove(
        &self,
        ids: Vec<HistoryId>,
    ) -> Result<(), DeleteOutputError> {
        if ids.is_empty() {
            return Ok(());
        }
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let db = inner.db.read();
            let mut tx = db.begin_write().map_err(delete_error)?;
            tx.set_durability(Durability::None).map_err(delete_error)?;
            {
                let mut table = tx.open_table(OUTPUT).map_err(delete_error)?;
                for id in ids {
                    table.remove(&id.into_bytes()).map_err(delete_error)?;
                }
            }
            tx.commit().map_err(delete_error)?;
            inner.dirty.store(true, Ordering::Release);
            Ok(())
        })
        .await
        .expect("output-capture delete task panicked")
    }
}

fn capture_error(error: impl std::error::Error + Send + Sync + 'static) -> CaptureError {
    CaptureError::Storage(Box::new(error))
}

fn get_error(error: impl std::error::Error + Send + Sync + 'static) -> GetOutputError {
    GetOutputError::Storage(Box::new(error))
}

fn delete_error(error: impl std::error::Error + Send + Sync + 'static) -> DeleteOutputError {
    DeleteOutputError::Storage(Box::new(error))
}

#[cfg(test)]
mod tests {
    use atuin_common::units::{ByteSize, Percent};
    use rstest::{fixture, rstest};
    use tempfile::TempDir;

    use super::*;
    use crate::output_capture::persistence::blob::maintenance::{
        GC_INTERVAL, SYNC_INTERVAL, wait_until,
    };

    #[fixture]
    fn directory() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn id(number: u128) -> HistoryId {
        HistoryId::from_bytes(number.to_be_bytes())
    }

    fn capture() -> CommandCapture {
        CommandCapture {
            output_start: "x".repeat(16 * 1024),
            output_end: None,
            output_observed_bytes: 16 * 1024,
            terminal_width: 120,
            terminal_height: 40,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Mutation {
        Capture,
        Remove,
        Reclaim,
    }

    async fn mutate(store: &RedbBackend, mutation: Mutation) {
        match mutation {
            Mutation::Capture => store.capture(id(2), capture()).await.unwrap(),
            Mutation::Remove => store.remove(vec![id(1)]).await.unwrap(),
            Mutation::Reclaim => {
                store.reclaim(1).await.unwrap();
            }
        }
    }

    #[rstest]
    #[tokio::test(start_paused = true)]
    async fn mutations_are_flushed_on_the_wall_clock(
        directory: TempDir,
        #[values(Mutation::Capture, Mutation::Remove, Mutation::Reclaim)] mutation: Mutation,
    ) {
        let mut store = RedbBackend::open_for_benchmark(directory.path()).unwrap();
        store.capture(id(1), capture()).await.unwrap();
        store.persist().unwrap();
        store.inner.dirty.store(false, Ordering::Relaxed);
        store.maintenance = Some(Arc::new(Maintenance::spawn(store.inner.clone(), None)));
        tokio::task::yield_now().await;
        let writer = store.clone();
        let task = tokio::spawn(async move { mutate(&writer, mutation).await });
        wait_until(|| task.is_finished()).await;
        task.await.unwrap();
        assert!(store.inner.dirty.load(Ordering::Acquire));
        tokio::time::advance(SYNC_INTERVAL).await;
        wait_until(|| !store.inner.dirty.load(Ordering::Acquire)).await;
        store.stop_maintenance().await;
        let expected = store.entries().unwrap();
        drop(store);
        let reopened = RedbBackend::open_for_benchmark(directory.path()).unwrap();
        assert_eq!(reopened.entries().unwrap(), expected);
    }

    #[rstest]
    #[tokio::test]
    async fn undecodable_values_return_a_storage_error(directory: TempDir) {
        let store = RedbBackend::open_for_benchmark(directory.path()).unwrap();
        {
            let db = store.inner.db.read();
            let tx = db.begin_write().unwrap();
            tx.open_table(OUTPUT)
                .unwrap()
                .insert(&id(1).into_bytes(), b"not messagepack".as_slice())
                .unwrap();
            tx.commit().unwrap();
        }
        assert!(matches!(store.get(id(1)).await, Err(GetOutputError::Storage(_))));
    }

    #[rstest]
    #[tokio::test]
    async fn rejected_and_empty_mutations_do_not_mark_dirty(directory: TempDir) {
        let store = RedbBackend::open_for_benchmark(directory.path()).unwrap();
        store.capture(id(1), capture()).await.unwrap();
        store.inner.dirty.store(false, Ordering::Relaxed);
        assert!(matches!(store.capture(id(1), capture()).await, Err(CaptureError::AlreadyExists)));
        store.remove(vec![]).await.unwrap();
        assert_eq!(store.reclaim(0).await.unwrap(), 0);
        assert!(!store.inner.dirty.load(Ordering::Acquire));
    }

    #[rstest]
    #[tokio::test(start_paused = true)]
    async fn gc_trims_oldest_and_ignores_reusable_file_capacity(directory: TempDir) {
        let store = RedbBackend::open_for_benchmark(directory.path()).unwrap();
        for number in (1..=40).rev() {
            store.capture(id(number), capture()).await.unwrap();
        }
        store.persist().unwrap();
        let before = store.entries().unwrap();
        let size = store.inner.estimated_disk_space().unwrap();
        /* Leave enough headroom after one pass to avoid page-rounding effects on the trigger. */
        let budget = ByteSize::b(size);
        drop(store);
        let mut store = RedbBackend::open(directory.path(), DiskUsageLimit::Bytes(budget)).unwrap();
        wait_until(|| store.entries().unwrap().len() < before.len()).await;
        let retained = store.entries().unwrap();
        assert!(!retained.is_empty());
        assert_eq!(retained, before[before.len() - retained.len()..]);
        assert!(store.inner.estimated_disk_space().unwrap() < size * Percent::new(95.0));
        assert!(std::fs::metadata(directory.path().join("output.redb")).unwrap().len() > size);
        tokio::time::advance(GC_INTERVAL).await;
        /* Graceful shutdown drains any tick that has started, including its blocking work. */
        tokio::task::yield_now().await;
        store.stop_maintenance().await;
        assert_eq!(store.entries().unwrap(), retained);
    }

    #[rstest]
    #[tokio::test]
    async fn compaction_is_safe_with_live_maintenance_and_backend_clones(directory: TempDir) {
        let mut store = RedbBackend::open(directory.path(), DiskUsageLimit::Unlimited).unwrap();
        store.capture(id(1), capture()).await.unwrap();
        let clone = store.clone();
        store.compact().unwrap();
        assert_eq!(clone.get(id(1)).await.unwrap(), Some(capture()));
        drop(clone);
        store.stop_maintenance().await;
    }

    #[rstest]
    #[tokio::test]
    async fn dropping_the_last_backend_stops_tasks_and_releases_the_database(directory: TempDir) {
        let store =
            RedbBackend::open(directory.path(), DiskUsageLimit::Bytes(ByteSize::b(1))).unwrap();
        let weak = Arc::downgrade(&store.inner);
        let clone = store.clone();
        drop(store);
        assert!(weak.upgrade().is_some());
        drop(clone);
        wait_until(|| weak.upgrade().is_none()).await;
        RedbBackend::open_for_benchmark(directory.path()).unwrap();
    }
}
