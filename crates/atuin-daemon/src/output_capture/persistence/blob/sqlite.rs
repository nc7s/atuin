//! Experimental SQLite blob store using the reference serialization and maintenance policy.
//!
//! WAL + NORMAL commits provide atomic visibility without syncing every capture. A FULL WAL
//! checkpoint is the explicit durability boundary; VACUUM is reserved for explicit compaction.

#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use atuin_client::history::{CommandCapture, HistoryId};
use atuin_client::settings::DiskUsageLimit;
use atuin_common::db::{query, query_as, query_scalar};
use eyre::Result;
use futures::TryStreamExt as _;
use futures::executor::block_on;
use parking_lot::Mutex;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{Connection as _, SqliteConnection};

use super::fjall::ActiveSchema;
use super::fjall::schema::Schema as _;
use super::maintenance::{MaintainedStore, Maintenance, MaintenanceStats, resolve_budget};
use super::{CaptureError, DeleteOutputError, GetOutputError, StorageError};

struct SqliteBackendInner {
    /* SQLx's SQLite worker runs independently of Tokio. Serializing complete operations here lets
     * the synchronous maintenance hooks drive its futures without blocking an async lock owner.
     * Foreground I/O runs on spawn_blocking, just like the other benchmark backends. */
    connection: Mutex<SqliteConnection>,
    dirty: AtomicBool,
}

#[derive(Clone)]
pub(in crate::output_capture) struct SqliteBackend {
    inner: Arc<SqliteBackendInner>,
    maintenance: Option<Arc<Maintenance>>,
}

impl SqliteBackend {
    pub(in crate::output_capture) fn open(path: &Path, limit: DiskUsageLimit) -> Result<Self> {
        let mut backend = Self::open_for_benchmark(path)?;
        backend.maintenance =
            Some(Arc::new(Maintenance::spawn(backend.inner.clone(), resolve_budget(path, limit)?)));
        Ok(backend)
    }

    pub(in crate::output_capture) fn open_for_benchmark(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let options = SqliteConnectOptions::new()
            .filename(path.join("output.sqlite3"))
            .create_if_missing(true)
            .page_size(4096)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(Duration::from_secs(5))
            .pragma("cache_size", "-8192")
            .pragma("wal_autocheckpoint", "1000")
            .pragma("journal_size_limit", "4194304")
            .pragma("auto_vacuum", "NONE");
        Self::connect(&options)
    }

    fn connect(options: &SqliteConnectOptions) -> Result<Self> {
        let connection = block_on(async {
            let mut connection = SqliteConnection::connect_with(options).await?;
            /* A rowid table keeps large BLOBs in table leaves rather than index-tree cells.
             * The binary UUID primary-key index supplies atomic uniqueness and eviction order. */
            query(
                "CREATE TABLE IF NOT EXISTS output_capture_v2 (
                    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
                    value BLOB NOT NULL
                ) STRICT",
            )
            .execute(&mut connection)
            .await?;
            Ok::<_, sqlx::Error>(connection)
        })?;
        Ok(Self {
            inner: Arc::new(SqliteBackendInner {
                connection: Mutex::new(connection),
                dirty: AtomicBool::new(false),
            }),
            maintenance: None,
        })
    }

    pub(in crate::output_capture) async fn stop_maintenance(&mut self) -> MaintenanceStats {
        Maintenance::shutdown(self.maintenance.take()).await
    }

    /// Join SQLx's worker before the caller inspects files or reopens the store.
    pub(in crate::output_capture) fn close(self) -> Result<()> {
        let inner = Arc::try_unwrap(self.inner)
            .map_err(|_| eyre::eyre!("cannot close SQLite while backend clones exist"))?;
        block_on(inner.connection.into_inner().close())?;
        Ok(())
    }

    pub(in crate::output_capture) fn persist(&self) -> Result<()> {
        self.inner.persist().map_err(|error| eyre::eyre!(error))
    }

    pub(in crate::output_capture) fn compact(&self) -> Result<()> {
        let mut connection = self.inner.connection.lock();
        block_on(async {
            checkpoint(&mut connection).await?;
            query("VACUUM").execute(&mut *connection).await?;
            checkpoint(&mut connection).await
        })
        .map_err(|error| eyre::eyre!(error))
    }

    pub(in crate::output_capture) fn entries(&self) -> Result<Vec<(HistoryId, u64)>> {
        let mut connection = self.inner.connection.lock();
        let rows: Vec<(Vec<u8>, i64)> = block_on(
            query_as("SELECT id, length(value) FROM output_capture_v2 ORDER BY id")
                .fetch_all(&mut *connection),
        )?;
        drop(connection);
        rows.into_iter()
            .map(|(key, bytes)| Ok((ActiveSchema::deserialize_key(&key)?, u64::try_from(bytes)?)))
            .collect()
    }

    pub(in crate::output_capture) async fn reclaim(
        &self,
        bytes: u64,
    ) -> Result<u64, DeleteOutputError> {
        self.inner.clone().reclaim_oldest(bytes).await
    }

    pub(in crate::output_capture) async fn capture(
        &self,
        id: HistoryId,
        capture: CommandCapture,
    ) -> Result<(), CaptureError> {
        let value = ActiveSchema::serialize_value(capture)
            .map_err(|error| CaptureError::Serialize(Box::new(error)))?;
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = inner.connection.lock();
            let result = block_on(
                query("INSERT INTO output_capture_v2 (id, value) VALUES (?, ?) ON CONFLICT(id) DO NOTHING")
                    .bind(id.into_bytes().as_slice())
                    .bind(value)
                    .execute(&mut *connection),
            )
            .map_err(|error| CaptureError::Storage(Box::new(error)))?;
            if result.rows_affected() == 0 {
                return Err(CaptureError::AlreadyExists);
            }
            inner.dirty.store(true, Ordering::Release);
            drop(connection);
            Ok(())
        })
        .await
        .expect("output-capture write task panicked")
    }

    pub(in crate::output_capture) async fn get(
        &self,
        id: HistoryId,
    ) -> Result<Option<CommandCapture>, GetOutputError> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = inner.connection.lock();
            let value: Option<Vec<u8>> = block_on(
                query_scalar("SELECT value FROM output_capture_v2 WHERE id = ?")
                    .bind(id.into_bytes().as_slice())
                    .fetch_optional(&mut *connection),
            )
            .map_err(|error| GetOutputError::Storage(Box::new(error)))?;
            drop(connection);
            value
                .map(|value| {
                    ActiveSchema::deserialize_value(value)
                        .map_err(|error| GetOutputError::Storage(Box::new(error)))
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
            let mut connection = inner.connection.lock();
            let removed = block_on(async {
                let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
                let mut removed = 0;
                for id in ids {
                    removed += query("DELETE FROM output_capture_v2 WHERE id = ?")
                        .bind(id.into_bytes().as_slice())
                        .execute(&mut *tx)
                        .await?
                        .rows_affected();
                }
                tx.commit().await?;
                Ok::<_, sqlx::Error>(removed)
            })
            .map_err(delete_error)?;
            if removed > 0 {
                inner.dirty.store(true, Ordering::Release);
            }
            Ok(())
        })
        .await
        .expect("output-capture delete task panicked")
    }
}

impl MaintainedStore for SqliteBackendInner {
    fn dirty(&self) -> &AtomicBool {
        &self.dirty
    }

    fn persist(&self) -> Result<(), StorageError> {
        block_on(checkpoint(&mut self.connection.lock()))
    }

    fn estimated_disk_space(&self) -> Result<u64, StorageError> {
        let mut connection = self.connection.lock();
        block_on(async {
            /* Exclude reusable free pages and WAL copies. File length would keep evicting live
             * records to address space that deletion already made available for reuse. */
            let (pages, free, size): (i64, i64, i64) = query_as(
                "SELECT page_count, freelist_count, page_size
                 FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()",
            )
            .fetch_one(&mut *connection)
            .await?;
            Ok(u64::try_from(pages - free)? * u64::try_from(size)?)
        })
    }

    async fn reclaim_oldest(self: Arc<Self>, bytes: u64) -> Result<u64, DeleteOutputError> {
        if bytes == 0 {
            return Ok(0);
        }
        tokio::task::spawn_blocking(move || {
            let mut connection = self.connection.lock();
            block_on(async {
                let mut tx =
                    connection.begin_with("BEGIN IMMEDIATE").await.map_err(delete_error)?;
                let mut rows = query_as::<_, (Vec<u8>, i64)>(
                    "SELECT id, length(value) FROM output_capture_v2 ORDER BY id",
                )
                .fetch(&mut *tx);
                let mut boundary = None;
                let mut removed = 0_u64;
                while let Some((key, length)) = rows.try_next().await.map_err(delete_error)? {
                    removed = removed.saturating_add(u64::try_from(length).map_err(delete_error)?);
                    boundary = Some(key);
                    if removed >= bytes {
                        break;
                    }
                }
                drop(rows);
                let has_victims = boundary.is_some();
                if let Some(key) = boundary {
                    query("DELETE FROM output_capture_v2 WHERE id <= ?")
                        .bind(key)
                        .execute(&mut *tx)
                        .await
                        .map_err(delete_error)?;
                }
                tx.commit().await.map_err(delete_error)?;
                if has_victims {
                    self.dirty.store(true, Ordering::Release);
                }
                Ok(removed)
            })
        })
        .await
        .expect("output-capture reclaim task panicked")
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "SQLite checkpoint incomplete: busy={busy}, WAL frames={frames}, checkpointed={checkpointed}"
)]
struct IncompleteCheckpoint {
    busy: i64,
    frames: i64,
    checkpointed: i64,
}

async fn checkpoint(connection: &mut SqliteConnection) -> Result<(), StorageError> {
    /* NORMAL-mode checkpoints sync the WAL before copying frames, then sync the database.
     * A busy/partial checkpoint is not a successful durability boundary: the flusher must retry. */
    let (busy, frames, checkpointed): (i64, i64, i64) =
        query_as("PRAGMA wal_checkpoint(FULL)").fetch_one(connection).await?;
    if busy != 0 || frames != checkpointed {
        return Err(Box::new(IncompleteCheckpoint {
            busy,
            frames,
            checkpointed,
        }));
    }
    Ok(())
}

fn delete_error(error: impl std::error::Error + Send + Sync + 'static) -> DeleteOutputError {
    DeleteOutputError::Storage(Box::new(error))
}
