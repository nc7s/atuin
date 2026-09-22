//! Experimental output-store comparison API, enabled only by `output-store-bench`.
//!
//! All engines use the reference serialization, CRUD operations and wall-clock maintenance.
//! `Store::open` enables Atuin's timers with the production capture budget by default.
//! Synchronous measurement methods block the caller.

use std::path::Path;

use atuin_client::history::{CommandCapture, HistoryId};
use atuin_client::settings::{CaptureLimits, DiskUsageLimit};
use eyre::{Result, ensure};

pub use super::persistence::blob::maintenance::{GC_INTERVAL, MaintenanceStats, SYNC_INTERVAL};
use super::persistence::blob::redb::RedbBackend;
use super::persistence::blob::sqlite::SqliteBackend;
use super::persistence::{BlobStore as _, FjallBlobStore};
use super::{CaptureError, DeleteOutputError, GetOutputError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, derive_more::Display)]
pub enum Engine {
    #[display("fjall")]
    Fjall,
    #[display("redb")]
    Redb,
    #[display("sqlite")]
    Sqlite,
}

impl Engine {
    pub const ALL: [Self; 3] = [Self::Fjall, Self::Redb, Self::Sqlite];
}

enum Backend {
    Fjall(FjallBlobStore),
    Redb(RedbBackend),
    Sqlite(SqliteBackend),
}

pub struct Store {
    backend: Backend,
}

impl Store {
    /// Enable the reference flusher and disk-budget GC policy. Requires a Tokio runtime.
    /// Engine-specific storage estimates mean the same budget can retain different records.
    pub fn open_with_limit(engine: Engine, path: &Path, limit: DiskUsageLimit) -> Result<Self> {
        let backend = match engine {
            Engine::Fjall => {
                Backend::Fjall(FjallBlobStore::open_with_limit_for_benchmark(path, limit)?)
            }
            Engine::Redb => Backend::Redb(RedbBackend::open(path, limit)?),
            Engine::Sqlite => Backend::Sqlite(SqliteBackend::open(path, limit)?),
        };
        Ok(Self { backend })
    }

    /// Enable wall-clock flushing and GC with the default production capture budget.
    /// Requires a Tokio runtime, just like `open_with_limit`.
    pub fn open(engine: Engine, path: &Path) -> Result<Self> {
        Self::open_with_limit(engine, path, CaptureLimits::default().max_disk_usage)
    }

    /// Explicit opt-out for tests that drive durability and retention themselves.
    pub fn open_without_maintenance(engine: Engine, path: &Path) -> Result<Self> {
        let backend = match engine {
            Engine::Fjall => Backend::Fjall(FjallBlobStore::open_for_benchmark(path)?),
            Engine::Redb => Backend::Redb(RedbBackend::open_for_benchmark(path)?),
            Engine::Sqlite => Backend::Sqlite(SqliteBackend::open_for_benchmark(path)?),
        };
        Ok(Self { backend })
    }

    /// Stop timers, await in-flight maintenance I/O, persist, and release the database lock.
    /// Use this before inspecting files or reopening a wall-clock store; Drop only aborts timers.
    /// Return completed timer work, or an error if any maintenance operation failed.
    pub async fn close(mut self) -> Result<MaintenanceStats> {
        let stats = match &mut self.backend {
            Backend::Fjall(store) => store.stop_maintenance().await,
            Backend::Redb(store) => store.stop_maintenance().await,
            Backend::Sqlite(store) => store.stop_maintenance().await,
        };
        tokio::task::spawn_blocking(move || {
            self.persist()?;
            if let Backend::Sqlite(store) = self.backend {
                store.close()?;
            }
            Ok::<_, eyre::Report>(())
        })
        .await
        .expect("store close task panicked")?;
        ensure!(stats.errors == 0, "wall-clock maintenance reported {} errors", stats.errors);
        Ok(stats)
    }

    pub async fn capture(
        &self,
        id: HistoryId,
        capture: CommandCapture,
    ) -> Result<(), CaptureError> {
        match &self.backend {
            Backend::Fjall(store) => store.capture(id, capture).await,
            Backend::Redb(store) => store.capture(id, capture).await,
            Backend::Sqlite(store) => store.capture(id, capture).await,
        }
    }

    pub async fn get(&self, id: HistoryId) -> Result<Option<CommandCapture>, GetOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.get(id).await,
            Backend::Redb(store) => store.get(id).await,
            Backend::Sqlite(store) => store.get(id).await,
        }
    }

    pub async fn remove(&self, ids: Vec<HistoryId>) -> Result<(), DeleteOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.remove(ids.into_iter()).await,
            Backend::Redb(store) => store.remove(ids).await,
            Backend::Sqlite(store) => store.remove(ids).await,
        }
    }

    /// Evict oldest entries by serialized-value bytes, not physical file size.
    pub async fn reclaim(&self, bytes: u64) -> Result<u64, DeleteOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.reclaim_for_benchmark(bytes).await,
            Backend::Redb(store) => store.reclaim(bytes).await,
            Backend::Sqlite(store) => store.reclaim(bytes).await,
        }
    }

    /// Durably commit all preceding operations, without forcing LSM memtables to SSTs.
    pub fn persist(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.persist_for_benchmark(),
            Backend::Redb(store) => store.persist(),
            Backend::Sqlite(store) => store.persist(),
        }
    }

    /// Flush Fjall memtables to SSTs/blob files; the other engines need only persistence.
    pub fn materialize(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.materialize_for_benchmark(),
            Backend::Redb(store) => store.persist(),
            Backend::Sqlite(store) => store.persist(),
        }
    }

    /// Explicit native compaction, not a promise of a globally minimal file layout.
    pub fn compact(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.compact_for_benchmark(),
            Backend::Redb(store) => store.compact(),
            Backend::Sqlite(store) => store.compact(),
        }
    }

    /// Live IDs and serialized-value lengths in bytewise key order.
    pub fn entries(&self) -> Result<Vec<(HistoryId, u64)>> {
        match &self.backend {
            Backend::Fjall(store) => store.entries_for_benchmark(),
            Backend::Redb(store) => store.entries(),
            Backend::Sqlite(store) => store.entries(),
        }
    }
}

/// Size of the exact uncompressed MessagePack payload used by all engines.
pub fn serialized_value_len(capture: CommandCapture) -> Result<u64> {
    use super::persistence::blob::fjall::ActiveSchema;
    use super::persistence::blob::fjall::schema::Schema as _;
    Ok(u64::try_from(ActiveSchema::serialize_value(capture)?.len())?)
}
