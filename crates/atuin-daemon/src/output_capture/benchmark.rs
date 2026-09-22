//! Experimental output-store comparison API, enabled only by `output-store-bench`.
//!
//! Both engines use the reference serialization, CRUD operations and wall-clock maintenance.
//! `Store::open` disables Atuin's timers for reproducible, caller-driven simulations;
//! engine-internal maintenance remains enabled. Synchronous measurement methods block the caller.

use std::path::Path;

use atuin_client::history::{CommandCapture, HistoryId};
use atuin_client::settings::DiskUsageLimit;
use eyre::Result;

use super::persistence::blob::redb::RedbBackend;
use super::persistence::{BlobStore as _, FjallBlobStore};
use super::{CaptureError, DeleteOutputError, GetOutputError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, derive_more::Display)]
pub enum Engine {
    #[display("fjall")]
    Fjall,
    #[display("redb")]
    Redb,
}

enum Backend {
    Fjall(FjallBlobStore),
    Redb(RedbBackend),
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
        };
        Ok(Self { backend })
    }

    /// Disable Atuin's timers so the caller can drive durability and retention explicitly.
    pub fn open(engine: Engine, path: &Path) -> Result<Self> {
        let backend = match engine {
            Engine::Fjall => Backend::Fjall(FjallBlobStore::open_for_benchmark(path)?),
            Engine::Redb => Backend::Redb(RedbBackend::open_for_benchmark(path)?),
        };
        Ok(Self { backend })
    }

    /// Stop timers, await in-flight maintenance I/O, persist, and release the database lock.
    /// Use this before inspecting files or reopening a wall-clock store; Drop only aborts timers.
    pub async fn close(mut self) -> Result<()> {
        match &mut self.backend {
            Backend::Fjall(store) => store.stop_maintenance().await,
            Backend::Redb(store) => store.stop_maintenance().await,
        }
        tokio::task::spawn_blocking(move || self.persist())
            .await
            .expect("store close task panicked")
    }

    pub async fn capture(
        &self,
        id: HistoryId,
        capture: CommandCapture,
    ) -> Result<(), CaptureError> {
        match &self.backend {
            Backend::Fjall(store) => store.capture(id, capture).await,
            Backend::Redb(store) => store.capture(id, capture).await,
        }
    }

    pub async fn get(&self, id: HistoryId) -> Result<Option<CommandCapture>, GetOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.get(id).await,
            Backend::Redb(store) => store.get(id).await,
        }
    }

    pub async fn remove(&self, ids: Vec<HistoryId>) -> Result<(), DeleteOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.remove(ids.into_iter()).await,
            Backend::Redb(store) => store.remove(ids).await,
        }
    }

    /// Evict oldest entries by serialized-value bytes, not physical file size.
    pub async fn reclaim(&self, bytes: u64) -> Result<u64, DeleteOutputError> {
        match &self.backend {
            Backend::Fjall(store) => store.reclaim_for_benchmark(bytes).await,
            Backend::Redb(store) => store.reclaim(bytes).await,
        }
    }

    /// Durably commit all preceding operations, without forcing LSM memtables to SSTs.
    pub fn persist(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.persist_for_benchmark(),
            Backend::Redb(store) => store.persist(),
        }
    }

    /// Flush Fjall memtables to SSTs/blob files; redb has no corresponding extra layer.
    pub fn materialize(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.materialize_for_benchmark(),
            Backend::Redb(store) => store.persist(),
        }
    }

    /// Explicit native compaction, not a promise of a globally minimal file layout.
    pub fn compact(&self) -> Result<()> {
        match &self.backend {
            Backend::Fjall(store) => store.compact_for_benchmark(),
            Backend::Redb(store) => store.compact(),
        }
    }

    /// Live IDs and serialized-value lengths in bytewise key order.
    pub fn entries(&self) -> Result<Vec<(HistoryId, u64)>> {
        match &self.backend {
            Backend::Fjall(store) => store.entries_for_benchmark(),
            Backend::Redb(store) => store.entries(),
        }
    }
}

/// Size of the exact uncompressed MessagePack payload used by both engines.
pub fn serialized_value_len(capture: CommandCapture) -> Result<u64> {
    use super::persistence::blob::fjall::ActiveSchema;
    use super::persistence::blob::fjall::schema::Schema as _;
    Ok(u64::try_from(ActiveSchema::serialize_value(capture)?.len())?)
}
