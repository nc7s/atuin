//! Measurement hooks only. Normal daemon construction and storage options are unchanged.

use std::path::Path;
use std::sync::Arc;

use atuin_client::history::HistoryId;
use atuin_client::settings::DiskUsageLimit;
use eyre::Result;
use fjall::{OptimisticTxDatabase, PersistMode};

use super::super::maintenance::{MaintainedStore, MaintenanceStats, resolve_budget};
use super::{FjallBlobStore, FjallStorageInner, Maintenance};
use crate::output_capture::DeleteOutputError;

impl FjallBlobStore {
    pub(in crate::output_capture) fn open_with_limit_for_benchmark(
        path: &Path,
        limit: DiskUsageLimit,
    ) -> Result<Self> {
        let mut store = Self::open_for_benchmark(path)?;
        store.maintenance =
            Some(Arc::new(Maintenance::spawn(store.inner.clone(), resolve_budget(path, limit)?)));
        Ok(store)
    }

    pub(in crate::output_capture) fn open_for_benchmark(path: &Path) -> Result<Self> {
        let db = OptimisticTxDatabase::builder(path).open()?;
        Ok(Self {
            inner: Arc::new(FjallStorageInner::new(db)?),
            maintenance: None,
        })
    }

    pub(in crate::output_capture) async fn stop_maintenance(&mut self) -> MaintenanceStats {
        Maintenance::shutdown(self.maintenance.take()).await
    }

    pub(in crate::output_capture) fn persist_for_benchmark(&self) -> Result<()> {
        self.inner.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    pub(in crate::output_capture) fn materialize_for_benchmark(&self) -> Result<()> {
        self.inner.keyspace.inner().rotate_memtable_and_wait()?;
        self.persist_for_benchmark()
    }

    pub(in crate::output_capture) fn compact_for_benchmark(&self) -> Result<()> {
        self.materialize_for_benchmark()?;
        self.inner.keyspace.inner().major_compact()?;
        self.persist_for_benchmark()
    }

    pub(in crate::output_capture) async fn reclaim_for_benchmark(
        &self,
        bytes: u64,
    ) -> Result<u64, DeleteOutputError> {
        self.inner.clone().reclaim_oldest(bytes).await
    }

    pub(in crate::output_capture) fn entries_for_benchmark(&self) -> Result<Vec<(HistoryId, u64)>> {
        self.inner
            .keyspace
            .inner()
            .iter()
            .map(|guard| {
                let (key, value) = guard.into_inner()?;
                Ok((HistoryId::from_bytes(key.as_ref().try_into()?), u64::try_from(value.len())?))
            })
            .collect()
    }
}
