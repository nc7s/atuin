//! Shared wall-clock durability and oldest-first disk-budget maintenance.

#[cfg(test)]
mod tests;

use std::future::Future;
#[cfg(any(test, feature = "output-store-bench"))]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

#[cfg(any(test, feature = "output-store-bench"))]
use atuin_client::settings::DiskUsageLimit;
use atuin_common::units::{ByteSize, Percent};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use super::{DeleteOutputError, StorageError};

pub(super) trait MaintainedStore: Send + Sync + 'static {
    fn dirty(&self) -> &AtomicBool;
    fn persist(&self) -> Result<(), StorageError>;
    fn estimated_disk_space(&self) -> Result<u64, StorageError>;
    fn reclaim_oldest(
        self: Arc<Self>,
        bytes: u64,
    ) -> impl Future<Output = Result<u64, DeleteOutputError>> + Send;
}

pub const SYNC_INTERVAL: Duration = Duration::from_secs(5);
pub const GC_INTERVAL: Duration = Duration::from_secs(60);
const TRIGGER_SHARE: Percent = Percent::new(95.0);
const TARGET_SHARE: Percent = Percent::new(90.0);

/// Completed wall-clock work since the store was opened; excludes caller-driven persistence.
#[cfg(feature = "output-store-bench")]
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MaintenanceStats {
    pub flushes: u64,
    pub gc_checks: u64,
    pub gc_reclaimed_bytes: u64,
    pub errors: u64,
}

#[derive(Debug, Default)]
struct MaintenanceCounters {
    flushes: AtomicU64,
    gc_checks: AtomicU64,
    gc_reclaimed_bytes: AtomicU64,
    errors: AtomicU64,
}

/// Owned only by backend handles, never by the tasks that drive the store.
#[derive(Debug)]
pub(super) struct Maintenance {
    #[cfg_attr(
        not(feature = "output-store-bench"),
        expect(dead_code, reason = "owns timer tasks")
    )]
    tasks: Vec<BackgroundTask>,
    #[cfg(feature = "output-store-bench")]
    counters: Arc<MaintenanceCounters>,
}

impl Maintenance {
    pub(super) fn spawn<S: MaintainedStore>(inner: Arc<S>, budget: Option<ByteSize>) -> Self {
        let counters = Arc::new(MaintenanceCounters::default());
        let mut tasks = vec![spawn_flusher(inner.clone(), counters.clone())];
        if let Some(budget) = budget {
            tasks.push(spawn_gc(inner, budget, counters.clone()));
        }
        Self {
            tasks,
            #[cfg(feature = "output-store-bench")]
            counters,
        }
    }

    /// Wait for in-flight blocking I/O before a benchmark closes or reopens the database.
    #[cfg(feature = "output-store-bench")]
    pub(super) async fn shutdown(maintenance: Option<Arc<Self>>) -> MaintenanceStats {
        let Some(maintenance) = maintenance else {
            return MaintenanceStats::default();
        };
        let maintenance = Arc::try_unwrap(maintenance)
            .expect("cannot shut down maintenance while backend clones exist");
        for mut task in maintenance.tasks {
            drop(task.stop.take());
            task.task.take().expect("maintenance task").await.expect("maintenance task panicked");
        }
        let counters = maintenance.counters;
        MaintenanceStats {
            flushes: counters.flushes.load(Ordering::Relaxed),
            gc_checks: counters.gc_checks.load(Ordering::Relaxed),
            gc_reclaimed_bytes: counters.gc_reclaimed_bytes.load(Ordering::Relaxed),
            errors: counters.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug)]
struct BackgroundTask {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for BackgroundTask {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn spawn_flusher<S: MaintainedStore>(
    inner: Arc<S>,
    counters: Arc<MaintenanceCounters>,
) -> BackgroundTask {
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(SYNC_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => break,
                _ = interval.tick() => {}
            }

            /* Acquire pairs with mutations' Release stores. Clear before persisting so a concurrent
             * mutation remains dirty for the next tick, without relying on engine-internal locks. */
            if !inner.dirty().swap(false, Ordering::Acquire) {
                continue;
            }
            let store = inner.clone();
            match tokio::task::spawn_blocking(move || store.persist())
                .await
                .expect("persistence task shouldn't panic")
            {
                Ok(()) => {
                    counters.flushes.fetch_add(1, Ordering::Relaxed);
                }
                Err(err) => {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(?err, "failed to persist data on disk. will try again...");
                    inner.dirty().store(true, Ordering::Relaxed);
                }
            }
        }
    });
    BackgroundTask {
        stop: Some(stop),
        task: Some(task),
    }
}

fn spawn_gc<S: MaintainedStore>(
    inner: Arc<S>,
    budget: ByteSize,
    counters: Arc<MaintenanceCounters>,
) -> BackgroundTask {
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(GC_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => break,
                _ = interval.tick() => {}
            }

            match collect_garbage(inner.clone(), budget).await {
                Ok(bytes) => {
                    counters.gc_checks.fetch_add(1, Ordering::Relaxed);
                    counters.gc_reclaimed_bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                Err(err) => {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(?err, "output capture gc failed to reclaim entries");
                }
            }
        }
    });
    BackgroundTask {
        stop: Some(stop),
        task: Some(task),
    }
}

async fn collect_garbage<S: MaintainedStore>(
    inner: Arc<S>,
    budget: ByteSize,
) -> Result<u64, StorageError> {
    let store = inner.clone();
    let size = tokio::task::spawn_blocking(move || store.estimated_disk_space())
        .await
        .expect("disk-usage task shouldn't panic")?;
    let budget = budget.as_u64();
    if size >= budget * TRIGGER_SHARE {
        return Ok(inner.reclaim_oldest(size.saturating_sub(budget * TARGET_SHARE)).await?);
    }
    Ok(0)
}

#[cfg(test)]
pub(super) async fn wait_until(mut condition: impl FnMut() -> bool) {
    /* Yield without sleeping: paused Tokio time must not auto-advance while blocking I/O runs. */
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "background maintenance did not finish");
        tokio::task::yield_now().await;
    }
}

/// Only percentages inspect the filesystem; unlimited usage starts no garbage collector.
#[cfg(any(test, feature = "output-store-bench"))]
pub(super) fn resolve_budget(
    path: &Path,
    limit: DiskUsageLimit,
) -> std::io::Result<Option<ByteSize>> {
    limit.resolve_for_path(path)
}
