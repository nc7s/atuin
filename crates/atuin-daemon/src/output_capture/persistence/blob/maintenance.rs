//! Shared wall-clock durability and oldest-first disk-budget maintenance.

#[cfg(test)]
mod tests;

use std::future::Future;
#[cfg(any(test, feature = "output-store-bench"))]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

pub(super) const SYNC_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const GC_INTERVAL: Duration = Duration::from_secs(60);
const TRIGGER_SHARE: Percent = Percent::new(95.0);
const TARGET_SHARE: Percent = Percent::new(90.0);

/// Owned only by backend handles, never by the tasks that drive the store.
#[derive(Debug)]
pub(super) struct Maintenance {
    #[cfg_attr(
        not(feature = "output-store-bench"),
        expect(dead_code, reason = "owns timer tasks")
    )]
    tasks: Vec<BackgroundTask>,
}

impl Maintenance {
    pub(super) fn spawn<S: MaintainedStore>(inner: Arc<S>, budget: Option<ByteSize>) -> Self {
        let mut tasks = vec![spawn_flusher(inner.clone())];
        if let Some(budget) = budget {
            tasks.push(spawn_gc(inner, budget));
        }
        Self { tasks }
    }

    /// Wait for in-flight blocking I/O before a benchmark closes or reopens the database.
    #[cfg(feature = "output-store-bench")]
    pub(super) async fn shutdown(maintenance: Option<Arc<Self>>) {
        if let Some(maintenance) = maintenance {
            let maintenance = Arc::try_unwrap(maintenance)
                .expect("cannot shut down maintenance while backend clones exist");
            for mut task in maintenance.tasks {
                drop(task.stop.take());
                task.task
                    .take()
                    .expect("maintenance task")
                    .await
                    .expect("maintenance task panicked");
            }
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

fn spawn_flusher<S: MaintainedStore>(inner: Arc<S>) -> BackgroundTask {
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
            if let Err(err) = tokio::task::spawn_blocking(move || store.persist())
                .await
                .expect("persistence task shouldn't panic")
            {
                tracing::error!(?err, "failed to persist data on disk. will try again...");
                inner.dirty().store(true, Ordering::Relaxed);
            }
        }
    });
    BackgroundTask {
        stop: Some(stop),
        task: Some(task),
    }
}

fn spawn_gc<S: MaintainedStore>(inner: Arc<S>, budget: ByteSize) -> BackgroundTask {
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

            if let Err(err) = collect_garbage(inner.clone(), budget).await {
                tracing::warn!(?err, "output capture gc failed to reclaim entries");
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
) -> Result<(), StorageError> {
    let store = inner.clone();
    let size = tokio::task::spawn_blocking(move || store.estimated_disk_space())
        .await
        .expect("disk-usage task shouldn't panic")?;
    let budget = budget.as_u64();
    if size >= budget * TRIGGER_SHARE {
        inner.reclaim_oldest(size.saturating_sub(budget * TARGET_SHARE)).await?;
    }
    Ok(())
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
