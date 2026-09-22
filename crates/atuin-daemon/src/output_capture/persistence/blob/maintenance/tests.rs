use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::mpsc;

use parking_lot::Mutex;
use rstest::{fixture, rstest};

use super::*;

#[derive(Default)]
struct TestStore {
    dirty: AtomicBool,
    persists: AtomicUsize,
    persist_gate: Mutex<Option<mpsc::Receiver<()>>>,
    measurements: AtomicUsize,
    size: AtomicU64,
    reclaimed: AtomicU64,
    should_fail_persist: AtomicBool,
    should_redirty: AtomicBool,
    should_fail_measurement: AtomicBool,
}

impl MaintainedStore for TestStore {
    fn dirty(&self) -> &AtomicBool {
        &self.dirty
    }

    fn persist(&self) -> Result<(), StorageError> {
        if self.should_redirty.swap(false, Ordering::Relaxed) {
            self.dirty.store(true, Ordering::Release);
        }
        self.persists.fetch_add(1, Ordering::Relaxed);
        let gate = self.persist_gate.lock().take();
        if let Some(gate) = gate {
            gate.recv().unwrap();
        }
        if self.should_fail_persist.swap(false, Ordering::Relaxed) {
            return Err(std::io::Error::other("injected persistence failure").into());
        }
        Ok(())
    }

    fn estimated_disk_space(&self) -> Result<u64, StorageError> {
        let result = if self.should_fail_measurement.load(Ordering::Relaxed) {
            Err(std::io::Error::other("injected disk-usage failure").into())
        } else {
            Ok(self.size.load(Ordering::Relaxed))
        };
        self.measurements.fetch_add(1, Ordering::Relaxed);
        result
    }

    async fn reclaim_oldest(self: Arc<Self>, bytes: u64) -> Result<u64, DeleteOutputError> {
        self.reclaimed.fetch_add(bytes, Ordering::Relaxed);
        Ok(bytes)
    }
}

#[fixture]
fn store() -> Arc<TestStore> {
    Arc::new(TestStore::default())
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn flusher_only_persists_dirty_stores_every_five_seconds(store: Arc<TestStore>) {
    let _maintenance = Maintenance::spawn(store.clone(), None);
    tokio::task::yield_now().await;
    assert_eq!(store.persists.load(Ordering::Relaxed), 0);
    store.dirty.store(true, Ordering::Release);
    tokio::time::advance(SYNC_INTERVAL - Duration::from_secs(1)).await;
    assert_eq!(store.persists.load(Ordering::Relaxed), 0);
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_until(|| store.persists.load(Ordering::Relaxed) == 1).await;
    assert!(!store.dirty.load(Ordering::Acquire));
    tokio::time::advance(SYNC_INTERVAL).await;
    tokio::task::yield_now().await;
    assert_eq!(store.persists.load(Ordering::Relaxed), 1);
}

#[rstest]
#[case::failure(true, false)]
#[case::concurrent_mutation(false, true)]
#[tokio::test(start_paused = true)]
async fn flusher_retries_failures_and_preserves_concurrent_mutations(
    store: Arc<TestStore>,
    #[case] should_fail: bool,
    #[case] should_redirty: bool,
) {
    store.dirty.store(true, Ordering::Release);
    store.should_fail_persist.store(should_fail, Ordering::Relaxed);
    store.should_redirty.store(should_redirty, Ordering::Relaxed);
    let _maintenance = Maintenance::spawn(store.clone(), None);
    wait_until(|| {
        store.persists.load(Ordering::Relaxed) == 1 && store.dirty.load(Ordering::Acquire)
    })
    .await;
    tokio::time::advance(SYNC_INTERVAL).await;
    wait_until(|| store.persists.load(Ordering::Relaxed) == 2).await;
    assert!(!store.dirty.load(Ordering::Acquire));
}

#[rstest]
#[case::below_trigger(949, 1000, 0)]
#[case::at_trigger(950, 1000, 50)]
#[case::at_budget(1000, 1000, 100)]
#[case::over_budget(1200, 1000, 300)]
#[case::zero_budget(100, 0, 100)]
#[case::empty(0, 0, 0)]
#[tokio::test]
async fn gc_uses_reference_trigger_and_target(
    store: Arc<TestStore>,
    #[case] size: u64,
    #[case] budget: u64,
    #[case] expected: u64,
) {
    store.size.store(size, Ordering::Relaxed);
    collect_garbage(store.clone(), ByteSize::b(budget)).await.unwrap();
    assert_eq!(store.reclaimed.load(Ordering::Relaxed), expected);
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn gc_ticks_immediately_then_every_minute_and_retries_errors(store: Arc<TestStore>) {
    store.size.store(1000, Ordering::Relaxed);
    store.should_fail_measurement.store(true, Ordering::Relaxed);
    let _maintenance = Maintenance::spawn(store.clone(), Some(ByteSize::b(1000)));
    wait_until(|| store.measurements.load(Ordering::Relaxed) == 1).await;
    assert_eq!(store.reclaimed.load(Ordering::Relaxed), 0);
    store.should_fail_measurement.store(false, Ordering::Relaxed);
    tokio::time::advance(GC_INTERVAL - Duration::from_secs(1)).await;
    assert_eq!(store.measurements.load(Ordering::Relaxed), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    wait_until(|| store.reclaimed.load(Ordering::Relaxed) == 100).await;
    assert_eq!(store.measurements.load(Ordering::Relaxed), 2);
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn unlimited_budget_never_measures_or_collects(store: Arc<TestStore>) {
    store.size.store(u64::MAX, Ordering::Relaxed);
    let _maintenance = Maintenance::spawn(store.clone(), None);
    tokio::task::yield_now().await;
    tokio::time::advance(GC_INTERVAL * 2).await;
    tokio::task::yield_now().await;
    assert_eq!(store.measurements.load(Ordering::Relaxed), 0);
    assert_eq!(store.reclaimed.load(Ordering::Relaxed), 0);
}

#[rstest]
#[tokio::test]
async fn tasks_live_until_the_last_owner_drops_without_a_reference_cycle(store: Arc<TestStore>) {
    let weak = Arc::downgrade(&store);
    let maintenance = Arc::new(Maintenance::spawn(store, Some(ByteSize::b(1000))));
    let clone = maintenance.clone();
    drop(maintenance);
    assert!(weak.upgrade().is_some());
    drop(clone);
    wait_until(|| weak.upgrade().is_none()).await;
}

#[cfg(feature = "output-store-bench")]
#[rstest]
#[tokio::test]
async fn graceful_shutdown_waits_for_in_flight_blocking_io(store: Arc<TestStore>) {
    let (release, gate) = mpsc::channel();
    *store.persist_gate.lock() = Some(gate);
    store.dirty.store(true, Ordering::Release);
    let maintenance = Arc::new(Maintenance::spawn(store.clone(), None));
    wait_until(|| store.persists.load(Ordering::Relaxed) == 1).await;
    let shutdown = tokio::spawn(Maintenance::shutdown(Some(maintenance)));
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    release.send(()).unwrap();
    shutdown.await.unwrap();
    assert_eq!(Arc::strong_count(&store), 1);
}

#[rstest]
#[case::unlimited(DiskUsageLimit::Unlimited, None)]
#[case::absolute(DiskUsageLimit::Bytes(ByteSize::b(1000)), Some(ByteSize::b(1000)))]
fn absolute_and_unlimited_budgets_do_not_inspect_the_filesystem(
    #[case] limit: DiskUsageLimit,
    #[case] expected: Option<ByteSize>,
) {
    assert_eq!(resolve_budget(Path::new("/nonexistent/output-store"), limit).unwrap(), expected);
}
