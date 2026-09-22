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

#[fixture]
fn store() -> SqliteBackend {
    SqliteBackend::connect(&SqliteConnectOptions::new().filename(":memory:")).unwrap()
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

async fn mutate(store: &SqliteBackend, mutation: Mutation) {
    match mutation {
        Mutation::Capture => store.capture(id(2), capture()).await.unwrap(),
        Mutation::Remove => store.remove(vec![id(1)]).await.unwrap(),
        Mutation::Reclaim => {
            store.reclaim(1).await.unwrap();
        }
    }
}

#[rstest]
fn configuration_uses_wal_and_bounded_caches(directory: TempDir) {
    let store = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
    let mut connection = store.inner.connection.lock();
    block_on(async {
        let journal: String =
            query_scalar("PRAGMA journal_mode").fetch_one(&mut *connection).await.unwrap();
        assert_eq!(journal, "wal");
        let (page_size, synchronous, auto_vacuum, cache_size): (i64, i64, i64, i64) = query_as(
            "SELECT page_size, synchronous, auto_vacuum, cache_size
             FROM pragma_page_size(), pragma_synchronous(), pragma_auto_vacuum(), pragma_cache_size()",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        assert_eq!((page_size, synchronous, auto_vacuum, cache_size), (4096, 1, 0, -8192));
        let auto_checkpoint: i64 =
            query_scalar("PRAGMA wal_autocheckpoint").fetch_one(&mut *connection).await.unwrap();
        let journal_limit: i64 =
            query_scalar("PRAGMA journal_size_limit").fetch_one(&mut *connection).await.unwrap();
        assert_eq!((auto_checkpoint, journal_limit), (1000, 4 * 1024 * 1024));
    });
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn mutations_are_flushed_on_the_wall_clock(
    directory: TempDir,
    #[values(Mutation::Capture, Mutation::Remove, Mutation::Reclaim)] mutation: Mutation,
) {
    let mut store = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
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
    let stats = store.stop_maintenance().await;
    assert_eq!(stats.flushes, 1);
    assert_eq!(stats.errors, 0);
    let expected = store.entries().unwrap();
    store.close().unwrap();
    let reopened = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
    assert_eq!(reopened.entries().unwrap(), expected);
    reopened.close().unwrap();
}

#[rstest]
#[tokio::test]
async fn undecodable_values_return_a_storage_error(store: SqliteBackend) {
    store.capture(id(1), capture()).await.unwrap();
    block_on(
        query("UPDATE output_capture_v2 SET value = ? WHERE id = ?")
            .bind(b"not messagepack".as_slice())
            .bind(id(1).into_bytes().as_slice())
            .execute(&mut *store.inner.connection.lock()),
    )
    .unwrap();
    assert!(matches!(store.get(id(1)).await, Err(GetOutputError::Storage(_))));
}

#[rstest]
#[tokio::test]
async fn rejected_and_empty_mutations_do_not_mark_dirty(store: SqliteBackend) {
    store.capture(id(1), capture()).await.unwrap();
    store.inner.dirty.store(false, Ordering::Relaxed);
    assert!(matches!(store.capture(id(1), capture()).await, Err(CaptureError::AlreadyExists)));
    store.remove(vec![]).await.unwrap();
    store.remove(vec![id(99)]).await.unwrap();
    assert_eq!(store.reclaim(0).await.unwrap(), 0);
    assert!(!store.inner.dirty.load(Ordering::Acquire));
}

#[rstest]
#[tokio::test]
async fn unexpected_constraints_are_not_duplicate_errors(store: SqliteBackend) {
    block_on(
        query(
            "CREATE TRIGGER reject_capture BEFORE INSERT ON output_capture_v2
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
        )
        .execute(&mut *store.inner.connection.lock()),
    )
    .unwrap();
    assert!(matches!(store.capture(id(1), capture()).await, Err(CaptureError::Storage(_))));
    assert!(!store.inner.dirty.load(Ordering::Acquire));
}

#[rstest]
#[tokio::test]
async fn failed_deletions_roll_back_the_entire_transaction(
    store: SqliteBackend,
    #[values(Mutation::Remove, Mutation::Reclaim)] mutation: Mutation,
) {
    for number in 1..=2 {
        store.capture(id(number), capture()).await.unwrap();
    }
    store.inner.dirty.store(false, Ordering::Relaxed);
    block_on(
        query(
            "CREATE TRIGGER reject_delete BEFORE DELETE ON output_capture_v2
             WHEN OLD.id = X'00000000000000000000000000000002'
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
        )
        .execute(&mut *store.inner.connection.lock()),
    )
    .unwrap();
    let result = match mutation {
        Mutation::Remove => store.remove(vec![id(1), id(2)]).await,
        Mutation::Reclaim => store.reclaim(u64::MAX).await.map(|_| ()),
        Mutation::Capture => unreachable!(),
    };
    assert!(matches!(result, Err(DeleteOutputError::Storage(_))));
    assert_eq!(store.entries().unwrap().len(), 2);
    assert!(!store.inner.dirty.load(Ordering::Acquire));
}

#[rstest]
#[tokio::test]
async fn checkpoint_rejects_busy_readers_and_succeeds_after_release(directory: TempDir) {
    let store = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
    store.capture(id(1), capture()).await.unwrap();
    store.persist().unwrap();
    let options = SqliteConnectOptions::new().filename(directory.path().join("output.sqlite3"));
    let mut reader = SqliteConnection::connect_with(&options).await.unwrap();
    let mut tx = reader.begin().await.unwrap();
    let _: i64 =
        query_scalar("SELECT count(id) FROM output_capture_v2").fetch_one(&mut *tx).await.unwrap();
    store.capture(id(2), capture()).await.unwrap();
    block_on(query("PRAGMA busy_timeout = 0").execute(&mut *store.inner.connection.lock()))
        .unwrap();
    let error = store.persist().unwrap_err();
    assert!(error.to_string().contains("checkpoint incomplete"));
    tx.rollback().await.unwrap();
    reader.close().await.unwrap();
    store.persist().unwrap();
    store.close().unwrap();
    assert!(!directory.path().join("output.sqlite3-wal").exists());
    let reopened = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
    assert_eq!(reopened.entries().unwrap().len(), 2);
    reopened.close().unwrap();
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn gc_trims_oldest_and_ignores_reusable_file_capacity(directory: TempDir) {
    let store = SqliteBackend::open_for_benchmark(directory.path()).unwrap();
    for number in (1..=80).rev() {
        store.capture(id(number), capture()).await.unwrap();
    }
    store.persist().unwrap();
    let file_size = std::fs::metadata(directory.path().join("output.sqlite3")).unwrap().len();
    store.remove((1..=40).map(id).collect()).await.unwrap();
    store.persist().unwrap();
    let size = store.inner.estimated_disk_space().unwrap();
    assert!(size < file_size);
    let before = store.entries().unwrap();
    store.close().unwrap();
    let mut store =
        SqliteBackend::open(directory.path(), DiskUsageLimit::Bytes(ByteSize::b(size))).unwrap();
    wait_until(|| store.entries().unwrap().len() < before.len()).await;
    let retained = store.entries().unwrap();
    assert!(!retained.is_empty());
    assert_eq!(retained, before[before.len() - retained.len()..]);
    assert!(store.inner.estimated_disk_space().unwrap() < size * Percent::new(95.0));
    tokio::time::advance(GC_INTERVAL).await;
    tokio::task::yield_now().await;
    let stats = store.stop_maintenance().await;
    assert!(stats.gc_reclaimed_bytes > 0);
    assert_eq!(stats.errors, 0);
    assert_eq!(store.entries().unwrap(), retained);
    store.persist().unwrap();
    store.close().unwrap();
}

#[rstest]
#[tokio::test]
async fn compaction_with_maintenance_and_clones_reclaims_free_pages(directory: TempDir) {
    let mut store = SqliteBackend::open(directory.path(), DiskUsageLimit::Unlimited).unwrap();
    for number in 1..=40 {
        store.capture(id(number), capture()).await.unwrap();
    }
    store.persist().unwrap();
    let before = std::fs::metadata(directory.path().join("output.sqlite3")).unwrap().len();
    store.remove((1..=30).map(id).collect()).await.unwrap();
    let clone = store.clone();
    store.compact().unwrap();
    assert_eq!(clone.get(id(40)).await.unwrap(), Some(capture()));
    assert!(std::fs::metadata(directory.path().join("output.sqlite3")).unwrap().len() < before);
    drop(clone);
    store.stop_maintenance().await;
    store.close().unwrap();
}

#[rstest]
#[tokio::test]
async fn dropping_the_last_backend_stops_tasks(directory: TempDir) {
    let store = SqliteBackend::open(directory.path(), DiskUsageLimit::Unlimited).unwrap();
    let weak = Arc::downgrade(&store.inner);
    let clone = store.clone();
    drop(store);
    assert!(weak.upgrade().is_some());
    drop(clone);
    wait_until(|| weak.upgrade().is_none()).await;
}
