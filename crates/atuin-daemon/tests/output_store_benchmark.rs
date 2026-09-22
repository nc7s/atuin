#![cfg(feature = "output-store-bench")]

use std::sync::Arc;
use std::time::Duration;

use atuin_client::history::{CommandCapture, HistoryId};
use atuin_client::settings::{CaptureLimits, DiskUsageLimit};
use atuin_common::units::ByteSize;
use atuin_daemon::CaptureError;
use atuin_daemon::output_store_benchmark::{Engine, GC_INTERVAL, Store, serialized_value_len};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use rstest::{fixture, rstest};
use tempfile::TempDir;

#[path = "../benches/output_store/config.rs"]
mod config;
#[path = "../benches/output_store/corpus.rs"]
mod corpus;
#[path = "../benches/output_store/measure.rs"]
mod measure;
#[path = "../benches/output_store/simulation.rs"]
mod simulation;
#[path = "../benches/output_store/workload.rs"]
mod workload;

#[fixture]
fn directory() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn id(number: u128) -> HistoryId {
    HistoryId::from_bytes(number.to_be_bytes())
}

fn capture(output: &str, tail: Option<&str>) -> CommandCapture {
    CommandCapture {
        output_start: output.to_owned(),
        output_end: tail.map(str::to_owned),
        output_observed_bytes: 1234,
        terminal_width: 120,
        terminal_height: 40,
    }
}

#[rstest]
#[tokio::test]
async fn captures_round_trip_without_overwriting(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
    #[values(None, Some(""), Some("last line: λ\n"))] tail: Option<&str>,
) {
    let store = Store::open(engine, directory.path()).unwrap();
    let original = capture("\u{1b}[32mhello 世界\u{1b}[0m\n", tail);
    assert!(store.get(id(1)).await.unwrap().is_none());
    store.capture(id(1), original.clone()).await.unwrap();
    assert!(matches!(
        store.capture(id(1), capture("replacement", None)).await,
        Err(CaptureError::AlreadyExists)
    ));
    assert_eq!(store.get(id(1)).await.unwrap(), Some(original.clone()));
    assert_eq!(store.entries().unwrap(), vec![(id(1), serialized_value_len(original).unwrap())]);
}

#[rstest]
#[tokio::test]
async fn concurrent_writers_have_exactly_one_winner(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let store = Arc::new(Store::open(engine, directory.path()).unwrap());
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    for n in 0..16 {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let value = capture(&format!("writer {n}"), None);
            (store.capture(id(1), value.clone()).await, value)
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        match task.await.unwrap() {
            (Ok(()), value) => winners.push(value),
            (Err(CaptureError::AlreadyExists), _) => {}
            (Err(error), _) => panic!("unexpected storage error: {error}"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(store.get(id(1)).await.unwrap(), winners.pop());
}

#[rstest]
#[tokio::test]
async fn deletion_is_selective_idempotent_and_allows_recapture(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let store = Store::open(engine, directory.path()).unwrap();
    for n in 1..=3 {
        store.capture(id(n), capture("original", None)).await.unwrap();
    }
    store.remove(vec![]).await.unwrap();
    store.remove(vec![id(1), id(3), id(99)]).await.unwrap();
    store.remove(vec![id(1), id(99)]).await.unwrap();
    assert!(store.get(id(1)).await.unwrap().is_none());
    assert!(store.get(id(3)).await.unwrap().is_none());
    assert!(store.get(id(2)).await.unwrap().is_some());
    let replacement = capture("recaptured", Some("tail"));
    store.capture(id(1), replacement.clone()).await.unwrap();
    assert_eq!(store.get(id(1)).await.unwrap(), Some(replacement));
}

#[rstest]
#[case(0, 0)]
#[case(1, 1)]
#[case(u64::MAX, 3)]
#[tokio::test]
async fn reclaim_uses_key_order_and_serialized_value_lengths(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
    #[case] bytes: u64,
    #[case] removed: usize,
) {
    let store = Store::open(engine, directory.path()).unwrap();
    for n in (1..=3).rev() {
        store
            .capture(id(n), capture(&"x".repeat(usize::try_from(n).unwrap() * 100), None))
            .await
            .unwrap();
    }
    let before = store.entries().unwrap();
    assert_eq!(
        store.reclaim(bytes).await.unwrap(),
        before[..removed].iter().map(|(_, bytes)| bytes).sum::<u64>()
    );
    assert_eq!(store.entries().unwrap(), before[removed..]);
}

#[rstest]
#[tokio::test]
async fn persistence_materialization_and_compaction_preserve_live_data(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let mut store = Store::open(engine, directory.path()).unwrap();
    let value = capture(&"build output\n".repeat(1000), Some("last line"));
    for n in 1..=20 {
        store.capture(id(n), value.clone()).await.unwrap();
    }
    store.materialize().unwrap();
    store.remove((1..=10).map(id).collect()).await.unwrap();
    store.persist().unwrap();
    let expected = store.entries().unwrap();
    store.close().await.unwrap();
    store = Store::open(engine, directory.path()).unwrap();
    assert_eq!(store.entries().unwrap(), expected);
    store.compact().unwrap();
    store.close().await.unwrap();
    let store = Store::open(engine, directory.path()).unwrap();
    assert_eq!(store.entries().unwrap(), expected);
    for n in 1..=20 {
        assert_eq!(store.get(id(n)).await.unwrap(), (n > 10).then(|| value.clone()));
    }
}

#[rstest]
#[tokio::test(start_paused = true)]
async fn default_stores_enable_wall_clock_maintenance(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let store = Store::open(engine, directory.path()).unwrap();
    store.capture(id(1), capture("timer-driven capture", None)).await.unwrap();
    tokio::time::advance(GC_INTERVAL).await;
    tokio::task::yield_now().await;
    let stats = store.close().await.unwrap();
    assert!(stats.flushes > 0);
    assert!(stats.gc_checks > 0);
    assert_eq!(stats.gc_reclaimed_bytes, 0);
    assert_eq!(stats.errors, 0);
}

#[rstest]
#[tokio::test]
async fn wall_clock_stores_compact_and_close_before_reopening(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
    #[values(DiskUsageLimit::Unlimited, DiskUsageLimit::Bytes(ByteSize::b(1 << 30)))]
    limit: DiskUsageLimit,
) {
    let store = Store::open_with_limit(engine, directory.path(), limit).unwrap();
    let value = capture("wall-clock capture", Some("tail"));
    store.capture(id(1), value.clone()).await.unwrap();
    store.compact().unwrap();
    store.close().await.unwrap();
    let store = Store::open_with_limit(engine, directory.path(), limit).unwrap();
    assert_eq!(store.get(id(1)).await.unwrap(), Some(value));
    store.close().await.unwrap();
}

#[rstest]
#[tokio::test]
async fn wall_clock_gc_applies_the_budget_on_open(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let store = Store::open(engine, directory.path()).unwrap();
    store.capture(id(1), capture(&"output".repeat(1000), None)).await.unwrap();
    store.materialize().unwrap();
    store.close().await.unwrap();
    let store =
        Store::open_with_limit(engine, directory.path(), DiskUsageLimit::Bytes(ByteSize::b(0)))
            .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !store.entries().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("startup GC did not evict over-budget output");
    let stats = store.close().await.unwrap();
    assert!(stats.gc_checks > 0);
    assert!(stats.gc_reclaimed_bytes > 0);
    let store = Store::open(engine, directory.path()).unwrap();
    assert!(store.entries().unwrap().is_empty());
}

#[rstest]
fn generated_captures_round_trip(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let store = Store::open_without_maintenance(engine, directory.path()).unwrap();
    let strategy = (
        "[^\\p{C}]{0,128}",
        prop::option::of("[^\\p{C}]{0,128}"),
        any::<u64>(),
        any::<u16>(),
        any::<u16>(),
    );
    let mut runner = TestRunner::new(Config {
        cases: 32,
        ..Config::default()
    });
    runner
        .run(&strategy, |(start, end, observed, width, height)| {
            let value = CommandCapture {
                output_start: start,
                output_end: end,
                output_observed_bytes: observed,
                terminal_width: width,
                terminal_height: height,
            };
            let actual = runtime.block_on(async {
                store.remove(vec![id(1)]).await.unwrap();
                store.capture(id(1), value.clone()).await.unwrap();
                store.get(id(1)).await.unwrap().unwrap()
            });
            prop_assert_eq!(actual, value);
            Ok(())
        })
        .unwrap();
}

#[rstest]
fn unusable_paths_fail_instead_of_silently_discarding_output(
    directory: TempDir,
    #[values(Engine::Fjall, Engine::Redb)] engine: Engine,
) {
    let path = directory.path().join("not-a-directory");
    std::fs::write(&path, "occupied").unwrap();
    assert!(Store::open(engine, &path).is_err());
}

#[rstest]
#[tokio::test]
async fn benchmark_lifecycle_keeps_identical_data(directory: TempDir) {
    use clap::Parser as _;

    let config = config::Config::parse_from([
        "output-store",
        "--output",
        directory.path().to_str().unwrap(),
        "--records",
        "10,20",
        "--days",
        "2",
        "--commands-per-day",
        "10",
        "--retention-days",
        "1",
        "--churn-days",
        "2",
        "--checkpoint-days",
        "1",
    ]);
    assert_eq!(config.max_disk_usage, CaptureLimits::default().max_disk_usage);
    let corpus = Arc::new(corpus::Corpus::load(&config.corpus).unwrap());
    let workload = workload::Workload::new(config.seed, config.commands_per_day, corpus);
    let fjall = simulation::run(Engine::Fjall, &config, &workload).await.unwrap();
    let redb = simulation::run(Engine::Redb, &config, &workload).await.unwrap();
    assert_eq!(fjall.len(), redb.len());
    for snapshots in [&fjall, &redb] {
        assert!(snapshots.iter().any(|row| row.maintenance.gc_checks > 0));
        assert!(snapshots.iter().all(|row| row.maintenance.errors == 0));
        assert!(snapshots.iter().all(|row| row.maintenance.gc_reclaimed_bytes == 0));
    }
    for (fjall, redb) in fjall.iter().zip(&redb) {
        assert_eq!(fjall.phase, redb.phase);
        assert_eq!(fjall.live, redb.live);
        assert_eq!(fjall.generated, redb.generated);
        assert_eq!(fjall.verified_captures, fjall.live.records);
        assert_eq!(redb.verified_captures, redb.live.records);
        assert!(fjall.disk.file_bytes > 0);
        assert!(redb.disk.file_bytes > 0);
    }
    let loaded: Vec<_> =
        fjall.iter().filter(|row| row.phase == "loaded").map(|row| row.live.records).collect();
    assert_eq!(loaded, vec![10, 20]);
    assert_eq!(fjall.last().unwrap().live.records, 10);
    assert_eq!(fjall.last().unwrap().generated.records, 40);
}

#[rstest]
fn real_corpus_is_diverse_and_replay_keeps_the_capture_limit() {
    let corpus = Arc::new(corpus::Corpus::load(&corpus::default_path()).unwrap());
    assert!(corpus.summary.samples >= 1000);
    assert!(corpus.summary.unique_outputs >= 500);
    assert!(corpus.summary.projects.len() >= 4);
    assert!(corpus.summary.p95_bytes > corpus.summary.median_bytes);
    let workload = workload::Workload::new(42, 300, corpus.clone());
    let mut counts = std::collections::BTreeMap::new();
    for index in 0..3000 {
        let record = workload.record(index);
        assert!(record.output_bytes() <= u64::try_from(corpus.summary.capture_limit).unwrap());
        *counts.entry(record.kind).or_insert(0) += 1;
    }
    assert_eq!(counts.len(), 9);
}
