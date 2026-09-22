use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use atuin_client::history::HistoryId;
use atuin_client::settings::DiskUsageLimit;
use atuin_daemon::CaptureError;
use atuin_daemon::output_store_benchmark::{Engine, Store, serialized_value_len};
use eyre::{Result, ensure};
use serde::Serialize;

use super::config::{Config, Scenario};
use super::corpus::Kind;
use super::measure::{Snapshot, disk_usage};
use super::workload::Workload;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LogicalSize {
    pub records: u64,
    pub output_bytes: u64,
    pub observed_bytes: u64,
    pub serialized_value_bytes: u64,
    pub values_below_1kib: u64,
    pub unique_samples: u64,
    pub unique_source_outputs: u64,
    pub kinds: BTreeMap<Kind, u64>,
}

impl LogicalSize {
    fn add(&mut self, entry: &Expected) {
        self.records += 1;
        self.output_bytes += entry.output_bytes;
        self.observed_bytes += entry.observed_bytes;
        self.serialized_value_bytes += entry.serialized_bytes;
        self.values_below_1kib += u64::from(entry.serialized_bytes < 1024);
        *self.kinds.entry(entry.kind).or_default() += 1;
    }
}

struct Expected {
    index: u64,
    serialized_bytes: u64,
    output_bytes: u64,
    observed_bytes: u64,
    kind: Kind,
    sample: usize,
    output: usize,
}

struct Simulation {
    workload: Workload,
    live: BTreeMap<[u8; 16], Expected>,
    generated: LogicalSize,
    samples: BTreeSet<usize>,
    outputs: BTreeSet<usize>,
}

impl Simulation {
    fn new(workload: Workload) -> Self {
        Self {
            workload,
            live: BTreeMap::new(),
            generated: LogicalSize::default(),
            samples: BTreeSet::new(),
            outputs: BTreeSet::new(),
        }
    }

    async fn append(&mut self, store: &Store, index: u64) -> Result<()> {
        let record = self.workload.record(index);
        let entry = Expected {
            index,
            serialized_bytes: serialized_value_len(record.capture.clone())?,
            output_bytes: record.output_bytes(),
            observed_bytes: record.capture.output_observed_bytes,
            kind: record.kind,
            sample: record.sample,
            output: record.output,
        };
        store.capture(record.id, record.capture.clone()).await?;
        self.generated.add(&entry);
        self.generated.unique_samples += u64::from(self.samples.insert(entry.sample));
        self.generated.unique_source_outputs += u64::from(self.outputs.insert(entry.output));
        self.live.insert(record.id.into_bytes(), entry);
        if index.is_multiple_of(u64::from(self.workload.commands_per_day)) {
            ensure!(
                store.get(record.id).await? == Some(record.capture.clone()),
                "immediate round-trip failed"
            );
            let mut duplicate = record.capture;
            duplicate.output_start.push_str("must not overwrite the first capture");
            ensure!(
                matches!(
                    store.capture(record.id, duplicate).await,
                    Err(CaptureError::AlreadyExists)
                ),
                "duplicate capture was not rejected"
            );
        }
        Ok(())
    }

    async fn play_day(&mut self, store: &Store, day: u32) -> Result<()> {
        let start = u64::from(day) * u64::from(self.workload.commands_per_day);
        for slot in 0..self.workload.commands_per_day {
            let index = start + u64::from(slot);
            self.append(store, index).await?;
            /* History deletion is separate from retention and independent of output size. */
            if index.is_multiple_of(97) {
                let id = self.workload.record(index).id;
                store.remove(vec![id]).await?;
                store.remove(vec![id]).await?;
                ensure!(store.get(id).await?.is_none(), "deleted capture remained visible");
                self.live.remove(&id.into_bytes());
            }
        }
        Ok(())
    }

    async fn trim_oldest(&mut self, store: &Store, count: usize) -> Result<()> {
        let expired: Vec<_> = self
            .live
            .iter()
            .take(count)
            .map(|(key, entry)| (*key, entry.serialized_bytes))
            .collect();
        let bytes = expired.iter().map(|(_, bytes)| bytes).sum();
        ensure!(
            store.reclaim(bytes).await? == bytes,
            "oldest-first eviction removed the wrong byte count"
        );
        for (key, _) in expired {
            self.live.remove(&key);
        }
        Ok(())
    }

    async fn trim_before(&mut self, store: &Store, day: u32) -> Result<()> {
        let count = self
            .live
            .values()
            .take_while(|entry| self.workload.day(entry.index) < u64::from(day))
            .count();
        self.trim_oldest(store, count).await
    }

    async fn verify(&self, store: &Store) -> Result<LogicalSize> {
        let expected: Vec<_> = self
            .live
            .iter()
            .map(|(key, entry)| (HistoryId::from_bytes(*key), entry.serialized_bytes))
            .collect();
        ensure!(
            store.entries()? == expected,
            "live IDs, ordering or serialized lengths differ from model"
        );
        let mut logical = LogicalSize::default();
        let mut samples = BTreeSet::new();
        let mut outputs = BTreeSet::new();
        for entry in self.live.values() {
            let record = self.workload.record(entry.index);
            ensure!(
                store.get(record.id).await? == Some(record.capture),
                "capture {} failed round-trip",
                record.id
            );
            logical.add(entry);
            logical.unique_samples += u64::from(samples.insert(entry.sample));
            logical.unique_source_outputs += u64::from(outputs.insert(entry.output));
        }
        Ok(logical)
    }
}

struct Run {
    engine: Engine,
    path: PathBuf,
    scenario: String,
    limit: DiskUsageLimit,
    snapshots: Vec<Snapshot>,
}

impl Run {
    fn new(engine: Engine, config: &Config, scenario: String) -> Self {
        Self {
            engine,
            path: config.output.join(&scenario).join(engine.to_string()),
            scenario,
            limit: config.max_disk_usage,
            snapshots: Vec::new(),
        }
    }

    fn open(&self) -> Result<Store> {
        Store::open_with_limit(self.engine, &self.path, self.limit)
    }

    async fn checkpoint(
        &mut self,
        store: Store,
        phase: &str,
        simulation: &Simulation,
    ) -> Result<Store> {
        /* Drain timer I/O before traversing files, including the final durable commit. */
        let maintenance = store.close().await?;
        ensure!(
            maintenance.gc_reclaimed_bytes == 0,
            "wall-clock GC evicted data at {phase}; increase --max-disk-usage for an equal-data comparison"
        );
        let disk = disk_usage(&self.path)?;
        let store = self.open()?;
        let live = simulation.verify(&store).await?;
        let snapshot = Snapshot {
            engine: self.engine.to_string(),
            scenario: self.scenario.clone(),
            phase: phase.to_owned(),
            verified_captures: live.records,
            live,
            generated: simulation.generated.clone(),
            disk,
            maintenance,
        };
        snapshot.print();
        self.snapshots.push(snapshot);
        Ok(store)
    }

    async fn finish(&mut self, mut store: Store, simulation: &Simulation) -> Result<()> {
        store.materialize()?;
        store = self.checkpoint(store, "final-materialized", simulation).await?;
        store.compact()?;
        store = self.checkpoint(store, "compacted", simulation).await?;
        store = self.checkpoint(store, "reopened", simulation).await?;
        store.close().await?;
        Ok(())
    }
}

pub async fn run(engine: Engine, config: &Config, workload: &Workload) -> Result<Vec<Snapshot>> {
    let mut snapshots = Vec::new();
    if config.scenarios.contains(&Scenario::Sizes) {
        for &count in &config.records {
            snapshots.extend(run_size(engine, config, workload.clone(), count).await?);
        }
    }
    if config.scenarios.contains(&Scenario::Year) {
        snapshots.extend(run_year(engine, config, workload.clone()).await?);
    }
    Ok(snapshots)
}

async fn run_size(
    engine: Engine,
    config: &Config,
    workload: Workload,
    count: u32,
) -> Result<Vec<Snapshot>> {
    let mut run = Run::new(engine, config, format!("records-{count}"));
    let mut store = run.open()?;
    let mut simulation = Simulation::new(workload);
    store = run.checkpoint(store, "empty", &simulation).await?;
    for index in 0..u64::from(count) {
        simulation.append(&store, index).await?;
    }
    store = run.checkpoint(store, "loaded", &simulation).await?;
    store.materialize()?;
    store = run.checkpoint(store, "loaded-materialized", &simulation).await?;
    let removed = count / 2;
    simulation.trim_oldest(&store, usize::try_from(removed)?).await?;
    store = run.checkpoint(store, "half-deleted", &simulation).await?;
    for index in u64::from(count)..u64::from(count + removed) {
        simulation.append(&store, index).await?;
    }
    store = run.checkpoint(store, "refilled", &simulation).await?;
    run.finish(store, &simulation).await?;
    Ok(run.snapshots)
}

async fn run_year(engine: Engine, config: &Config, workload: Workload) -> Result<Vec<Snapshot>> {
    let mut run = Run::new(engine, config, "year".to_owned());
    let mut store = run.open()?;
    let mut simulation = Simulation::new(workload);
    store = run.checkpoint(store, "empty", &simulation).await?;
    for day in 0..config.days {
        simulation.play_day(&store, day).await?;
        if (day + 1).is_multiple_of(config.checkpoint_days) || day + 1 == config.days {
            store = run.checkpoint(store, &format!("grow-{}", day + 1), &simulation).await?;
        }
    }
    store.materialize()?;
    store = run.checkpoint(store, "grown-materialized", &simulation).await?;
    simulation.trim_before(&store, config.days - config.retention_days).await?;
    store = run.checkpoint(store, "trimmed", &simulation).await?;
    for offset in 0..config.churn_days {
        let day = config.days + offset;
        simulation.play_day(&store, day).await?;
        simulation.trim_before(&store, day + 1 - config.retention_days).await?;
        if (offset + 1).is_multiple_of(config.checkpoint_days) || offset + 1 == config.churn_days {
            store = run.checkpoint(store, &format!("churn-{}", offset + 1), &simulation).await?;
        }
    }
    run.finish(store, &simulation).await?;
    Ok(run.snapshots)
}
