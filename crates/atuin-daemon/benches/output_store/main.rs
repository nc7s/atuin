mod config;
mod corpus;
mod measure;
mod simulation;
mod workload;

use std::sync::Arc;
use std::time::Instant;

use atuin_daemon::output_store_benchmark::{Engine, GC_INTERVAL, SYNC_INTERVAL};
use clap::Parser;
use eyre::{Result, ensure};
use serde::Serialize;

use config::{Config, Scenario};
use measure::Snapshot;
use workload::Workload;

#[derive(Serialize)]
struct Report {
    format_version: u32,
    config: Config,
    corpus: corpus::Summary,
    workload: Workload,
    maintenance: MaintenanceConfig,
    elapsed_seconds: f64,
    snapshots: Vec<Snapshot>,
}

#[derive(Serialize)]
struct MaintenanceConfig {
    clock: &'static str,
    sync_interval_seconds: u64,
    gc_interval_seconds: u64,
    resolved_budget_bytes: Option<u64>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let started = Instant::now();
    let config = Config::parse();
    if config.scenarios.contains(&Scenario::Year) {
        ensure!(config.retention_days <= config.days, "--retention-days must not exceed --days");
    }
    ensure!(
        config.records.iter().collect::<std::collections::BTreeSet<_>>().len()
            == config.records.len(),
        "--records must not repeat a size"
    );
    let corpus = Arc::new(corpus::Corpus::load(&config.corpus)?);
    std::fs::create_dir(&config.output)?;
    let maintenance = MaintenanceConfig {
        clock: "wall",
        sync_interval_seconds: SYNC_INTERVAL.as_secs(),
        gc_interval_seconds: GC_INTERVAL.as_secs(),
        resolved_budget_bytes: config
            .max_disk_usage
            .resolve_for_path(&config.output)?
            .map(|budget| budget.as_u64()),
    };
    println!(
        "Wall-clock maintenance: flush every {}s, GC every {}s, budget {} ({:?} bytes)",
        maintenance.sync_interval_seconds,
        maintenance.gc_interval_seconds,
        config.max_disk_usage,
        maintenance.resolved_budget_bytes
    );
    let workload = Workload::new(config.seed, config.commands_per_day, corpus.clone());
    println!(
        "Corpus: {} commands, {} unique outputs, {} projects",
        corpus.summary.samples,
        corpus.summary.unique_outputs,
        corpus.summary.projects.len()
    );
    println!(concat!(
        "engine scenario       phase                  records output MiB encoded MiB ",
        "file MiB allocated MiB file/logical"
    ));
    let mut snapshots = simulation::run(Engine::Fjall, &config, &workload).await?;
    let redb = simulation::run(Engine::Redb, &config, &workload).await?;
    ensure!(snapshots.len() == redb.len(), "engines produced different checkpoint counts");
    for (fjall, redb) in snapshots.iter().zip(&redb) {
        ensure!(
            fjall.scenario == redb.scenario
                && fjall.phase == redb.phase
                && fjall.live == redb.live
                && fjall.generated == redb.generated,
            "engines retained different logical data at {}",
            fjall.phase
        );
    }
    snapshots.extend(redb);
    let path = config.output.join("report.json");
    let report = Report {
        format_version: 3,
        config,
        corpus: corpus.summary.clone(),
        workload,
        maintenance,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        snapshots,
    };
    serde_json::to_writer_pretty(std::fs::File::create_new(&path)?, &report)?;
    println!("All retained captures verified after every reopen. Report: {}", path.display());
    Ok(())
}
