use std::path::PathBuf;

use atuin_client::settings::{CaptureLimits, DiskUsageLimit};
use atuin_daemon::output_store_benchmark::Engine;
use clap::Parser;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scenario {
    Sizes,
    Year,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineOrder {
    FjallRedbSqlite,
    FjallSqliteRedb,
    RedbFjallSqlite,
    RedbSqliteFjall,
    SqliteFjallRedb,
    SqliteRedbFjall,
}

impl EngineOrder {
    pub fn engines(self) -> [Engine; 3] {
        use Engine::{Fjall, Redb, Sqlite};

        match self {
            Self::FjallRedbSqlite => [Fjall, Redb, Sqlite],
            Self::FjallSqliteRedb => [Fjall, Sqlite, Redb],
            Self::RedbFjallSqlite => [Redb, Fjall, Sqlite],
            Self::RedbSqliteFjall => [Redb, Sqlite, Fjall],
            Self::SqliteFjallRedb => [Sqlite, Fjall, Redb],
            Self::SqliteRedbFjall => [Sqlite, Redb, Fjall],
        }
    }
}

#[derive(Debug, Parser, Serialize)]
#[command(about = "Compare output-store space usage, not operation throughput")]
pub struct Config {
    /// New directory for all databases and report.json. Existing paths are refused.
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value_os_t = super::corpus::default_path())]
    pub corpus: PathBuf,
    /// Wall-clock GC budget. Binding budgets fail the equal-data comparison; use a larger limit.
    #[arg(long, default_value_t = CaptureLimits::default().max_disk_usage)]
    pub max_disk_usage: DiskUsageLimit,
    #[arg(long, value_enum, value_delimiter = ',', default_value = "sizes,year")]
    pub scenarios: Vec<Scenario>,
    /// Execution order only; every backend is still compared against Fjall.
    #[arg(long, value_enum, default_value = "fjall-redb-sqlite")]
    pub engine_order: EngineOrder,
    /// Independent fresh-database sizes, replaying identical prefixes of the workload.
    #[arg(long, value_delimiter = ',', default_value = "100,1000,2000,5000",
        value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub records: Vec<u32>,
    /// Workdays of accumulation before retention starts.
    #[arg(long, default_value_t = 260, value_parser = clap::value_parser!(u32).range(1..=3650))]
    pub days: u32,
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    pub commands_per_day: u32,
    /// Workdays retained after the initial accumulation phase.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=3650))]
    pub retention_days: u32,
    /// Workdays of append-and-evict churn after the initial trim.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(0..=3650))]
    pub churn_days: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=3650))]
    pub checkpoint_days: u32,
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
    /* Cargo passes this to harness-free benchmark executables. */
    #[arg(long = "bench", hide = true)]
    #[serde(skip)]
    is_bench: bool,
}
