use std::path::Path;

use atuin_daemon::output_store_benchmark::MaintenanceStats;
use eyre::{Result, ensure};
use serde::Serialize;

use super::simulation::LogicalSize;

#[derive(Default, Serialize)]
pub struct DiskUsage {
    pub file_bytes: u64,
    pub allocated_bytes: Option<u64>,
    pub files: Vec<FileSize>,
}

#[derive(Serialize)]
pub struct FileSize {
    path: String,
    bytes: u64,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub engine: String,
    pub scenario: String,
    pub phase: String,
    pub live: LogicalSize,
    pub generated: LogicalSize,
    pub disk: DiskUsage,
    pub verified_captures: u64,
    /// Completed wall-clock work since the previous checkpoint opened this store.
    pub maintenance: MaintenanceStats,
}

impl Snapshot {
    pub fn print(&self) {
        let mib = |bytes: u64| bytes as f64 / 1_048_576.0;
        let allocated = self
            .disk
            .allocated_bytes
            .map_or_else(|| "n/a".to_owned(), |n| format!("{:.2}", mib(n)));
        let logical = self.live.serialized_value_bytes + self.live.records * 16;
        let ratio = if logical == 0 {
            "n/a".to_owned()
        } else {
            format!("{:.3}", self.disk.file_bytes as f64 / logical as f64)
        };
        println!(
            "{:<6} {:<14} {:<22} {:>7} {:>10.2} {:>11.2} {:>8.2} {:>13} {:>12}",
            self.engine,
            self.scenario,
            self.phase,
            self.live.records,
            mib(self.live.output_bytes),
            mib(self.live.serialized_value_bytes),
            mib(self.disk.file_bytes),
            allocated,
            ratio
        );
    }
}

/// Measure only a closed database, including journals, manifests and directory allocations.
pub fn disk_usage(root: &Path) -> Result<DiskUsage> {
    let mut usage = DiskUsage {
        allocated_bytes: cfg!(unix).then_some(0),
        ..DiskUsage::default()
    };
    visit(root, root, &mut usage)?;
    usage.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(usage)
}

fn visit(root: &Path, path: &Path, usage: &mut DiskUsage) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(!metadata.is_symlink(), "unexpected symlink in database: {}", path.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        *usage.allocated_bytes.as_mut().expect("unix allocation counter") +=
            metadata.blocks() * 512;
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            visit(root, &entry?.path(), usage)?;
        }
    } else {
        ensure!(metadata.is_file(), "unexpected non-file in database: {}", path.display());
        usage.file_bytes += metadata.len();
        usage.files.push(FileSize {
            path: path.strip_prefix(root)?.to_string_lossy().into_owned(),
            bytes: metadata.len(),
        });
    }
    Ok(())
}
