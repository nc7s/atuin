# Output-store space benchmark

Compare the reference Fjall backend with an experimental, uncompressed redb backend by replaying real command output. The measurements are stored bytes and correctness properties, not throughput. Production still selects Fjall; redb and the measurement API are only compiled with `output-store-bench`. The benchmark compares blob storage only, excluding the SQLite search index and its reconciliation.

## Running

From the workspace root, using the project's Rust toolchain:

```sh
cargo bench -p atuin-daemon --features output-store-bench --bench output_store -- \
  --output /tmp/atuin-output-store
```

The default matrix includes **100, 1,000, 2,000 and 5,000 records**, each in a fresh database, plus the year-long simulation. All cases run against both engines with wall-clock flushing and GC enabled. `--max-disk-usage` defaults to the production capture limit, currently `10%` of the filesystem's total capacity; absolute limits such as `1GB` are also accepted. `unlimited` explicitly disables GC, but not flushing. The output directory must not exist. It contains the databases under each scenario and `report.json`; remove it when no longer needed. Allow several GB of free space for a full run, in addition to build artifacts.

Run just the four record counts:

```sh
cargo bench -p atuin-daemon --features output-store-bench --bench output_store -- \
  --output /tmp/atuin-output-store-sizes --scenarios sizes
```

Run just the year simulation with `--scenarios year`. For a quick end-to-end smoke test of both scenarios:

```sh
cargo bench -p atuin-daemon --features output-store-bench --bench output_store -- \
  --output /tmp/atuin-output-store-small --records 10,20 \
  --days 2 --commands-per-day 10 --retention-days 1 --churn-days 2 --checkpoint-days 1
```

Run the backend contract, corpus and harness tests:

```sh
cargo nextest run -p atuin-daemon --features output-store-bench --test output_store_benchmark
cargo nextest run -p atuin-daemon --features output-store-bench --lib -E 'test(output_capture::persistence::blob)'
```

This is a harness-free benchmark because the measurements are bytes and correctness properties. It deliberately does not use Divan/CodSpeed timing results.

## Real-output corpus

`corpus/manifest.json` records every source project, revision, command, exit status and output filename. `corpus/outputs/` holds combined stdout/stderr as UTF-8 text; identical outputs share a file. The data includes actual checks, builds and unit-test runs, alongside Git inspection, directory listings, source searches, file inspection, checksums, dependency trees, metadata and help output. Source projects include Atuin, redb, regex, serde_json, uuid and lz4_flex. Source licenses are preserved under `corpus/licenses/`.

The corpus contains no templated command text and no fabricated random log lines. Recorded lengths are preserved, apart from applying Atuin's current capture limit: oversized output keeps a UTF-8-safe start and end with the original normalized byte count. Terminal dimensions are fixed at 120×40. These are pipe captures, not a recording of PTY rendering or full-screen applications.

The collector normalizes absolute workspace/home paths and carriage returns, and decodes invalid UTF-8 with replacement characters. It does not read user shell history, environment dumps, credentials or private projects. The manifest records normalization and collection provenance. Atuin build output in the bundled corpus came from an isolated Rust 1.95-compatible workspace. Source inspection used working trees based on the revisions recorded in the manifest; the Atuin tree included the benchmark changes. The frozen output files and their hashes are the authoritative inputs. The compatibility adjustments affect build diagnostics, not the storage implementations being compared.

### Collection and regeneration

`collect.py` runs real commands against supplied public workspaces. It requires Python 3, Git, Cargo, rustc, ripgrep and the ordinary Unix commands it invokes. It refuses an existing output directory and fails on unexpected command failures. Checks, builds and tests must succeed; a missing dependency is not silently turned into a workload sample.

For example, with public checkouts or extracted crate releases:

```sh
python3 crates/atuin-daemon/benches/output_store/collect.py \
  --project atuin=/path/to/atuin \
  --project redb=/path/to/redb \
  --project regex=/path/to/regex \
  --project serde-json=/path/to/serde_json \
  --project uuid=/path/to/uuid \
  --project lz4=/path/to/lz4_flex \
  --build atuin --build redb --build regex --build serde-json \
  --target /tmp/output-corpus-target --output /tmp/output-corpus
```

`--build` selects projects to check/build/test; other projects still contribute source-inspection commands. Omit it to build every project. `--offline` uses only cached Cargo dependencies. An optional `--build-project NAME=PATH` points build commands at a different checkout while keeping source-inspection provenance explicit. A new target directory yields cold build output; an existing target directory also captures the short responses from incremental builds. Neither is synthesized.

Replay a newly collected corpus with `--corpus /tmp/output-corpus`. Regeneration will differ with tool versions, source revisions, caches and timings; the checked-in corpus freezes one concrete input dataset. Record the source revision and `Cargo.lock` alongside benchmark results.

## Daily-driver activity model

A seeded sampler chooses recorded commands by activity, **not by a prescribed output-size bucket**:

| Share | Activity |
| --- | --- |
| 20% | Silent commands |
| 18% | Short responses, paths, versions and line counts |
| 12% | Directory and file listings |
| 16% | Source searches |
| 12% | Git inspection |
| 8% | Checks and builds |
| 6% | Unit tests |
| 3% | Help pages |
| 5% | File contents, checksums, dependency trees and metadata |

Lengths and fixed content come from the recorded output. A command's text is never filled in or padded to a target size. Empty output still stores capture metadata. Sampling is with replacement, so a repeated invocation can have identical output, just as repeated status checks or cached builds can in normal use.

A finite corpus is not an indefinitely evolving year of real development. In particular, the long simulation reuses outputs heavily. **The report exposes both distinct sampled commands and distinct source outputs**, for generated and retained data, so this limitation is measurable rather than hidden. Empty outputs from different commands count as one source output. Inspect these counts, the corpus byte-size distribution and the retained activity mix when interpreting results. Try several seeds and other corpora; this is a reproducible replay model, not an empirical claim about every Atuin user.

IDs have UUIDv7 layout and advance through eight-hour workdays with weekend gaps. Each record has an independent seeded RNG; both engines and all size cases receive identical workload prefixes, regardless of scheduling. The corpus is loaded once and shared, rather than storing a separate in-memory copy of the entire year.

## Matrix and phases

### Record-count scenarios

Each requested size starts from a fresh database, without deleting any records during the initial load:

- `empty`: Initial database overhead
- `loaded`: Exactly 100, 1,000, 2,000 or 5,000 durable captures
- `loaded-materialized`: Explicitly flush Fjall memtables to SSTs/blob files; redb only needs its normal durable commit
- `half-deleted`: Evict the oldest half without requesting compaction
- `refilled`: Insert new IDs until the original record count is restored, exposing space reuse
- `final-materialized`: Flush remaining Fjall memtables before the final compaction experiment
- `compacted`: Run each engine's native explicit compaction, then close and reopen
- `reopened`: Measure again after reopening and verification, exposing startup cleanup without new captures

The engines retain identical records at each matching phase. `loaded` and `loaded-materialized` are the primary record-count comparisons; reclamation and compaction are reported separately rather than silently optimizing one store before measuring it.

### Year scenario

The defaults are 300 commands per workday, 260 workdays of accumulation, a trim to the newest 90 workdays, then 90 additional workdays of append-and-evict churn. This generates 105,000 captures overall. Approximately one command in 97 is explicitly deleted from history, independently of retention.

`grow-N` and `churn-N` checkpoints occur every 30 workdays by default. `grown-materialized` explicitly flushes before the initial `trimmed` measurement. The final materialization, compaction and reopen phases are the same as in the size cases. The retention window stays fixed during churn, allowing observation of reuse versus continuing growth.

## Backend comparability

Both engines use the existing reference UUID keys and V2 MessagePack values, with one transaction per capture and atomic duplicate rejection. Reads and writes use Tokio's blocking pool. Fjall keeps its existing LZ4 compression, KV separation and default database options. redb stores the same serialized values without compression, packing, dictionaries or a custom blob layer.

The record-count and year scenarios use `Store::open_with_limit` with wall-clock flushing and GC enabled, including after every checkpoint reopen. `Store::open` uses the same policy with the production capture budget; tests that need caller-driven maintenance must explicitly use `Store::open_without_maintenance`. Command timestamps model bursts of five, but playback runs as fast as the machine allows: simulated days do not advance the wall clock. There are no forced commits per burst or day. The five-second timer drives durability during playback, and every checkpoint gracefully stops maintenance, waits for in-flight I/O and durably commits before measuring files. Fjall uses `persist(SyncAll)`; redb uses non-durable writes followed by an immediate commit that also persists preceding transactions. Fjall's own background flushing and compaction remain enabled. Timing and machine speed affect transaction grouping and checkpoint sizes; repeat runs when investigating differences.

Explicit retention evicts the same oldest records from both stores. The requested reclamation amount is the sum of their serialized-value sizes, matching Fjall's eviction-candidate selection followed by removal. Wall-clock budget checks also run, but these scenarios require a nonbinding budget to preserve equal retained data. The benchmark fails if GC evicts captures or the retained data differs from the replay model; increase `--max-disk-usage` in that case. An enabled GC task is not evidence of physical reclamation: inspect the reported check and reclaimed-byte counts. Tight-budget behavior is covered separately by backend tests, since engine-specific estimates can retain different records.

The native maintenance operations are not equivalent algorithms. redb compaction needs exclusive mutable access and no outstanding transactions; Fjall's major compaction and blob reclamation have their own policies. The last row is not a guarantee of the smallest theoretically possible layout. The benchmark does not migrate existing stores, expose redb in daemon configuration, or change Fjall's production settings.

### Wall-clock maintenance

`Store::open_with_limit(engine, path, max_disk_usage)` enables the same maintenance implementation for either engine and must run inside Tokio. `DiskUsageLimit::Unlimited` enables flushing only; absolute and percentage limits also enable GC, with percentage budgets resolved against the filesystem containing the store as in the reference backend. This API remains behind `output-store-bench`; the daemon still selects Fjall. Flushing is shared with the production blob store. Benchmark GC applies the engine's thresholds to blobs only; production GC remains in `OutputCaptureEngine`, where removal also updates the search index.

- Flush dirty stores every five seconds, with the reference immediate startup tick and delayed missed ticks
- Mark successful captures, removals and reclamation transactions dirty; reject duplicates atomically without scheduling a flush
- Retry failed persistence on the next tick, preserving mutations concurrent with a flush
- Check the disk budget every minute, including at startup, skipping missed GC ticks
- At 95% of the budget, request oldest-first reclamation of enough serialized-value bytes to target 90%
- Stop background tasks when the last backend handle is dropped, without a reference cycle

Fjall persists with `SyncAll`; redb uses an immediate commit to persist preceding non-durable transactions. GC estimates remain engine-specific: Fjall seeds its estimate from segment and blob bytes on open, then adds or subtracts serialized-value bytes on captures and removals so the estimate shrinks promptly. redb sums live table data, indexing metadata and within-page fragmentation. redb excludes free pages, obsolete copy-on-write pages and file preallocation. Using raw file length would repeatedly evict live records to address already-reusable capacity. This is an approximate live-page budget, not a hard cap on redb's file length; explicit compaction remains a separate operation and is not run on every GC tick.

The same budget need not retain the same records in the two engines. Use the replay scenarios with a sufficiently large budget for equal-data space comparisons, and backend tests for budget-driven eviction. The replay executable enables the timers but does not wait out simulated days or claim production-paced maintenance coverage.

For a wall-clock store, call `store.close().await?` before reopening or inspecting database files. It stops the timer loops, waits for in-flight maintenance I/O and durably commits before releasing the database. A plain drop aborts timers but does not wait for an already-running blocking operation. redb's explicit compaction takes exclusive access to the database, including against live maintenance and backend clones, because its native API requires mutable access with no outstanding transactions.

## Measurements and checks

The console prints a table; `report.json` format version 3 contains exact byte counts, corpus statistics, workload parameters, generated/live record counts and activity mixes, reuse counts, verified-capture counts and per-file sizes. It also records the wall-clock intervals, resolved budget, elapsed replay time and completed maintenance activity for each checkpoint interval: successful timer flushes, successful GC checks, logical bytes evicted by GC and maintenance errors. Caller-driven persistence and retention are excluded from those counters. Any maintenance error fails the run. Each checkpoint gracefully closes the database before walking its files, preventing races with in-flight maintenance or background file deletion. It then reopens and verifies every retained capture.

- `output_bytes`: Retained start/end text, before MessagePack encoding
- `serialized_value_bytes`: Exact live MessagePack payload shared by both engines
- `values_below_1kib`: Live values below Fjall's default KV-separation threshold
- `unique_samples`: Distinct recorded commands selected from the corpus
- `unique_source_outputs`: Distinct raw output files represented by those commands
- `file_bytes`: Sum of all database file lengths, including journals and metadata
- `allocated_bytes`: On Unix, allocated filesystem blocks for files and directories, including sparse-file effects; unavailable elsewhere
- `file/logical`: File bytes divided by live MessagePack bytes plus 16 key bytes per record; combines compression and storage overhead, not a pure compression ratio

Measurements include clean-shutdown behavior and periodic reopen/recovery. They are checkpoint sizes, **not peak disk usage**: they do not capture transient compaction growth or every intermediate write. Filesystem compression, reflinks and allocation accounting can affect results. Run both stores on the same filesystem and record the platform and filesystem. Pay particular attention to allocated bytes when comparing sparse files at small record counts.

The executable fails on storage errors or a model mismatch. Every checkpoint verifies the complete live ID set, ordering, serialized lengths and all capture fields after reopening. Both engines must report identical logical data and generated workload statistics at every phase. Playback also checks duplicate rejection, immediate lookup, idempotent history deletion and exact logical bytes evicted.

Integration tests additionally cover concurrent same-ID writers, selective removal, recapture after deletion, zero/oversized reclamation requests, empty versus absent tails, generated Unicode round-trips, corpus diversity, capture-limit boundaries, and persistence through materialization and compaction. Wall-clock tests cover startup GC and graceful close/reopen for both engines. Unit tests cover flush timing and retry, concurrent dirty marking, GC thresholds and timing, unlimited budgets, task lifetime, redb live-page accounting and compaction with maintenance enabled. These are not process-kill or power-loss recovery tests.
