# Output-store storage analysis: Fjall, redb and SQLite

## Key findings

- **SQLite has the most repeatable final footprint.** It finishes smaller than redb in every recovered cloud pass, with identical final allocation within each workload seed
- **Fjall often finishes slightly smaller than SQLite, but its larger outcomes outweigh those small savings.** Substantial variation persists with the seed, Sprite and engine order held fixed
- **Retention does not promptly reclaim physical space.** Removing roughly 65% of live records increases Fjall's allocation and leaves SQLite's unchanged. Final year-scale compaction shrinks all three engines, but does not make Fjall's layout deterministic
- **No backend is smallest throughout the lifecycle.** Local small-store tests favor Fjall after initial materialization and SQLite after churn, compaction and reopening
- **The larger Fjall layouts warrant investigation, not a leak claim.** Extra blob files persist after process exit; their liveness and reclamation eligibility remain unknown

### Headline numbers

**Final year-scale allocation, after compaction and reopening:** 191 validated cloud passes across 16 seeds and ten Sprites, out of 256 planned passes. Values are filesystem-allocated MiB, not provider physical or billable storage.

| Engine | Median MiB | Q1–Q3 MiB | Minimum–maximum MiB |
|---|---:|---:|---:|
| Fjall | **105.625** | 103.707–135.668 | **101.504–285.777** |
| redb | **143.906** | 141.637–146.094 | **138.762–147.695** |
| SQLite | **105.766** | 104.098–107.445 | **101.461–109.027** |

| Paired comparison | Passes where A is smaller | Median A−B MiB | Minimum–maximum A−B MiB |
|---|---:|---:|---:|
| Fjall−redb | 164 / 191 | −38.031 | −41.656 to +141.973 |
| Fjall−SQLite | 106 / 191 | **−0.141** | **−2.594 to +180.012** |
| SQLite−redb | **191 / 191** | −38.406 | −39.754 to −37.039 |

Negative differences favor A; there are no ties. Paired differences compare identical live data within a pass and need not equal differences between pooled medians.

**Controlled repeatability:** four fresh-database repetitions with seed 14, Sprite 06 and a fixed engine order ended at **105.625, 263.391, 105.625 and 105.625 MiB** for Fjall. Reversing the order also produced a large outcome.

All validated passes retained the expected logical data, with **zero maintenance errors and zero budget-driven GC evictions**. These are clean-shutdown space measurements under a nonbinding budget, not throughput, peak-space or crash-recovery results. Production still uses Fjall; alternatives remain experimental and feature-gated.

## Scope and method

A pass replays each selected scenario against all three backends sequentially. Checkpoints within a pass are not independent replications. The principal evidence is:

| Cohort | Workload and ordering | Validated / planned passes | Validated snapshots |
|---|---|---:|---:|
| Local seed series | Seeds 1–20; small stores and year; fixed Fjall → redb → SQLite | 20 / 20 | 3,000 |
| Broad cloud round | Seeds 1–16; year only; all six orders across ten Sprites | 191 / 256 | 10,314 |
| Controlled cloud follow-up | Seeds 6 and 14; year only; two reversed orders; four repetitions per seed × Sprite × order | 32 / 48 | 1,728 |

The local series ran on Btrfs with `compress=zstd:3`; Sprite benchmark paths used overlayfs. Platform, scheduling, order and scenario coverage also differ, so local and cloud results are not pooled.

The broad schedule balanced pairwise backend precedence within each seed before execution, but recovered coverage is uneven. Of the 65 missing reports, losses arose from an interruption/restart and conservative compute-cost guards, not storage-budget eviction. Faster workers contribute more observations. The follow-up was selected after inspecting the broad results; two Sprites completed all assignments, while the third lost its directory and service after a boot change. Missing passes were not replaced.

Cloud summaries are descriptive: repeated seeds, Sprites and execution periods are dependent, and neither cohort supports an independent population sample of passes. No cloud significance tests or confidence intervals are claimed.

### Workload and backend configurations

The benchmark compares blob storage, excluding the SQLite output-search index. All backends receive identical UUID keys and V2 MessagePack values and must support duplicate rejection, lookup, history deletion, oldest-first reclamation and graceful persistence.

| Backend | Configuration | Durability boundary / explicit compaction |
|---|---|---|
| Fjall | Reference options; LZ4; key/value separation; native background work | `persist(SyncAll)` and memtable materialization / native major compaction |
| redb | Uncompressed values; one transaction per capture; non-durable foreground writes | Immediate commit / native compaction |
| SQLite | Rowid table; unique binary UUID index; strict BLOB columns; 4 KiB pages; 8 MiB cache target; WAL with `synchronous=NORMAL` | Full WAL checkpoint / `VACUUM` then full checkpoint |

SQLite retains its native 1,000-page WAL auto-checkpoint, five-second busy timeout and 4 MiB journal-size retention hint, with no automatic vacuum or application compression. Busy or incomplete explicit checkpoints fail validation. These are complete backend configurations, not a compression-neutral comparison or exhaustive tuning search.

The year profile grows for **260 workdays × 300 commands/day**, trims to the newest **90 workdays**, then appends and evicts for another **90 workdays**. It generates 105,000 captures per backend, deletes approximately one command in 97 explicitly, and ends with 26,722 live records. Each backend has 18 checkpoints, including every 30 workdays and the materialization, trim, compaction and reopen phases. The disk budget is 51,038,912,512 bytes (47.53 GiB); five-second flush and 60-second GC timers include startup ticks, with GC trigger/target at 95%/90% of estimated live-storage budget.

The corpus contains 1,455 command samples and 1,325 distinct output files from six projects: median output 276 B, p95 12,128 B, maximum 114,491 B. Sampling with replacement reuses this finite corpus; it does not establish behavior for arbitrary large, binary or incompressible output, or exercise the 1,000,000-byte capture limit. Frozen files and hashes define the inputs; the manifest notes that the Atuin corpus build workspace differed from its recorded source revision. See the [methodology](../../README.md) for the activity mix.

### Measurement boundaries

- **Allocated bytes:** Filesystem-reported blocks for database files and directories, including journals, blobs and sparse-file effects; all storage tables use MiB (1,048,576 bytes)
- **Logical storage:** Serialized values plus 16 key bytes per live record; distinct from raw retained output and physical allocation
- **Checkpoints:** Gracefully stop maintenance, wait for I/O, persist, measure, reopen and verify every retained capture
- **Replay timing:** Simulated days do not advance wall-clock timers; rapid replay and repeated reopening limit sustained maintenance coverage
- **Compaction:** Each engine's native operation, not equivalent algorithms or a guarantee of minimum size

Calculations use exact bytes and round for display. Quartiles use linear interpolation and describe spread, not uncertainty. Checkpoints do not measure temporary compaction growth, active-write WAL peaks or continuously running daemon behavior.

## Retention and compaction

Selected lifecycle checkpoints below are pooled medians over the same 191 cloud passes, not paired transition estimates or true peaks.

| Checkpoint | Live records | Fjall MiB | redb MiB | SQLite MiB |
|---|---:|---:|---:|---:|
| Growth: day 30 | 8,907 | 13.418 | 48.020 | 35.207 |
| Growth: day 260 | 77,195 | 302.340 | 413.660 | 304.156 |
| Grown, materialized | 77,195 | 344.422 | 413.660 | 304.156 |
| Trimmed to 90 workdays | 26,721 | 381.922 | 413.707 | 304.156 |
| Churn: day 90 | 26,722 | 396.773 | 417.680 | 304.156 |
| Final materialized | 26,722 | 240.070 | 417.680 | 304.156 |
| Compacted | 26,722 | 105.633 | 143.922 | 105.766 |
| Reopened | 26,722 | 105.625 | 143.906 | 105.766 |

The first trim removes 50,474 records and reduces median raw output from 285.582 to 99.980 MiB. Physical allocation responds very differently:

| Engine | Median paired allocation change at trim | Median paired reduction at final compaction |
|---|---:|---:|
| Fjall | +37.117 MiB (+10.776%) | 133.496 MiB (55.995%) |
| redb | −0.426 MiB (−0.103%) | 271.867 MiB (65.441%) |
| SQLite | Unchanged | 200.680 MiB (65.337%) |

Fjall grows at the trim in all 191 passes; SQLite is unchanged in all 191. redb shrinks in 121, grows slightly in 68 and is unchanged in two. Separately pooled medians can move differently from the median paired change. Deleted data may leave reusable capacity rather than return filesystem space.

Final compaction shrinks all engines in every pass. Fjall also shrinks substantially during preceding materialization, which must not be credited to compaction. Equal record counts in different phases need not mean identical payloads.

The largest measured year checkpoints are **473.336 MiB for Fjall, 421.281 MiB for redb and 310.125 MiB for SQLite**. These are lower bounds on actual peak requirements. A fixed retention window is not a physical-space cap near payload size.

## Fixed-condition repeatability and layout evidence

In the broad round, SQLite's final allocation is constant within every seed, and redb's largest within-seed spread is 116 KiB. Fjall's seed-14 spread is 180.152 MiB. Most broad repetitions change Sprite or engine order, so the follow-up holds those conditions fixed.

Sprites 04 and 06 each completed 16 follow-up passes. FSR means Fjall → SQLite → redb; RSF reverses that order. Each repetition starts with fresh databases. Values are final Fjall allocated MiB.

| Sprite | Seed | Order | Rep 1 | Rep 2 | Rep 3 | Rep 4 |
|---|---:|---|---:|---:|---:|---:|
| 04 | 6 | FSR | 104.008 | 104.008 | 104.008 | 104.008 |
| 04 | 6 | RSF | 104.008 | 104.008 | 104.008 | 104.008 |
| 04 | 14 | FSR | 105.625 | 105.625 | 105.625 | 105.625 |
| 04 | 14 | RSF | 105.625 | 105.625 | 105.625 | 105.625 |
| 06 | 6 | FSR | 104.008 | 104.008 | 104.008 | 104.008 |
| 06 | 6 | RSF | 104.008 | 104.008 | 104.008 | 104.008 |
| 06 | 14 | FSR | 105.625 | **263.391** | 105.625 | 105.625 |
| 06 | 14 | RSF | 105.625 | **189.637** | 105.625 | 105.625 |

redb and SQLite remain constant within each seed across all 16 surviving passes: respectively **143.207 / 105.621 MiB** for seed 6 and **143.906 / 105.766 MiB** for seed 14.

The Fjall spreads within fixed conditions are **157.766 MiB for FSR** and **84.012 MiB for RSF**. This establishes execution-dependent variation, not a causal Sprite, order or time-period effect. Sprite 06 had no large layouts in the broad round, while Sprite 04 had several; neither is a reliable fixed machine label. Sprite identity also does not guarantee unchanged physical hardware.

All eight seed-14 passes on Sprite 06 report the same application-maintenance totals: one successful timer flush and 17 GC checks. Those counters do not expose internal Fjall scheduling, compaction or reclamation eligibility.

All **32 post-process-exit inventories exactly match** the reported reopened inventories. The smaller seed-14 layout has **three blob files**, versus **six** at 189.637 MiB and **eight** at 263.391 MiB. The excess survives process exit, but inventories alone cannot identify live versus obsolete values or determine whether further maintenance would reclaim it.

Four baseline databases and the 263.391 MiB database were retained; archive hashes and all five extracted inventories were verified. The retained seed-14 pair shares workload and Sprite but not order/repetition. Fixed-order evidence comes from the reports above. Use recorded remote allocation, not locally extracted block counts, for size comparisons.

## Local evidence: small stores and final year footprint

These results remain separate from the cloud cohorts: 20 seeds, one full-suite pass per seed, fixed order, compressed Btrfs.

### Small stores

Each scenario starts fresh, loads records, materializes, deletes the oldest half, refills, materializes again, compacts and reopens. Refill changes the payload. Values below are median allocated MiB.

| Records | Fjall initially materialized | redb initially materialized | SQLite initially materialized | Fjall final | redb final | SQLite final |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0.268 | 0.496 | 0.324 | 0.590 | 0.582 | 0.400 |
| 1,000 | 2.654 | 5.068 | 3.697 | 5.736 | 5.129 | 3.764 |
| 2,000 | 5.404 | 10.354 | 7.572 | 11.787 | 11.035 | 8.006 |
| 5,000 | 13.670 | 26.455 | 19.574 | 29.398 | 26.832 | 19.695 |

**Fjall is initially smallest in 79/80 comparisons; SQLite is finally smallest in 80/80.** These are four scenarios per seed, not 80 independent experiments. Explicit compaction increases Fjall's allocation in all 80 cases: median increases by size are 23.326%, 22.462%, 23.502% and 23.072%. Native compaction is not uniformly space-saving at every scale.

### Final year footprint

| Engine | Median MiB | Minimum–maximum MiB |
|---|---:|---:|
| Fjall | 186.697 | 101.477–194.426 |
| redb | 143.490 | 138.754–147.688 |
| SQLite | 105.570 | 101.453–109.020 |

SQLite finishes smaller than redb in **20/20** passes and smaller than Fjall in **16/20**; Fjall beats redb in **9/20**. The higher local Fjall median cannot be assigned to filesystem compression alone: platform, scheduling, order and scenario selection also differ. SQLite's final advantage over redb repeats across cohorts; Fjall's ranking is execution-dependent.

## Implications and next steps

The results support investigating SQLite as a predictable-space alternative, **not switching production backends on footprint alone**. Validation found no corruption or contract mismatch in recovered passes, but says nothing about unavailable attempts or power-loss safety. Zero budget evictions do not demonstrate a physical-space limit, and whole-pass runtimes are not controlled latency or throughput comparisons.

1. Inspect live and obsolete blob references, manifest state and reclamation eligibility in the retained Fjall databases
2. If needed, instrument internal flush, compaction and reclamation events in a separate diagnostic experiment, preserving the current binary and results as the baseline
3. Measure production-paced operation, peak allocation, maintenance cost and crash recovery before selecting a backend; test tight budgets separately because engine-specific eviction estimates can retain different records

Another broad replay matrix is unnecessary to establish the observed within-condition variation. Further runs should answer specific mechanism or coverage questions, not replace missing observations or be pooled indiscriminately with the selected follow-up.

## Sources and reproducibility

Measurement reports use format version 3; audit/statistics JSON files summarize passes. Artifact links refer to separately kept local archives and may be absent from a clean checkout without the result bundle. Report hashes, plans, corpus identity, configuration, expected logical data and inventories were checked; broad-round plan metadata was reconstructed from its deterministic schedule and matched to recovered remote plans. Transfer retries did not rerun benchmarks.

| Evidence | Source |
|---|---|
| Local 20-seed raw reports | [runs/seed-01.json](runs/seed-01.json) through [runs/seed-20.json](runs/seed-20.json) |
| Local build/filesystem metadata | [Series manifest](../../../../../../artifacts/output-store-20-seeds/series.json) |
| Broad schedule, reports and missing assignments | [Round manifest](../../../../../../artifacts/output-store-sprite-round/round.json), [audit with report paths/hashes](../../../../../../artifacts/output-store-sprite-round/audit.json), [missing assignments](../../../../../../artifacts/output-store-sprite-round/missing-jobs.json) |
| Follow-up values and timings | [Audit](../../../../../../artifacts/output-store-followup-recovery-20260922/audit.json), [Sprite 04 results](../../../../../../artifacts/output-store-followup-recovery-20260922/04/final/results/), [Sprite 06 results](../../../../../../artifacts/output-store-followup-recovery-20260922/06/final/results/) |
| Retained database verification | [Sprite 04 receipt](../../../../../../artifacts/output-store-followup-recovery-20260922/04/retained-verified.json), [Sprite 06 receipt](../../../../../../artifacts/output-store-followup-recovery-20260922/06/retained-verified.json) |
| Recomputed tables and source hashes | [Consolidated statistics](../../../../../../artifacts/output-store-followup-recovery-20260922/consolidated-statistics.json), generated by [consolidate.py](../../../../../../artifacts/output-store-followup-recovery-20260922/consolidate.py) |
| Workload, contract and phases | [Benchmark README](../../README.md) |

Build identities:

- **Local three-engine executable:** SHA-256 `5e45b2a704fdd703106fdacaee864fda44e7c1bac505c9fd45f5e5e705b2b092`
- **Both cloud cohorts, unchanged order-selectable executable:** SHA-256 `b3fa67f41c73b2ca183705c26ce92a141d4e947c1b2c01b74836563d029df2fb`
- **Source commits:** `09699f2a` (experimental SQLite backend) and `eb175f07` (order-selectable benchmark)
- **Build toolchain:** Rust/Cargo 1.95.0; `Cargo.lock` SHA-256 `d938d99822dbbf08e16ed50d0f1b9e62be524b70cc8470ee8a412778bb2ea0c7`

To reproduce a cloud-profile pass, select the intended source/build and frozen corpus, choose a new output directory and use the absolute budget:

```sh
cargo bench -p atuin-daemon --features output-store-bench --bench output_store -- \
	--output /tmp/atuin-output-store-seed-14-fsr \
	--corpus crates/atuin-daemon/benches/output_store/corpus \
	--seed 14 --engine-order fjall-sqlite-redb --scenarios year \
	--days 260 --commands-per-day 300 --retention-days 90 \
	--churn-days 90 --checkpoint-days 30 --max-disk-usage 51038912512
```

Use the preserved executable for exact binary replication; rebuilding need not reproduce its hash or timing. For cohort replication, reconstruct the assigned queue from its plan rather than repeating a convenient order. The local full suite additionally selects `sizes,year` with `--records 100,1000,2000,5000`. A seed reproduces the logical workload, not a guaranteed physical layout.
