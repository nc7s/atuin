# Output-store storage analysis: Fjall, redb and SQLite

## Executive summary

**SQLite has the most repeatable final footprint in these experiments and consistently finishes smaller than redb. Fjall is often slightly smaller than SQLite, but can retain substantially more space even when the workload seed, Sprite and engine order are unchanged.** No backend is the smallest throughout every workload phase.

- **Broad cloud replication:** 191 of 256 planned passes were recovered and validated, covering 16 seeds on ten Sprites. Final year-scale medians were **105.625 MiB for Fjall, 143.906 MiB for redb and 105.766 MiB for SQLite**. These pooled medians hide Fjall's much wider **101.504–285.777 MiB** range and the experiment's uneven coverage.
- **Paired cloud comparisons:** Fjall finished smaller than redb in **164/191** passes and smaller than SQLite in **106/191**. SQLite finished smaller than redb in **191/191**. Fjall's median paired advantage over SQLite was only **0.141 MiB**, while its largest paired disadvantage was **180.012 MiB**.
- **Controlled repeatability:** A separate follow-up recovered 32 of 48 planned passes. For seed 14 on Sprite 06, one fixed engine order produced **105.625, 263.391, 105.625 and 105.625 MiB** across four fresh-database repetitions. The reversed order also produced a large outlier. Seed and order differences alone cannot explain these results.
- **Layout evidence:** All 32 follow-up Fjall inventories matched after process exit. The larger seed-14 outcomes contained eight and six blob files, versus three in the smaller layout. Five retained databases, including a small and a large seed-14 database, were recovered and checksum-verified. This identifies a reclamation/layout investigation target, not a proven leak or root cause.
- **Useful local evidence:** The earlier 20-seed local series found Fjall smallest after initial materialization in 79 of 80 small-store comparisons, but SQLite smallest in all 80 final small-store comparisons. Its final year-scale results favored SQLite over redb consistently and over Fjall in 16/20 passes; those fixed-order, local-filesystem findings are kept separate from the cloud results.
- **Retention is not physical reclamation:** In every recovered broad-cloud pass, trimming roughly 65% of the year-scale live records increased Fjall's allocation. SQLite's allocation did not change at that trim, and redb's changed only slightly. Explicit final compaction reduced all three engines' year-scale footprints, but did not make Fjall's final layout deterministic.

All validated passes retained the expected logical data and reported zero maintenance errors and zero budget-driven GC evictions. These are clean-shutdown storage measurements under a nonbinding budget, not peak-space, throughput, tight-budget or crash-recovery results. Production still selects Fjall; the alternatives remain experimental and feature-gated.

## 1. Evidence and experimental design

A pass replays every selected scenario against each participating backend sequentially. A checkpoint is one backend's measured state; checkpoints within a pass are not independent replications.

| Cohort | Workload and ordering | Planned / validated passes | Validated snapshots | Role in this report |
|---|---|---:|---:|---|
| Initial local two-engine run | Seed 42; sizes and year; Fjall → redb | 1 / 1 | 100 | Historical baseline, superseded for ranking |
| Initial local three-engine run | Seed 42; sizes and year; Fjall → redb → SQLite | 1 / 1 | 150 | Illustrates the risk of single-run conclusions |
| Local seed series | Seeds 1–20; sizes and year; fixed Fjall → redb → SQLite order | 20 / 20 | 3,000 | Small-store evidence and conditional paired statistics |
| Sprite pilot | Seed 1; sizes and year; same fixed order | 1 / 1 | 150 | Deployment and runtime feasibility, not fleet calibration |
| Broad Sprite round | Seeds 1–16; year only; all six engine orders across ten Sprites | 256 / 191 | 10,314 | Main multi-seed replication, incomplete and unbalanced |
| Controlled Sprite follow-up | Seeds 6 and 14; year only; two reversed orders; four repetitions per seed × Sprite × order | 48 / 32 | 1,728 | Within-condition repeatability, complete on two of three assigned Sprites |

The local series ran sequentially on Btrfs with `compress=zstd:3`. Sprite benchmark paths were on overlayfs, with ext4 present in the underlying platform layout. Guest allocation is not provider physical storage or billable storage. CPU availability, I/O, caches and background work also differ. Local and cloud observations are therefore not pooled into one ranking or significance test.

The broad cloud schedule was fixed before execution. Each seed was assigned 16 passes spanning all ten Sprites; every pairwise backend precedence was balanced 8/8 within that seed. Each of the six complete orders occurred 42 or 43 times in the planned matrix. Recovered coverage no longer has that balance.

The follow-up was selected after examining the broad round: seed 14 had substantial variation, seed 6 was flat in the recovered observations, and Sprites 03, 04 and 06 offered contrasting earlier outcomes. Each Sprite received four shuffled complete blocks of the four seed/order combinations. This is an adaptive diagnostic cohort, not an additional random sample for the broad comparison.

## 2. Workload, configurations and measurement

### Shared application contract

The benchmark compares blob storage only, excluding the SQLite output-search index and its reconciliation. Every backend receives the same UUID keys and V2 MessagePack capture values, with atomic duplicate rejection, lookup, explicit history removal, oldest-first reclamation and graceful persistence. Matching checkpoints must retain identical logical data.

| Backend | Tested configuration | Explicit durability and maintenance |
|---|---|---|
| Fjall | Reference options, LZ4 compression, key/value separation and native background work | `persist(SyncAll)`; explicit memtable materialization and native major compaction |
| redb | Uncompressed values, one transaction per capture, no custom blob layer | Non-durable foreground writes followed by an immediate commit at the durability boundary; native compaction |
| SQLite | Ordinary rowid table plus unique binary UUID index; strict BLOB columns; 4 KiB pages; 8 MiB cache target; WAL with `synchronous=NORMAL` | Full WAL checkpoint at the durability boundary; `VACUUM` followed by full checkpoint for explicit compaction |

SQLite retains its native 1,000-page WAL auto-checkpoint, five-second busy timeout and 4 MiB journal-size retention hint; the hint is not an active-write hard limit. There is no automatic vacuum or application compression. Busy or incomplete explicit WAL checkpoints are errors. This compares complete backend configurations, not compression-neutral engine overhead or an exhaustive search of engine tuning options.

### Full year profile

| Parameter | Value |
|---|---|
| Growth | 260 workdays × 300 commands/day |
| Retention | Trim to the newest 90 workdays |
| Churn | 90 further workdays of append-and-evict activity |
| Captures generated per backend | 78,000 before retention; 105,000 overall |
| Explicit history deletions | Approximately one command in 97 |
| Live records | 77,195 before the first trim; 26,721 just after it; 26,722 at the end |
| Checkpoints | Every 30 workdays, plus materialization, trim, compaction and reopen phases; 18 per backend |
| Wall-clock maintenance | Five-second flushing and 60-second GC checks, with startup ticks |
| Resolved disk budget | 51,038,912,512 bytes, approximately 47.53 GiB |
| GC trigger / target | 95% / 90% of the engine-specific estimated live-storage budget |

The cloud runs omit only the independent small-store scenarios. They do not shorten the year profile or remove its checkpoints. Checkpoints close, measure, reopen and verify stores, so thinning them would change execution, not merely reporting frequency.

The corpus contains 1,455 recorded command samples and 1,325 distinct output files from six public projects. Median output length is 276 B, p95 is 12,128 B and the maximum is 114,491 B. Sampling follows the activity mix documented in the [benchmark methodology](../../README.md), rather than padding output to chosen sizes. The sampler uses replacement, so long replays reuse a finite set of outputs. No corpus output reaches the 1,000,000-byte capture limit. These runs do not establish behavior for arbitrary large, binary or incompressible output, or exercise capture truncation at that limit. The manifest records that the Atuin corpus build workspace differed from its recorded source revision; frozen files and hashes define the inputs.

### What the measurements mean

- **Raw output:** Retained start/end text before MessagePack serialization
- **Logical storage:** Serialized values plus 16 key bytes per live record
- **File bytes:** Apparent lengths of database files, including journals, tables, blobs and metadata
- **Allocated bytes:** Filesystem-reported blocks for files and directories, including sparse-file effects
- **Materialization:** Explicit flushing of Fjall memtables into tables/blob files; durable commit or WAL checkpoint for the alternatives
- **Compaction:** The backend's native explicit operation, not equivalent algorithms or a guarantee of minimum possible size

Unless stated otherwise, storage tables report allocated MiB, where one MiB is 1,048,576 bytes. Calculations use exact bytes; display values are rounded. Quartiles use linear interpolation and describe spread, not uncertainty in an estimated effect.

Every checkpoint gracefully stops application maintenance, waits for in-flight I/O and persists before measuring files, then reopens and verifies every retained capture. Playback also checks duplicate rejection, immediate lookup, idempotent history deletion and exact logical reclamation. Snapshot inventories are clean-shutdown observations, not continuously open-store or peak disk measurements. Simulated dates do not advance the wall clock: replay runs as fast as the machine allows, repeatedly resetting store lifetimes through checkpoints.

## 3. Broad cloud round: coverage and final allocation

### Completion and missingness

| Sprite | Valid / planned passes | Outcome | Median pass seconds | Large-layout passes |
|---|---:|---|---:|---:|
| 01 | 11 / 26 | Restart/interruption safeguard | 176.8 | 1 |
| 02 | 17 / 26 | Conservative compute guard | 270.4 | 1 |
| 03 | 19 / 26 | Conservative compute guard | 245.3 | 7 |
| 04 | 26 / 26 | Completed | 148.7 | 8 |
| 05 | 23 / 26 | Conservative compute guard | 201.7 | 2 |
| 06 | 25 / 26 | Conservative compute guard | 179.0 | 0 |
| 07 | 25 / 25 | Completed | 190.0 | 2 |
| 08 | 12 / 25 | Conservative compute guard | 390.2 | 3 |
| 09 | 17 / 25 | Conservative compute guard | 288.9 | 1 |
| 10 | 16 / 25 | Conservative compute guard | 300.8 | 3 |

There are **65 missing validated reports**. Only recoverable, completed, validated passes are included; interrupted attempts were not silently replaced. Worker 01's boot ID changed, but the reason for its restart is not established. Seven other workers stopped at conservative resource-cost guards, not because the benchmark's disk budget evicted data. Missingness is associated with worker speed and interruption; faster workers contribute more observations.

“Large layout” is an exploratory label: Fjall allocation more than 10 MiB above that seed's minimum in the broad recovered cohort. It identifies 28/191 passes and substantial variation in 14/16 seeds. It is not a preregistered endpoint, an absolute efficiency threshold or a population failure rate. A seed's minimum can itself be relatively large.

All six orders have recovered large layouts. Coverage and large-layout counts are: Fjall → SQLite → redb **30 / 4**; redb → SQLite → Fjall **32 / 5**; SQLite → Fjall → redb **32 / 2**; Fjall → redb → SQLite **35 / 4**; SQLite → redb → Fjall **30 / 6**; redb → Fjall → SQLite **32 / 7**. These unbalanced counts do not estimate causal order or Sprite effects.

### Pooled final year-scale allocation

The endpoint is `year/reopened`, after final materialization, explicit compaction and reopening. These are **descriptive summaries of 191 recovered passes**, not an equally weighted sample of seeds or machines.

| Engine | Median MiB | Q1–Q3 MiB | Minimum–maximum MiB | Mean MiB | Sample SD MiB |
|---|---:|---:|---:|---:|---:|
| Fjall | 105.625 | 103.707–135.668 | 101.504–285.777 | 125.896 | 45.125 |
| redb | 143.906 | 141.637–146.094 | 138.762–147.695 | 143.810 | 2.881 |
| SQLite | 105.766 | 104.098–107.445 | 101.461–109.027 | 105.621 | 2.210 |

The near equality of Fjall's and SQLite's medians does not imply similar predictability. Much of SQLite's pooled variation comes from different seeded workloads; its final allocation is identical within every seed. Fjall's large upper tail remains within fixed seeds.

### Paired final comparisons

Negative A−B means A is smaller. Every pair compares identical live data within the same pass; a median paired difference need not equal the difference of pooled medians.

| A−B | Median difference MiB | Minimum–maximum difference MiB | A smaller | B smaller |
|---|---:|---:|---:|---:|
| Fjall−redb | −38.031 | −41.656 to +141.973 | 164 | 27 |
| Fjall−SQLite | −0.141 | −2.594 to +180.012 | 106 | 85 |
| SQLite−redb | −38.406 | −39.754 to −37.039 | 191 | 0 |

There are no ties. Fjall's advantages over SQLite are small compared with its largest disadvantages. SQLite's final advantage over redb is consistent throughout this recovered cohort. Counts are not treated as 191 independent Bernoulli trials: seeds, Sprites, order and execution period recur, and coverage is incomplete. No cloud confidence intervals or significance tests are presented.

### Within-seed repeatability

All values below are final allocated MiB. Fjall's median equals its observed minimum at the displayed precision for every seed; the maxima expose variation that a median-only table would hide.

| Seed | Valid passes | Fjall min / median | Fjall max | redb min–max | SQLite, constant within seed |
|---:|---:|---:|---:|---:|---:|
| 1 | 12 | 138.227 | 261.594 | 145.906–145.906 | 107.500 |
| 2 | 11 | 102.949 | 280.754 | 138.820–138.887 | 101.746 |
| 3 | 12 | 105.488 | 189.594 | 145.945–145.945 | 107.027 |
| 4 | 9 | 107.684 | 193.484 | 147.262–147.262 | 107.859 |
| 5 | 13 | 102.852 | 280.734 | 138.762–138.762 | 101.461 |
| 6 | 9 | 104.008 | 104.008 | 143.207–143.207 | 105.621 |
| 7 | 13 | 103.605 | 258.504 | 141.637–141.637 | 104.203 |
| 8 | 11 | 108.020 | 266.383 | 146.180–146.262 | 107.391 |
| 9 | 14 | 101.504 | 256.992 | 141.137–141.137 | 104.098 |
| 10 | 10 | 106.102 | 191.730 | 143.633–143.633 | 105.535 |
| 11 | 13 | 139.180 | 263.629 | 147.695–147.695 | 109.027 |
| 12 | 12 | 104.207 | 189.500 | 141.637–141.637 | 104.398 |
| 13 | 13 | 103.707 | 262.730 | 142.273–142.387 | 103.848 |
| 14 | 12 | 105.625 | 285.777 | 143.906–143.906 | 105.766 |
| 15 | 13 | 104.410 | 280.867 | 146.059–146.121 | 106.367 |
| 16 | 14 | 106.320 | 106.320 | 147.406–147.406 | 108.504 |

redb's largest within-seed spread is 116 KiB; SQLite's is zero. Fjall's seed-14 spread is 180.152 MiB. This establishes that workload sampling alone is insufficient to explain Fjall's variation, but the broad round usually changes Sprite or order between repetitions. Only three recovered seed × Sprite × order cells have multiple observations, two each, and those pairs are stable. The controlled follow-up addresses that identification gap.

## 4. Broad cloud lifecycle: retention and compaction

The following are pooled checkpoint medians over the same 191 passes. They describe the observed lifecycle, not paired transition estimates or true peaks.

| Checkpoint | Live records | Fjall MiB | redb MiB | SQLite MiB |
|---|---:|---:|---:|---:|
| Growth: day 30 | 8,907 | 13.418 | 48.020 | 35.207 |
| Growth: day 90 | 26,721 | 84.465 | 143.484 | 105.422 |
| Growth: day 180 | 53,443 | 187.551 | 285.484 | 210.355 |
| Growth: day 260 | 77,195 | 302.340 | 413.660 | 304.156 |
| Grown, materialized | 77,195 | 344.422 | 413.660 | 304.156 |
| Trimmed to 90 workdays | 26,721 | 381.922 | 413.707 | 304.156 |
| Churn: day 30 | 26,722 | 377.141 | 416.121 | 304.156 |
| Churn: day 60 | 26,722 | 362.199 | 417.680 | 304.156 |
| Churn: day 90 | 26,722 | 396.773 | 417.680 | 304.156 |
| Final materialized | 26,722 | 240.070 | 417.680 | 304.156 |
| Compacted | 26,722 | 105.633 | 143.922 | 105.766 |
| Reopened | 26,722 | 105.625 | 143.906 | 105.766 |

Fjall's early-growth median is substantially smaller, but materialization exposes additional table/blob storage while journals can remain. By the grown-materialized checkpoint, SQLite has the smaller pooled median. Equal record counts across different phases need not mean identical payloads; only matching backend checkpoints within a pass have exactly matching retained data.

The initial trim removes 50,474 records, approximately 65% of the live set. Median raw output falls from 285.582 to 99.980 MiB, but filesystem allocation does not follow it promptly:

- **Fjall:** Allocation increases in all 191 passes; the median paired increase is 37.117 MiB, and the median paired percentage increase is 10.776%
- **redb:** Median paired change is −0.426 MiB, or −0.103%; 121 passes shrink, 68 grow slightly and two are unchanged
- **SQLite:** Allocation is unchanged in all 191 passes

The slightly increasing redb medians in the lifecycle table do not contradict its negative median paired trim effect: taking medians separately and taking the median of paired differences are different operations. Freed pages and deleted values can remain as reusable capacity rather than returned filesystem space.

Final compaction shrinks all three engines in every recovered cloud pass, measured from `final-materialized` to `compacted`:

| Engine | Median paired reduction MiB | Median paired reduction | Range of paired reductions |
|---|---:|---:|---:|
| Fjall | 133.496 | 55.995% | 26.207–71.736% |
| redb | 271.867 | 65.441% | 63.700–66.783% |
| SQLite | 200.680 | 65.337% | 63.971–66.886% |

Fjall also changes substantially during preceding materialization. That change must not be attributed to explicit compaction alone. Native operations and cleanup policies differ between engines, and final compaction does not eliminate Fjall's execution-dependent layout variation.

The largest measured year checkpoints across the broad cohort are **473.336 MiB for Fjall, 421.281 MiB for redb and 310.125 MiB for SQLite**. These are lower bounds on each cohort's actual peak requirements, not measurements of temporary compaction growth or write-time WAL peaks. A fixed logical retention window is not a physical-space cap near the payload size.

## 5. Controlled follow-up: fixed seed, Sprite and order

Sprites 04 and 06 each completed all 16 assigned passes. Sprite 03's follow-up directory and service disappeared after an observed boot change; no completed follow-up pass was recovered from it. The resulting 32-pass dataset is a complete balanced subset on the two surviving Sprites, not a completed three-Sprite experiment. No benchmark passes were rerun to replace the loss.

FSR means Fjall → SQLite → redb; RSF means redb → SQLite → Fjall. Each column below is the corresponding repetition/block, with fresh databases. Values are final Fjall allocation in MiB.

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

SQLite and redb have identical final allocation within each seed across all 16 surviving passes for that seed:

| Seed | redb MiB | SQLite MiB |
|---:|---:|---:|
| 6 | 143.207 | 105.621 |
| 14 | 143.906 | 105.766 |

### What this establishes

**Fjall varies within a fixed seed × Sprite × order cell.** The FSR spread is 157.766 MiB and the RSF spread is 84.012 MiB. The omitted Sprite 03 does not invalidate these within-condition contrasts; it limits third-Sprite coverage and generalization. Neither an estimate of cross-machine frequency nor a causal hardware effect follows from this selected subset. Logical Sprite identity also does not guarantee an unchanged underlying physical host across boots or experiments.

Sprite 06 had no large layouts in its 25 recovered broad-round passes but has two here. Conversely, Sprite 04 has none in this follow-up despite earlier large layouts. Earlier Sprite-level associations are not reliable fixed labels. The workloads represented by the two cohorts also differ, so this is not a controlled estimate of a change in machine behavior.

Both large outcomes occur in block 2, but that alone does not identify a time-period cause. For all eight seed-14 passes on Sprite 06, the reported Fjall application-maintenance totals are identical: one successful timer flush and 17 successful GC checks. Aggregate application counters do not expose internal Fjall compaction, reclamation eligibility or exact scheduling. Checkpoint timing logs record stdout arrival after the benchmark's measurement/reopen/verification sequence, not internal operation durations.

### Persistent layout evidence

All 32 post-process-exit Fjall inventories exactly match their reported reopened inventories, including filenames, apparent file lengths and allocation. The larger outcomes are therefore not explained by a discrepancy between that reported snapshot and the worker's subsequent post-exit measurement.

| Seed 14, Sprite 06 outcome | Final allocated MiB | Blob files |
|---|---:|---:|
| Smaller layout | 105.625 | 3 |
| RSF repetition 2 | 189.637 | 6 |
| FSR repetition 2 | 263.391 | 8 |

The extra blob files are a concrete investigation target. File inventories do not establish which values remain live, whether files are reclaimable under Fjall's policies, or whether another open/maintenance cycle would remove them. These observations do not prove unbounded growth or a storage leak.

Four baseline databases and the 263.391 MiB database were retained. Both archive hashes and all five extracted file inventories were verified. The retained seed-14 pair matches workload and Sprite, but its baseline is RSF repetition 1 and its large member is FSR repetition 2; it is not a same-order physical pair. The fixed-order comparisons above are supported independently by the validated reports. Local extracted block allocation must not replace the recorded remote measurements, because filesystem and sparse-file representation can differ.

## 6. Significant findings from the local rounds

### Twenty-seed final year comparison

The local series consists of one sequential full-suite pass per seed, seeds 1–20, on compressed Btrfs, with fixed Fjall → redb → SQLite order. Its variation combines workload and execution effects; it cannot separate them or estimate an order-independent backend effect.

| Engine | Median MiB | Q1–Q3 MiB | Minimum–maximum MiB |
|---|---:|---:|---:|
| Fjall | 186.697 | 107.157–189.826 | 101.477–194.426 |
| redb | 143.490 | 141.629–146.081 | 138.754–147.688 |
| SQLite | 105.570 | 104.169–107.386 | 101.453–109.020 |

For the local primary endpoint, `year/reopened`, the following paired statistics retain the seed/pass as the unit, **n = 20**, rather than treating 3,000 snapshots as independent observations. Negative A−B favors A.

| A−B | Median paired difference MiB | Median-effect interval MiB | A smaller / B smaller | Holm-adjusted sign-test p |
|---|---:|---:|---:|---:|
| Fjall−redb | +43.119 | −35.930 to +47.844 | 9 / 11 | 0.823803 |
| Fjall−SQLite | +81.758 | +1.371 to +85.164 | 4 / 16 | 0.023636 |
| SQLite−redb | −38.213 | −38.789 to −37.434 | 20 / 0 | 0.000005722 |

The tests are exact two-sided paired sign tests, excluding ties; there are none here. Holm adjustment covers these three primary comparisons only. Median-effect intervals use sorted paired differences 6–15 and have **at least 95.861% marginal coverage under an IID sampling model**; the coverage is 95.861% for a continuous distribution and can be conservative with ties. They are not simultaneous intervals, and IQRs in the preceding table are not confidence intervals.

These are conditional, model-based summaries of the local fixed-order experiment, not population claims about Atuin users or confirmation that the same ranking holds on cloud machines. The broad cloud round has a much smaller Fjall median and a larger maximum. That difference cannot be assigned to filesystem compression alone: platform, scheduling, order, scenario selection and execution coverage also differ. The reproducible result across cohorts is SQLite's final advantage over redb; Fjall's ordering is execution-dependent.

### Small-store lifecycle

The cloud cohorts did not repeat the independent 100-, 1,000-, 2,000- and 5,000-record scenarios. The 20-seed local series remains the strongest evidence for them. Each size starts fresh, loads records, materializes, deletes the oldest half, refills, materializes again, compacts and reopens. Refill changes the payload, so equal initial and final record counts do not imply the same output bytes.

The following are median allocated MiB across the 20 matched local passes:

| Records | Fjall initially materialized | redb initially materialized | SQLite initially materialized | Fjall final | redb final | SQLite final |
|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0.268 | 0.496 | 0.324 | 0.590 | 0.582 | 0.400 |
| 1,000 | 2.654 | 5.068 | 3.697 | 5.736 | 5.129 | 3.764 |
| 2,000 | 5.404 | 10.354 | 7.572 | 11.787 | 11.035 | 8.006 |
| 5,000 | 13.670 | 26.455 | 19.574 | 29.398 | 26.832 | 19.695 |

Fjall is smallest after initial materialization in 19/20 cases at 100 records and 20/20 at each larger size. SQLite is smallest at the final reopened checkpoint in 20/20 passes at every size. These are paired counts within each scenario, not 80 independent experiments.

Fjall's allocation increases during explicit compaction in all 80 small-store cases, measured from `final-materialized` to `compacted`. Median increases by size are 23.326%, 22.462%, 23.502% and 23.072%; individual increases range from 11.364% to 31.937%. This contrasts with the consistently shrinking year-scale compactions and remains a useful warning: native compaction is not uniformly space-saving at every scale.

### What single runs and the pilot still contribute

The original two-engine seed-42 run ended at 187.305 MiB for Fjall and 140.938 MiB for redb. The later three-engine seed-42 run ended at 103.363 MiB for Fjall, 140.938 MiB for redb and 104.648 MiB for SQLite. These are different executable runs, not a controlled test of adding SQLite. Their changed ordering reinforces why a single replay is inadequate for ranking Fjall's final footprint.

The cloud pilot successfully validated the full three-engine suite using the original local executable and corpus, with 191.161 seconds of process elapsed time. It established deployment feasibility, not a reliable fleet runtime or spending model: broad-round worker medians subsequently ranged from 148.7 to 390.2 seconds even with the small-store scenarios omitted.

## 7. Maintenance, validation and operational limits

Successful application-maintenance counters sum over the recorded checkpoint intervals. Caller-driven persistence, explicit modeled retention and native engine background operations are not these counters.

| Cohort | Engine | Timer flushes | GC checks | GC-evicted logical bytes | Maintenance errors |
|---|---|---:|---:|---:|---:|
| Local 20 seeds | Fjall | 100 | 900 | 0 | 0 |
| Local 20 seeds | redb | 99 | 900 | 0 | 0 |
| Local 20 seeds | SQLite | 134 | 900 | 0 | 0 |
| Broad cloud, 191 passes | Fjall | 338 | 3,247 | 0 | 0 |
| Broad cloud, 191 passes | redb | 221 | 3,247 | 0 | 0 |
| Broad cloud, 191 passes | SQLite | 1,528 | 3,247 | 0 | 0 |
| Follow-up, 32 passes | Fjall | 31 | 544 | 0 | 0 |
| Follow-up, 32 passes | redb | 32 | 544 | 0 | 0 |
| Follow-up, 32 passes | SQLite | 195 | 544 | 0 | 0 |

Counts include startup ticks and do not distinguish them from later periodic ticks. Maintenance is enabled, but rapid replay and frequent closing/reopening limit sustained wall-clock coverage. Different flush counts are not a measurement of durability quality or backend throughput.

Archive/report hashes, assigned plans, corpus identity, configuration, expected seeded logical data and snapshot inventories were checked. The broad round's damaged local plan metadata was reconstructed from its deterministic schedule and matched against every recovered remote plan. The follow-up's final report archives also match its individually recovered report hashes. Large retained-database transfers were accepted only after full archive checksum verification. Transfer retries did not rerun benchmarks.

No corruption or contract mismatch was found in the validated snapshots. That does not verify unavailable attempts or constitute a process-kill/power-loss test. Backend tests separately exercise functional contracts and tight-budget eviction, but the equal-data replay deliberately fails if budget-driven eviction occurs.

The main limits are:

- **Incomplete and selected coverage:** 65 broad-round reports and all 16 assignments on the third follow-up Sprite are missing; the diagnostic cohort was selected after observing earlier outcomes
- **Dependent observations:** Seeds, Sprites and periods recur; checkpoint counts and pooled pass counts do not supply independent population sample sizes
- **Configuration and platform dependence:** Compression, schema, native storage policy, filesystem allocation and host conditions differ; a Sprite name is not a guarantee of dedicated hardware
- **Finite replay model:** Recorded outputs are reused; activity mix, output sizes and checkpoint cadence are not an empirical distribution of all users' workloads
- **Nonbinding budget:** Zero budget evictions do not demonstrate enforcement of a physical-space limit; live-storage estimates and physical allocation are different quantities
- **Checkpoint-only space:** Temporary peaks, active WALs, continuous-daemon behavior and minimum achievable layouts are not established
- **Incomplete operational comparison:** Whole-pass times and diagnostic resource samples exist, but there is no controlled per-operation latency, throughput, write-amplification or crash-recovery comparison

### Resource-accounting caveat

The broad workers used $1.10 conservative guest-resource guards each, counting reported full RAM plus guest CPU. Services reported approximately 15.62 GiB, whereas the interactive pilot inspection showed 8 GiB. The sum of last recorded broad-round guards is about $10.159, with incomplete accounting around the interrupted worker. The two completed follow-up workers recorded $0.5591 and $0.7124, totaling $1.2715, before subsequent collection costs. These are not provider invoices, exclude additional setup/collection/storage and do not reconcile the overall $15 allocation. Cost-guard exits must not be misread as storage-budget failures.

## 8. Conclusions and next investigation

**The main diagnostic result is established:** Fjall can finish with substantially different layouts under identical seeded input, Sprite identity and engine order. It often achieves a slightly smaller final footprint than SQLite, but its larger outcomes dominate the difference in predictability. SQLite repeatedly finishes smaller than redb and has no within-seed final-allocation variation in either recovered cloud cohort. This supports investigating SQLite as a predictable-space alternative, not changing the production backend on space measurements alone.

Earlier findings that remain useful are Fjall's initial small-store advantage, SQLite's final small-store advantage, the weak relationship between deletion and immediate physical reclamation, and the workload-dependent effects of explicit compaction. The larger rounds replace a single-run final ranking with evidence about both paired footprint and execution variability.

The highest-value next steps are:

1. Inspect live versus obsolete blob references, manifest state and reclamation eligibility in the retained Fjall databases; distinguish persistent policy choices from delayed cleanup or a defect
2. If needed, instrument Fjall's internal flush/compaction/reclamation events in a separate diagnostic experiment, retaining the current binary and observations as the baseline
3. Measure production-paced operation, peak allocation, maintenance cost and crash recovery before a backend-selection decision; test tight budgets separately because engine-specific eviction estimates can retain different records

Another broad replay matrix is not required to establish the observed within-condition variation. Additional runs would serve specific coverage or mechanism questions, and should not silently replace failed observations or be pooled with this adaptive follow-up.

## 9. Sources and reproducibility

The main measurement files use report format version 3. Cohort audit/statistics JSON files are summaries, not individual passes. Artifact paths below are repository-relative local archives kept separately from source; they may not be present in a clean checkout unless the result bundle is supplied.

| Evidence | Source |
|---|---|
| Local 20-seed raw reports | [runs/seed-01.json](runs/seed-01.json) through [runs/seed-20.json](runs/seed-20.json) |
| Local execution/build/filesystem metadata | [Series manifest](../../../../../../artifacts/output-store-20-seeds/series.json) |
| Initial three-engine seed-42 report | [Raw report](../../../../../../artifacts/output-store-three-backends/report.json) |
| Sprite pilot | [Raw report](../../../../../../artifacts/output-store-sprite-pilot/report.json) and [process metrics](../../../../../../artifacts/output-store-sprite-pilot/metrics.json) |
| Broad planned schedule and recovered reports | [Round manifest](../../../../../../artifacts/output-store-sprite-round/round.json), [audit with report paths/hashes](../../../../../../artifacts/output-store-sprite-round/audit.json), [missing assignments](../../../../../../artifacts/output-store-sprite-round/missing-jobs.json) |
| Follow-up cells, individual values and timings | [Audit](../../../../../../artifacts/output-store-followup-recovery-20260922/audit.json), [Sprite 04 final results](../../../../../../artifacts/output-store-followup-recovery-20260922/04/final/results/), [Sprite 06 final results](../../../../../../artifacts/output-store-followup-recovery-20260922/06/final/results/) |
| Retained database verification | [Sprite 04 receipt](../../../../../../artifacts/output-store-followup-recovery-20260922/04/retained-verified.json), [Sprite 06 receipt](../../../../../../artifacts/output-store-followup-recovery-20260922/06/retained-verified.json) |
| Recomputed broad/local tables and source hashes | [Consolidated statistics](../../../../../../artifacts/output-store-followup-recovery-20260922/consolidated-statistics.json), generated by [consolidate.py](../../../../../../artifacts/output-store-followup-recovery-20260922/consolidate.py) |
| Workload, contract and phase definitions | [Benchmark README](../../README.md) |

The local three-engine series and pilot used executable SHA-256 `5e45b2a704fdd703106fdacaee864fda44e7c1bac505c9fd45f5e5e705b2b092`. Both cloud cohorts used the unchanged order-selectable executable SHA-256 `b3fa67f41c73b2ca183705c26ce92a141d4e947c1b2c01b74836563d029df2fb`. Source commits `09699f2a` and `eb175f07` record the experimental SQLite backend and order-selectable benchmark. The actual builds used Rust/Cargo 1.95.0; recorded `Cargo.lock` SHA-256 is `d938d99822dbbf08e16ed50d0f1b9e62be524b70cc8470ee8a412778bb2ea0c7`.

To reproduce a cloud-profile pass from the workspace root, select the intended source/build and frozen corpus, choose a new output directory, and pass the absolute budget rather than recomputing a filesystem percentage:

```sh
cargo bench -p atuin-daemon --features output-store-bench --bench output_store -- \
  --output /tmp/atuin-output-store-seed-14-fsr \
  --corpus crates/atuin-daemon/benches/output_store/corpus \
  --seed 14 --engine-order fjall-sqlite-redb --scenarios year \
  --days 260 --commands-per-day 300 --retention-days 90 \
  --churn-days 90 --checkpoint-days 30 --max-disk-usage 51038912512
```

Use the preserved executable for exact binary replication; a rebuild need not have the same hash or timing. Reconstruct the assigned queue from its plan for cohort replication, rather than repeatedly running a convenient order. The full local suite additionally selects `sizes,year` with `--records 100,1000,2000,5000`. Original paths in JSON identify run locations, not mandatory destinations. The recorded seed reproduces the logical workload, not a guaranteed physical database layout.
