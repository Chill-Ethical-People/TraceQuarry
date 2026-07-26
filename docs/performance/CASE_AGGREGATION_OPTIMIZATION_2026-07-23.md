# Case Aggregation Optimization

Date: 2026-07-23

## Objective

Reduce the long pause between completion of per-collection parsing and delivery
of combined case outputs without changing forensic records, findings, or
correlations.

## Workload

The end-to-end benchmark used 50 inert synthetic UAC-shaped archives:

- 5.15 GiB compressed
- 16.36 GiB expanded
- 57,270 regular members
- 359,785 normalized timeline events
- Four case workers
- Comprehensive assisted-investigation profile

The workload includes clean, ransomware, software-exploitation, APT-like,
credential-attack, and cryptomining scenarios. It contains no production
evidence or real identities.

## Optimizations

- Index finding-policy matches during the existing event-count pass instead of
  scanning the full timeline once per policy.
- Replace list-backed actor-evidence uniqueness checks with linear set-backed
  collection.
- Match all shared-tool literals in one regex pass per event instead of one
  complete event scan per tool.
- Sort only high-signal events when building the cross-host storyline.
- Reuse the already sorted, deduplicated case timeline when filtering duplicate
  collections.
- Defer event identity serialization unless an existing event-ID collision
  actually requires comparison.
- Write CSV and JSONL together while materializing each event dictionary once.

## Results

### Aggregation microbenchmark

| Stage | Before | After | Improvement |
| --- | ---: | ---: | ---: |
| Finding derivation, 49,121 events | 10.340 s | 0.197 s | 52.5x |
| Case correlations, 49,121 events | 3.164 s | 0.368 s | 8.6x |
| Sort/deduplicate/ID check, 49,121 events | 0.446 s | 0.103 s | 4.3x |
| Finding derivation, 359,785 events | Not separately captured | 1.041 s | n/a |
| Case correlations, 359,785 events | Not separately captured | 2.669 s | n/a |

### End-to-end 50-collection case

| Measurement | Before | After |
| --- | ---: | ---: |
| Total wall time | Approximately 20 min | 449.12 s (7 min 29 s) |
| Post-host case aggregation | Approximately 13 min | 23 s |
| Events | 359,785 | 359,785 |
| Findings | 86 | 86 |
| Correlations | 28 | 28 |
| Parser errors | 0 | 0 |

The end-to-end run is approximately 2.7 times faster. The post-host aggregation
pause is approximately 34 times shorter.

## Equivalence Checks

- Combined JSONL SHA-256: identical before and after
- Combined CSV SHA-256: identical before and after
- Findings: identical after deterministic sorting
- Storylines: identical after deterministic sorting
- Correlations: identical after deterministic sorting
- Focused optimization tests: 20 passed
- Full project tests: 100 passed, including 11 loopback web integration tests
- Ruff: passed for `uac_parser`, `tests`, and `tools`
- MyPy: no issues in 36 source files

## Remaining Cost

Archive decompression, evidence hashing, parser work, and per-host output
serialization now dominate total runtime. Additional gains should focus on
avoiding repeated archive reads between inspection and analysis, bounded
process-based parsing for CPU-heavy sources, and resumable per-collection
intermediate outputs.
