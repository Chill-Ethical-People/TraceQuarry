# High-Volume Browser Upload UAT - 2026-07-23

## Result

TraceQuarry completed a browser-driven case containing 150 synthetic UAC
archives through the staged upload API and two-worker case pipeline.

| Measure | Result |
|---|---:|
| Selected archives | 150 |
| Compressed input size | 70,988 bytes |
| Synthetic auth records | 450 |
| Upload and SHA-256 staging | 1.952 seconds |
| Analysis after job acceptance | 5.408 seconds |
| Per-collection output directories | 150 |
| Combined timeline events | 450 |
| Parser errors | 0 |
| Derived output size | 4,008,866 bytes |

The completed case contained `case_timeline_full.csv/jsonl`, findings,
correlations, source index, summary, parser error log, case manifest, and 150
per-collection output directories.

## Workflow Checks

- The browser rendered 150 pending rows in a bounded, filterable queue.
- Four upload workers transferred separate files concurrently.
- Every file was staged beneath one visible relative work-directory path.
- The server retained the original filename inside an isolated numbered
  subdirectory, preventing name collisions without changing host inference.
- The queue exposed pending, uploading, staged, parsing, complete, and failed
  counts plus per-collection progress.
- The final state was 150 complete and zero pending, parsing, or failed.
- Desktop and 390-pixel mobile layouts had no horizontal page overflow.
- Browser console inspection reported no JavaScript errors.
- Existing HTTP security and parser regression tests remained green.

## Interpretation

This run validates collection count, staging behavior, state transitions, output
creation, and queue usability. It does not establish a universal 150-collection
runtime because the archives were deliberately tiny. Real performance is driven
primarily by expanded evidence size, parsed event count, line length, source
mix, IoC volume, storage throughput, and available memory.

Use the broader [capacity baseline](LOAD_TEST_2026-07-21.md) for event-volume and
collection-count guidance. Large real-world cases should begin with one active
analysis job and two case workers, then increase concurrency only after observing
resource use on the analysis host.
