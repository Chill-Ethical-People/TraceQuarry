# Evidence And Output Guide

Read this reference when interpreting TraceQuarry output, validating a finding,
or integrating a timeline with another case platform.

## Review Order

| Priority | Output | Purpose |
|---|---|---|
| 1 | `run_manifest.json` / `case_manifest.json` | Verify inputs, settings, parser version, rule fingerprint, collection fingerprint, and derived-output hashes. |
| 2 | `source_index.json` / `case_source_index.json` | Measure discovered evidence, parser coverage, unsupported inputs, unmatched files, exclusions, and source hashes. |
| 3 | `parser_errors.log` / `case_parser_errors.log` | Identify failures and decide whether they invalidate an investigative conclusion. |
| 4 | `assisted_investigation.*` / `case_assisted_investigation.*` | Review profile-prioritized questions and evidence-readiness gaps. |
| 5 | `findings.json` / `case_findings.json` | Triage correlated leads and storylines. |
| 6 | `timeline_mini.*` / `case_timeline_mini.*` | Review the bounded incident window. |
| 7 | `timeline_full.*` / `case_timeline_full.*` | Expand context and identify precursors outside the selected window. |
| 8 | `ioc_hits.*` / `case_ioc_hits.*` | Scope supplied indicators across events and collections. |

Case workspaces also contain `hosts/<collection_id>/` with complete
per-collection output and `case_correlation.json` with structured cross-host
relationships. Preserve both levels for traceability.

## Timeline Schema 1.1

Use these fields when validating or exporting events:

- `event_id`: deterministic identifier within the output timeline.
- `related_event_ids`: events supporting a correlation or inference.
- `timestamp`, `timestamp_raw`, `timezone`: normalized UTC value and original
  evidence needed to reproduce it.
- `time_start`, `time_end`: observation interval when exact placement is not known.
- `timestamp_type`, `timestamp_precision`, `timestamp_confidence`,
  `timezone_confidence`: temporal semantics; do not sort beyond supported precision.
- `evidence_role`: `behavior`, `state_observation`, `context`, or `inference`.
- `host`, `collection_id`, `collection_name`, `collection_input`,
  `collection_host`: host and collection provenance for case correlation.
- `source_path`, `source_sha256`, `source_type`, `parser`, `parser_version`: source
  and transformation provenance.
- `event_category`, `event_action`, principal/network/process/file fields: the
  normalized event representation.
- `mitre`: behavior-supported ATT&CK mappings.
- `mitre_candidates`: ATT&CK hypotheses requiring analyst corroboration.
- `detection_names`, `ttp_flags`, `tags`: triage labels, not conclusions.
- `severity`, `confidence`: parser prioritization; reassess after raw validation.
- `summary`, `raw`, `extra`: normalized explanation, source content, and
  parser-specific context.

## Evidence Roles

**Behavior** records an action in a timestamped or event-bearing source, such as
an authentication result, audit execution, or web request.

**State observation** records what existed at acquisition time, such as a process,
network socket, authorized key, account entry, or persistence configuration. It
does not establish creation, execution, or installation time by itself.

**Context** provides configuration or historical context, such as SSH settings or
known-host entries. It narrows hypotheses but is not direct execution evidence.

**Inference** is produced by correlation, backup diffing, or timeline placement.
Validate its related events and assumptions before reporting it as fact.

## Coverage Semantics

- `parsed` means a parser accepted the source, not that every semantic event was
  recognized.
- `unsupported` means the format requires another parser or conversion path.
- `unmatched` means the file was inventoried but no source classifier selected it.
- `excluded` means TraceQuarry deliberately did not parse the item; review the
  reason before deciding it is irrelevant.
- A zero event count can mean no matching records, timestamp failure, format
  drift, truncation, or collection absence. Inspect the source and errors.
- Binary journal, login databases, proprietary agent stores, and encrypted or
  damaged archives may need native tooling. Record the gap and preserve the input.

## Case Correlation Semantics

Require explicit outbound evidence from one parsed host to another parsed host
before reporting lateral movement. Shared source IPs, usernames, tools, paths, or
time proximity support "shared activity observed" or "possible campaign-level
pattern" only. Retain per-host event IDs and collection provenance in every case
finding so another analyst can reproduce the relationship.

## Confidence Calibration

- **High**: direct raw evidence plus independent corroboration, with reliable time
  and identity/provenance.
- **Medium**: direct evidence with partial context, or a deterministic state/diff
  result whose time or actor remains uncertain.
- **Low**: heuristic match, string presence, ambiguous timestamp, weak provenance,
  or uncorroborated inference.

Parser-assigned confidence is a starting value. State the analyst's final
confidence and reasoning separately.
