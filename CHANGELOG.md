# Changelog

All notable TraceQuarry changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) while it remains pre-1.0.

## [Unreleased]

## [0.4.0-beta.2] - 2026-07-26

### Added

- Added a streamed Excel investigation workbook containing an executive
  briefing, analyst-selected chronology, normalized timeline, and findings.
- Added an executive briefing preview to the web console and XLSX export actions
  alongside the existing CSV workflow.
- Disabled formula and automatic hyperlink interpretation for workbook evidence
  strings.
- Added a canonical contributor-maintained YAML detection pack for tools, TTPs,
  malware/payload metadata, and non-attributive actor-similarity profiles.
- Added runtime YAML TTP and actor-profile evaluation, strict duplicate/schema
  validation, a `tracequarry-rules` validator, and rule-authoring guidance.
- Enforced Ruff formatting, linting, and complexity limits, strict MyPy checks,
  Bandit scanning, dependency auditing, and a 75% branch-coverage floor in CI
  and release workflows.
- Added Snyk Open Source CI testing, scheduled monitoring, and a dependency
  manifest consistency regression.
- Added verified full-history Gitleaks scanning and immutable commit pins for
  every GitHub Action used by CI and release workflows.
- Expanded post-public branch protection to require pull requests and all CI,
  Snyk, Gitleaks, CodeQL, and dependency-review checks.
- Regression coverage for tar traversal and archive-link handling.
- Added direct ingestion for copied Linux log directories and loose log files.
- Added bounded, read-only logical extraction for SQLite log databases, including
  extensionless Synology-style databases and lookup-table enrichment.
- Added review-ready timeline CSV export with separately stored analyst
  dispositions, guided investigation tags, notes, and update timestamps.
- Added persistent completed-case discovery and reopening in the web workbench.
- Replaced the native previous-case selector with a branded, keyboard-accessible
  case combobox that previews case type, completion time, and result counts.
- Added staged upload sessions for up to 1,000 browser-selected evidence files,
  bounded parallel transfer, per-file SHA-256 verification, retryable failures,
  and reuse between time-range inspection and analysis.
- Added an analyst-facing collection queue with upload and parser phase counts,
  per-collection progress, filtering, and the local staging path.
- Added asynchronous time-range inspection and bounded parallel case parsing via
  `--case-workers` for responsive high-collection-count workflows.
- Added serialized work-directory reservations, periodic upload retention,
  enforced session expiry, and restart recovery for unfinished reservations.
- Added durable local job-state records, interrupted-job recovery, health,
  readiness, and job-list operations endpoints.
- Replaced the process-global case index and per-job state files with a
  thread-safe SQLite Case Repository, including legacy JSON import, retention,
  private file permissions, manifest recovery, and crash-window reconciliation.
- Added structured JSON operational logging and an enterprise single-node
  deployment baseline.
- Added typed job lifecycle validation, monotonic repository revisions,
  optimistic conflict detection, and a centralized web application context.
- Added an experimental CaseWeave v1 producer preview with per-collection export
  bundles, complete evidence
  inventory, deterministic identities, exact source references, dataset hashes,
  candidate-only timeline/finding semantics, external package references, and
  auditable omission ledgers. Directory evidence is materialized as a
  deterministic source package for byte-level verification; durable custody
  IDs and typed non-regular member accounting preserve retry and package
  provenance.
- Added SHA-256 hash-chained analyst annotation auditing and a local chain
  verification endpoint.
- Added accessible drag-and-drop browser intake with additive selection,
  duplicate suppression, unsupported-file feedback, and selected-size totals.
- Added MITRE ATT&CK v19.1 phase enrichment with distinct confirmed and candidate
  tactic fields, phase filters, CSV fields, and summary distribution reporting.
- Added audited analyst promotion into a sparse reconstructed timeline, a
  `summary_selection` review-export column, and an interactive incident briefing
  with raw evidence and provenance.

### Changed

- Split web timeline review, analyst annotations, incident briefing, HTTP route
  dispatch, and streamed upload state transitions into focused components.
- Aligned the web and Excel executive briefings with TraceQuarry's night, moss,
  yuzu, ember, and warm-paper brand palette.
- Replaced archive extraction APIs with explicit regular-file streaming and
  canonical destination checks for tar and ZIP inputs.
- Replaced SHA-1 event and collection identifiers with SHA-256 identifiers.
- Added complete function annotations across the parser and web workbench.
- Improved small-screen workbench sizing so evidence and Live Run controls no
  longer force horizontal page overflow.
- Reduced large-case aggregation latency with one-pass finding and shared-tool
  indexing, linear actor-evidence deduplication, normalized timeline reuse, lazy
  event-ID collision checks, and single-pass CSV/JSONL materialization.
- Extracted the web interface into packaged HTML, CSS, and JavaScript resources
  and added CI validation for template integrity and JavaScript syntax.
- Replaced deprecated multipart `cgi` handling with bounded URL-encoded control
  requests backed by the streamed, hashed staging API.
- Account lifecycle summaries now count unique principals across corroborating
  records and no longer misclassify created groups as user accounts.
- Removed over-broad Masquerading and Defense Impairment mappings from generic
  temporary-path and executable-permission signals; multi-tactic techniques now
  require event context or remain phase candidates.

### Security

- Archive links and non-regular tar members are no longer materialized.
- Archive and loose-file scratch data now stays on the configured case volume;
  concurrent expansion is capacity-guarded with a 512 MiB free-space reserve.
- Repository hygiene rejects cloud-sync duplicate sidecars before release.
- Project dependency auditing and Snyk Open Source report no known
  vulnerabilities.
- Concurrent upload sessions can no longer overcommit the configured storage
  quota, and the browser policy no longer permits inline JavaScript.
- Dependabot pull requests no longer fail Snyk authentication when GitHub
  withholds Actions secrets; Dependency Review remains their security gate.
- Removed request-controlled values from CORS and download headers and from the
  investigation workbook temporary-file prefix.

## [0.4.0-beta.1] - 2026-07-18

### Added

- Public CI, installed-wheel validation, CodeQL, dependency review, Dependabot,
  release checksums, and CycloneDX SBOM generation.
- Packaged TraceQuarry and Chill Ethical People visual assets.
- A private vulnerability-reporting route.

### Changed

- Runtime rules and assets now resolve consistently from source checkouts and
  installed distributions.
- Packaging metadata now correctly advertises beta status and supported Python
  versions.

## [0.3.1] - 2026-07-18

### Security

- Restricted the web workbench to loopback access and added Host, Origin, and
  CSRF validation.
- Bound output access to completed jobs and blocked encoded traversal paths.
- Added restrictive evidence permissions, request and archive limits, public
  response redaction, and browser security headers.

## [0.3.0] - 2026-07-17

### Added

- Multi-collection case workspaces and cross-host correlation.
- Assisted investigation profiles and interactive timeline review.

[Unreleased]: https://github.com/Chill-Ethical-People/TraceQuarry/compare/v0.4.0-beta.2...HEAD
[0.4.0-beta.2]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.4.0-beta.1
[0.3.1]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.3.1
[0.3.0]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.3.0
