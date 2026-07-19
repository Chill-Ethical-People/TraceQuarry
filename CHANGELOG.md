# Changelog

All notable TraceQuarry changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) while it remains pre-1.0.

## [Unreleased]

### Added

- Enforced Ruff formatting and linting, strict MyPy checks, Bandit scanning,
  dependency auditing, and a 75% branch-coverage floor in CI and release workflows.
- Added Snyk Open Source CI testing, scheduled monitoring, and a dependency
  manifest consistency regression.
- Added verified full-history Gitleaks scanning and immutable commit pins for
  every GitHub Action used by CI and release workflows.
- Expanded post-public branch protection to require pull requests and all CI,
  Snyk, Gitleaks, CodeQL, and dependency-review checks.
- Regression coverage for tar traversal and archive-link handling.

### Changed

- Replaced archive extraction APIs with explicit regular-file streaming and
  canonical destination checks for tar and ZIP inputs.
- Replaced SHA-1 event and collection identifiers with SHA-256 identifiers.
- Added complete function annotations across the parser and web workbench.

### Security

- Archive links and non-regular tar members are no longer materialized.
- Repository hygiene rejects cloud-sync duplicate sidecars before release.
- Project dependency auditing and Snyk Open Source report no known
  vulnerabilities.

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

[Unreleased]: https://github.com/Chill-Ethical-People/TraceQuarry/compare/v0.4.0-beta.1...HEAD
[0.4.0-beta.1]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.4.0-beta.1
[0.3.1]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.3.1
[0.3.0]: https://github.com/Chill-Ethical-People/TraceQuarry/releases/tag/v0.3.0
