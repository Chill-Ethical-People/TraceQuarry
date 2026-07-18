# Changelog

All notable TraceQuarry changes are documented here. The project follows
[Semantic Versioning](https://semver.org/) while it remains pre-1.0.

## [Unreleased]

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

[Unreleased]: https://github.com/Chill-Ethical-People/tracequarry/compare/v0.4.0-beta.1...HEAD
[0.4.0-beta.1]: https://github.com/Chill-Ethical-People/tracequarry/releases/tag/v0.4.0-beta.1
[0.3.1]: https://github.com/Chill-Ethical-People/tracequarry/releases/tag/v0.3.1
[0.3.0]: https://github.com/Chill-Ethical-People/tracequarry/releases/tag/v0.3.0
