# TraceQuarry Production Preview

TraceQuarry Production Preview is suitable for controlled production use by
DFIR analysts processing copied Linux evidence on an isolated workstation or
forensic lab host. It is production-capable within the boundary below; it is not
an Internet-facing or multi-tenant incident-management service.

## Supported Boundary

- Single-user or trusted-team operation on Linux, macOS, Windows, or the
  hardened Docker Compose deployment.
- UAC collections, copied Linux log trees, individual or compressed Linux logs,
  and supported read-only SQLite forensic data.
- Single-collection and multi-collection case workspaces, UTC-normalized
  timelines, source coverage, IoC matching, ATT&CK context, findings, analyst
  annotations, summaries, and investigation exports.
- Local case persistence with documented backup and data-preserving uninstall
  behavior.
- CLI and loopback-only web workflows. Remote use requires an authenticated
  tunnel or access layer that preserves TraceQuarry's local security boundary.

## Analyst Responsibilities

- Preserve and hash the original evidence independently of TraceQuarry.
- Record the selected year, timezone, incident window, IoCs, tool version, and
  parsing options in the case record.
- Review `source_index.json` and `parser_errors.log` before relying on coverage.
- Validate material findings against raw records and surrounding events.
- Treat ATT&CK mappings, profile similarity, and automated findings as
  investigative context rather than attribution or final conclusions.
- Back up the case repository and output directory to encrypted case storage.

## Not Yet Supported

- Direct exposure of the web application to a LAN or the Internet.
- Native authentication, RBAC, multi-tenancy, centralized collaboration, or
  high-availability clustering.
- Automatic threat-actor attribution or autonomous incident conclusions.
- A supported end-to-end CaseWeave workflow; current bundles remain a developer
  preview for contract testing.
- Guaranteed parsing of every Linux distribution, vendor database, custom log
  format, or future UAC artifact without validation.

## Release Confidence

The Production Preview baseline has passed interactive browser and CLI UAT,
single- and multi-collection workflows, container persistence and backup tests,
cross-platform installer checks, 152 automated tests plus one subtest, and an
85% coverage gate. CI validates Python 3.11 and 3.12, CodeQL, Gitleaks, Snyk
Open Source, Snyk Container, packaging, and the hardened container runtime.

Report security issues through the private process in [`SECURITY.md`](../SECURITY.md).
Report reproducible parser or usability issues through the project issue
tracker without attaching real evidence, credentials, or customer data.
