# Enterprise Deployment Baseline

TraceQuarry is a local-first forensic analysis service. Its supported enterprise
baseline is a hardened, single-node analysis workstation or case server reached
through an authenticated local session or SSH tunnel. The application itself
remains loopback-only and must not be exposed directly to a LAN or the Internet.

## Delivered Controls

- Serialized upload reservations prevent concurrent sessions from overcommitting
  the configured work-directory quota.
- Archive expansion scratch space is kept on the configured case/work volume and
  coordinated across concurrent parsers with a 512 MiB free-space reserve.
- Browser evidence is streamed per file, bounded by declared size, hashed with
  SHA-256, promoted atomically, and retained under mode `0600`.
- Upload expiry is enforced when a session is accessed and by a periodic
  maintenance worker.
- Case and job references are transactionally indexed in the private SQLite
  repository `state/cases.sqlite3`. Legacy `state/jobs/*.json` records are
  imported automatically, and completed outputs can rebuild missing records.
- Job lifecycle transitions are typed and validated. Repository updates carry a
  monotonic revision and support optimistic conflict detection so stale writers
  cannot silently replace newer state.
- One application context owns runtime settings, capacity reservations,
  concurrency slots, CSRF state, maintenance, and the Case Repository rather
  than scattering mutable service globals across request handlers.
- Active jobs are marked `interrupted` after an unclean restart. A completed
  output manifest takes precedence when processing finished before the final
  repository update was committed.
- Analyst annotation changes are recorded in a SHA-256 hash chain and can be
  verified through `/api/job/<job-id>/audit`.
- `/api/health` and `/api/ready` expose storage, reservations, service uptime,
  maintenance state, and job counts without returning evidence paths.
- `/api/jobs` exposes the latest public job states for local operations tooling.
- HTML, CSS, and JavaScript are packaged separately. Inline scripts are blocked
  by the browser Content Security Policy.
- JSON operational logging is available for ingestion into a local log forwarder.
- Every collection produces an experimental CaseWeave v1 producer-preview
  bundle with complete evidence inventory, dataset hashes, source locators or
  exact raw records, and non-authoritative timeline/finding candidates. The
  CaseWeave importer and end-to-end workflow remain pending CaseWeave's public
  release and are outside TraceQuarry's supported public-beta feature set.

## Recommended Start Command

```bash
tracequarry-web \
  --host 127.0.0.1 \
  --port 8765 \
  --work-dir /srv/tracequarry \
  --input-root /cases \
  --max-upload-gib 16 \
  --max-work-dir-gib 250 \
  --max-concurrent-jobs 2 \
  --case-workers 4 \
  --maintenance-interval 300 \
  --state-retention-days 90 \
  --request-timeout 3600 \
  --log-format json
```

Place `/srv/tracequarry` and `/cases` on encrypted storage. Run the process as a
dedicated unprivileged account and restrict both directories to that account.
Use server-side paths for large evidence sets so archives are not copied through
the browser or duplicated beneath the work directory.

## Operations

Probe readiness locally:

```bash
curl --fail --silent http://127.0.0.1:8765/api/ready
```

Inspect current capacity and job state:

```bash
curl --silent http://127.0.0.1:8765/api/health
curl --silent http://127.0.0.1:8765/api/jobs
```

Alert when readiness becomes `false`, free storage approaches the evidence
safety reserve, or queued/running jobs stop progressing. The service does not
delete completed case outputs automatically; include `outputs/` in the
organization's case-retention and secure-deletion procedure.

Back up case outputs only after an analysis job is complete. Preserve original
evidence separately and treat TraceQuarry timelines, findings, annotations, and
summaries as derived evidence. Completed case references can be reconstructed
from `outputs/`; back up `state/cases.sqlite3` with the service stopped or with a
SQLite-aware backup tool when interrupted-job history must also be preserved.

## Scale Guidance

For 50 to 150 collections, prefer newline-separated server paths and begin with
two to four case workers. Tune workers using measured archive expansion, event
count, memory pressure, and storage throughput rather than collection count
alone.

One web process is a single failure and scheduling domain. Run only one process
against a work directory. Multiple TraceQuarry processes must not share upload,
state, or output directories.

## Shared-Service Boundary

The current release is not yet a multi-tenant collaboration service. It does not
provide:

- Application-level SSO, user accounts, or role-based access control
- Per-case authorization or tenant isolation
- Distributed task queues, worker leases, or automatic job resume
- External object storage or a transactional shared database
- High availability or multi-node coordination
- Identity-attributed audit records anchored in an external immutable store
- Supported direct deployment behind a public reverse proxy

An organization needing those controls should keep TraceQuarry behind an
authenticated workstation or SSH boundary while exporting its structured
timelines into an established case platform or Timesketch. The next scale-out
architecture should separate the API, task broker, stateless parsing workers,
object storage, case database, and identity provider before enabling shared
network access.

## Release Gates

Before deploying a changed build:

1. Run repository hygiene, Ruff, MyPy, Bandit, web-resource validation, and
   JavaScript syntax checks.
2. Run the complete unit and integration suite with branch coverage at or above
   the configured threshold.
3. Build the wheel and verify that rules, assets, and web resources resolve from
   an installed environment.
4. Run Snyk, pip-audit, CodeQL, dependency review, and Gitleaks in CI.
5. Parse a clean fixture and a multi-collection synthetic case, then compare
   event counts, provenance, findings, parser errors, and output hashes against
   the approved baseline.
