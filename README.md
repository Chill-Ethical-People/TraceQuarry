# TraceQuarry

<p align="center">
  <img src="assets/tracequarry-favicon.svg" width="168" alt="TraceQuarry layered timeline mark">
</p>
<p align="center">
  <a href="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/ci.yml"><img src="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/codeql.yml"><img src="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/codeql.yml/badge.svg" alt="CodeQL status"></a>
  <a href="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/snyk.yml"><img src="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/snyk.yml/badge.svg" alt="Snyk Open Source status"></a>
  <a href="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/secret-scan.yml"><img src="https://github.com/Chill-Ethical-People/TraceQuarry/actions/workflows/secret-scan.yml/badge.svg" alt="Gitleaks secret scan status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-5C7F67.svg" alt="Apache-2.0 license"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg" alt="Python 3.11 and 3.12"></a>
</p>

> **Public beta 0.4.0-beta.2:** an open-source Linux DFIR timeline parser for
> UAC collections, native Linux logs, and supported SQLite forensic data.
> Read the [0.4.0-beta.2 release notes](docs/releases/v0.4.0-beta.2.md).

TraceQuarry is a local-first Linux digital forensics and incident response
(DFIR) workbench. It converts
[Unix-like Artifacts Collector (UAC)](https://github.com/tclahr/uac) archives,
copied `/var/log` trees, compressed or rotated Linux logs, and supported SQLite
databases into normalized forensic timelines, source coverage indexes, IoC
matches, MITRE ATT&CK context, and evidence-backed findings.

Tagline: **Excavate the timeline. Preserve the proof.**

## What Is TraceQuarry?

TraceQuarry helps incident responders reconstruct activity on Linux systems
without sending evidence to a hosted service. It preserves raw log context and
source provenance while organizing authentication, execution, persistence,
privilege escalation, credential access, discovery, lateral movement,
exfiltration, and impact signals into analyst-reviewable outputs.

| Area | Public beta capability |
| --- | --- |
| Product category | Open-source Linux forensic timeline parser and DFIR triage workbench |
| Evidence inputs | UAC archives and directories, copied Linux logs, compressed rotations, and supported SQLite databases |
| Investigation outputs | CSV and JSONL timelines, findings, IoC hits, source coverage, incident summaries, and XLSX briefing workbooks |
| Analysis | Assisted investigation profiles, MITRE ATT&CK phase tagging, tool/TTP enrichment, and cross-collection correlation |
| Interfaces | Command-line interface and loopback-only local web GUI |
| Evidence privacy | Local processing; no external evidence upload is required |
| Release status | Public beta for responder testing and feedback |

## Public Beta Highlights

- Build one defensible UTC-normalized timeline from a UAC collection or loose
  Linux evidence while retaining raw records, source paths, hashes, timestamp
  confidence, and collection provenance.
- Combine multiple collections into a case workspace with per-host outputs,
  cross-host correlation, case summaries, and bounded parallel parsing.
- Review and tag evidence interactively, promote pivotal events into a concise
  reconstructed chronology, and export CSV, JSONL, Markdown, or an investigation
  workbook with an executive briefing.
- Stage large browser cases with per-file hashing, retryable uploads, queue
  filters, and visible pending, uploading, parsing, completed, and failed states.
- Extend community detection coverage through versioned YAML registries for
  tools, malware and payload signals, TTPs, ATT&CK phases, and non-attributive
  actor-profile similarity.

## Coming Next: CaseWeave Integration

TraceQuarry and CaseWeave are being designed to connect forensic collection
triage with collaborative incident reconstruction. The intended workflow will
let TraceQuarry hand evidence-backed timeline and finding candidates to
CaseWeave while preserving package hashes, collection custody, source locators,
omission accounting, and the boundary between automated suggestions and analyst
decisions.

The current TraceQuarry build emits an **experimental developer-preview bundle**
for contract testing. The CaseWeave importer and end-to-end user integration are
pending their own public release and are not part of TraceQuarry's supported
public-beta workflow yet. Follow the project for the full integration.

## Relationship To UAC

UAC is the upstream collection project; TraceQuarry is an independent downstream
parser and analysis workbench maintained by Chill Ethical People. TraceQuarry is
not affiliated with, maintained by, certified by, or endorsed by the UAC project.
It does not bundle, modify, or redistribute UAC. The UAC name is used only to
describe input compatibility and to credit the collection format that makes this
workflow possible.

TraceQuarry compatibility is based on recognized artifact paths and output
formats rather than a formal UAC compatibility certification. Report collection
failures and missing upstream artifacts to UAC only when they are reproducible in
UAC itself. Report parsing, normalization, enrichment, timeline, and TraceQuarry
GUI issues in the [TraceQuarry issue tracker](https://github.com/Chill-Ethical-People/TraceQuarry/issues).
Never attach real incident collections or sensitive evidence to a public issue.

TraceQuarry can also process an extracted directory, archive, individual Linux
log, compressed rotation, or supported SQLite database even when it was not
produced by UAC. Generic evidence intake is filename- and format-driven;
arbitrary source mappings remain outside the public-beta interface.

## Guided Walkthrough

<p align="center">
  <a href="docs/media/tracequarry-walkthrough-v0.4.0-beta.2.webm">
    <img src="docs/media/tracequarry-walkthrough-v0.4.0-beta.2.gif" width="960" alt="TraceQuarry v0.4.0-beta.2 guided walkthrough showing multi-collection Linux evidence intake, assisted investigation, per-collection progress, ATT&CK briefing, raw evidence review, analyst annotation, and export">
  </a>
</p>

This 60-second cursor-driven walkthrough uses two bundled synthetic collections.
It demonstrates multi-archive intake, case metadata, assisted-investigation
selection, evidence-range inspection, incident IoCs, per-collection Live Run
status, summary review, the ATT&CK-aware incident briefing, raw-record validation,
analyst promotion into the reconstructed chronology, and investigation export.
All displayed hosts, indicators, and activity are synthetic. Select the preview
to open the
[full-resolution WebM video](docs/media/tracequarry-walkthrough-v0.4.0-beta.2.webm).

## Why Analysts Use TraceQuarry

Linux UAC collections contain rich evidence, but the useful signals are spread
across auth logs, audit logs, shell history, account files, persistence
locations, package logs, process snapshots, network state, and filesystem
metadata. TraceQuarry brings those sources into one normalized timeline while
preserving source paths and raw-line context for defensible review.

Use it to move quickly from “we have a UAC archive” to a responder-ready view of
access, privilege activity, persistence, suspicious tooling, IoC hits, and the
incident window that deserves deeper validation.

## DFIR Use Case

Use TraceQuarry when you need to rapidly scope a Linux host collected with UAC
and answer responder questions such as:

- When did suspicious access begin and end?
- Which source IPs authenticated, failed authentication, or brute-forced SSH?
- Did a failed-login campaign turn into a successful root or user login?
- Were persistence mechanisms added through cron, systemd, PAM, shell profiles,
  rc.local, init.d, or SSH authorized keys?
- Were sudoers, UID 0 accounts, privileged groups, SUID/SGID files, or Linux
  capabilities abused?
- Were passwords changed, accounts unlocked, users added, or privileged group
  memberships modified?
- Were credential files, SSH keys, cloud metadata, kube configs, or password
  material accessed?
- Were common attacker tools such as `rclone`, `anydesk`, tunneling tools,
  miners, archive utilities, or cloud/container CLIs present in the evidence?
- Can a smaller incident-window timeline be produced for review, reporting, or
  handoff to another analyst?

TraceQuarry is a triage and timeline-assist tool. Findings are leads, not final
conclusions. Validate important findings against raw source lines and surrounding
timeline context before using them in a report.

## Agent Skill For DFIR Teams

TraceQuarry includes a community-ready Agent Skill in
[`skills/tracequarry/`](skills/tracequarry/).
It teaches a compatible coding agent how to establish case scope, run single- or
multi-collection analysis, interpret timeline schema `1.1`, validate findings
against raw evidence, and prepare a defensible responder deliverable. Detailed
output semantics and investigative pivots use progressive references under
[`skills/tracequarry/references/`](skills/tracequarry/references/), while
[`agents/openai.yaml`](skills/tracequarry/agents/openai.yaml)
provides the branded Codex skill metadata.

### Install In Codex

From a trusted local clone, expose the repository as a global Codex skill:

```bash
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
ln -s "$PWD/skills/tracequarry" \
  "${CODEX_HOME:-$HOME/.codex}/skills/tracequarry"
```

Alternatively, agents supported by the community `skills` CLI can install it
directly from GitHub:

```bash
npx --yes skills@latest add Chill-Ethical-People/TraceQuarry \
  --global --agent codex --skill tracequarry --yes
```

Install TraceQuarry's Python environment separately as described below, start a
new agent session, and invoke the skill as `$tracequarry`. This command runs the
community `skills` installer through `npx`; TraceQuarry does not require or
publish a separate npm package.

### Install In ChatGPT

Download `tracequarry-skill.zip` from a TraceQuarry GitHub release. In ChatGPT,
open **Plugins**, select the **Skills** tab, choose **Create**, then **Upload from
your computer**. See OpenAI's [Skills in ChatGPT guide](https://help.openai.com/en/articles/20001066-skills-in-chatgpt)
for current availability and workspace controls. Workspace administrators can
instead share or publish the skill through the workspace Skills library.

Review community skills before enabling them, keep installations updated through
normal source-control or workspace review, and never place case evidence inside
the skill or repository directory. OpenAI Skills follow the portable
[Agent Skills format](https://agentskills.io), but installation locations and
workspace permissions vary by product.

## Evidence Handling

Recommended responder handling:

- Work from a copied UAC archive, not the original evidence master.
- Record the original archive name, size, hash, collection host, collection time,
  analyst, and timezone assumption in your case notes.
- Keep output directories case-scoped, for example `out/<case>/<hostname>/`.
- Treat parser output as derived evidence and preserve the command line or GUI
  settings used to generate it.
- Do not push real UAC archives, extracted evidence, or generated parser outputs
  to a shared repository.

TraceQuarry is local-first by design. The parser does not need to upload evidence
to external services.

The GUI is deliberately loopback-only. Do not expose it directly on a LAN or the
Internet. For access from another workstation, use an authenticated SSH tunnel
that terminates on the analysis host. TraceQuarry creates new work directories
with mode `0700` and derived evidence with mode `0600`; use a case-specific,
encrypted volume when the collection contains sensitive material.

## Quick Start For A Case

1. Inspect the archive time range.

```bash
cd TraceQuarry
python3 -m uac_parser.web --host 127.0.0.1 --port 8765 \
  --work-dir web_runs \
  --input-root /cases
```

Open `http://127.0.0.1:8765`, choose either **Archive upload** or **Server
path**, select the log year and timezone, then click **Inspect Time Range**. For
a hypothesis-led review, select an **Assisted investigation** profile before
starting the analysis.

2. Run a first-pass parse with a broad window.

```bash
python3 -m uac_parser.cli /cases/uac-host01.tar.gz --out out/host01-first-pass \
  --incident-start 2026-04-01T00:00:00+08:00 \
  --incident-end 2026-06-16T23:59:59+08:00 \
  --year 2026 \
  --timezone Asia/Hong_Kong \
  --threat-type ransomware_extortion \
  --ioc 198.51.100.50 \
  --ioc rclone \
  --ioc anydesk
```

3. Review `summary.md`, `findings.json`, and `timeline_mini.csv`.

4. Re-run with a narrower window once the compromise period is understood.

5. Export or attach the CSV/JSONL timelines, findings, source coverage, and exact
   command line to the case record.

## Assisted Investigation

Assisted investigation applies an analyst-selected hypothesis to the completed
timeline. It prioritizes relevant findings, checks whether important artifact
groups are present, identifies supported and unresolved investigation questions,
and recommends the next pivots. It does not filter the full timeline, change raw
evidence, prove the selected threat type, identify malware, or attribute an actor.

Available profiles:

- `comprehensive`: broad compromise triage when the intrusion pattern is unknown
- `ransomware_extortion`: access, staging, exfiltration, impact, and cleanup
- `public_facing_exploitation`: exploit-like requests through payload execution and persistence
- `credential_compromise`: authentication, secrets, account changes, sudo, and remote access
- `persistence_backdoor`: PAM, loader, systemd, cron, SSH-key, and account persistence
- `cryptomining_resource_hijacking`: miners, pools, persistence, cloud, and container abuse
- `apt_like_intrusion`: valid accounts, credentials, layered persistence, tunneling, and cross-host access

An assisted run adds `assisted_investigation.md` and
`assisted_investigation.json`. Case mode adds
`case_assisted_investigation.md` and `case_assisted_investigation.json`. The
selected profile and generated output hashes are preserved in the run manifest.

Completed GUI jobs also provide **Explore Timeline**. The evidence explorer
pages through the incident-window or full JSONL timeline, supports text,
severity, source-type, ATT&CK phase, and analyst-summary filtering, and displays
the original raw record with host and collection provenance. Analyst
dispositions, tags, notes, and summary selections are saved
to `analyst_annotations.json`; they never modify the parser timeline or source
evidence. Every annotation change is also written to the SHA-256 hash-chained
`analyst_audit.jsonl`; `/api/job/<job-id>/audit` verifies its current chain
status. Guided tags cover lateral movement, persistence, execution,
exfiltration, credential harvesting, and discovery/reconnaissance.

Use **Include in reconstructed summary** sparingly to promote a pivotal,
raw-validated event into the consultant's concise chronology. This binary review
decision appears as `Summary` in the exported `summary_selection` column. It does
not overwrite the event's descriptive `summary` field or remove unselected
evidence. **Incident Briefing** orders the selected records by UTC time and keeps
the event ID, source path, source SHA-256, raw excerpt, analyst note, and ATT&CK
phase visible. **Export Timeline CSV** can export the full review set or only the
selected summary chronology. **Export Investigation XLSX** creates a review
workbook with these linked sheets:

- `Executive Briefing`: incident milestones, key metrics, observed actions,
  exfiltration/impact/account callouts, ATT&CK distribution, legal-review note,
  and an evidence-qualified executive summary.
- `Selected Timeline`: the analyst-promoted chronology with raw evidence and
  provenance.
- `Timeline` (and additional numbered sheets above Excel's row limit): the
  normalized timeline and analyst columns.
- `Findings`: parser findings with severity, confidence, tags, IoCs, and related
  event IDs.

The same executive briefing is previewed in the GUI before export. Spreadsheet
formula and automatic hyperlink interpretation are disabled for evidence values.

## Choosing Time Settings

Linux auth, cron, syslog, and package logs often use syslog-style timestamps that
omit a year. TraceQuarry needs a year and timezone to normalize those records to
UTC.

- Use `--year` for the year to apply to yearless logs.
- Use `--timezone` for the host-local timezone at the time of collection.
- Use timezone-aware incident windows when possible, for example
  `2026-06-16T09:58:00+08:00`.
- Confirm the normalized UTC output against known business events, EDR alerts,
  firewall logs, VPN logs, or SIEM data.

For chronological syslog-style files that cross December into January,
TraceQuarry detects the rollover and assigns the pre-rollover records to the
previous year. The selected `--year` remains the anchor year after rollover.
Explicit dates embedded only in filenames are not treated as event timestamps;
review rotated filenames and raw records before finalizing the incident window.

State artifacts without native timestamps may receive `correlated_*` timestamps
when bodyfile or auditd PATH records support timeline placement. Untimestamped
state is retained with an acquisition observation interval when a UAC collection
timestamp can be derived from the input name.

## Output Review Order

For incident response, review outputs in this order:

1. `parser_errors.log`
   Confirm that critical sources did not fail to parse. An empty file is ideal.

2. `source_index.json`
   Check the complete evidence inventory and parser coverage. Every non-metadata
   file is hashed and marked parsed, partially parsed, unsupported, unmatched,
   or failed. Confirm whether auth logs, audit logs, shell history, login history,
   process state, network state, account files, sudoers, cron, systemd, PAM, SSH
   keys, and bodyfile data were present.

3. `summary.md`
   Read the responder summary for high-level findings, ATT&CK phase distribution,
   lateral movement notes, account lifecycle changes, brute-force summaries, and
   storylines.

4. `findings.json`
   Treat this as the queue of high-signal leads. Pivot each important finding to
   the raw source line, source file, timestamp type, user, process, command, and
   related events.

5. `timeline_mini.csv`
   Use this as the main analyst timeline for the suspected incident window.
   Filter by `severity`, `event_category`, `event_action`, `user`, `src_ip`,
   `process`, `command`, `attack_phases`, `mitre`, and `source_path`.

6. `timeline_full.csv`
   Use this when the mini timeline shows suspicious activity at the edge of the
   selected window, or when you need to discover earlier staging, password
   changes, account creation, or persistence.

7. `ioc_hits.csv`
   Use this to scope known IPs, domains, hashes, paths, usernames, and tool names.
   High-volume IoC hits should be grouped by action, user, source file, and
   first/last seen before reporting.

## Output Contract

TraceQuarry writes the following files into the selected output directory:

- `timeline_full.jsonl`: all parsed events
- `timeline_full.csv`: spreadsheet-friendly full timeline
- `timeline_mini.jsonl`: incident-window events when a start or end time is set
- `timeline_mini.csv`: spreadsheet-friendly mini timeline
- `findings.json`: correlated detections and storylines
- `ioc_hits.json` and `ioc_hits.csv`: IoC matches when IoCs are supplied
- `summary.md`: human-readable investigation summary
- `source_index.json`: complete evidence inventory, source hashes, parser status,
  unsupported formats, unmatched files, input verification, and parse coverage
- `parser_errors.log`: non-fatal parser errors for analyst review
- `analyst_annotations.json` and `analyst_audit.jsonl`: GUI review state and its
  ordered, hash-chained local audit history
- `run_manifest.json`: input identity, source hashes, parser coverage, rule fingerprint,
  complete-collection fingerprint, input integrity verification, execution
  settings, and output hashes for reproducibility
- `assisted_investigation.md` and `.json`: hypothesis-led priorities, readiness,
  checklist status, evidence references, guardrails, and analyst pivots when a
  threat profile was selected
- `caseweave_import_bundle.zip`: an experimental CaseWeave developer-preview
  handoff containing
  normalized events plus evidence-backed timeline and finding candidates; it
  never represents producer output as an analyst confirmation. The bundle also
  carries content-derived IDs, external source-package references, and a hashed
  omission ledger for records that cannot meet the exchange provenance contract
- `caseweave_source_package.tar`: experimental deterministic source package for
  validating external member references in the preview contract
- `caseweave_custody.json`: experimental durable custody identities used to
  validate retries and distinct byte-identical acquisitions

For multi-collection case workspaces, TraceQuarry also writes:

- `hosts/<collection_id>/`: normal per-collection outputs for each UAC input
- `case_timeline_full.jsonl` and `case_timeline_full.csv`: merged case timeline
- `case_timeline_mini.jsonl` and `case_timeline_mini.csv`: merged incident-window timeline
- `case_findings.json`: case findings, storylines, and correlations
- `case_correlation.json`: structured cross-collection correlation data
- `case_ioc_hits.json` and `case_ioc_hits.csv`: case-level IoC matches
- `case_summary.md`: case-level summary for the GUI preview and reporting handoff
- `case_assisted_investigation.md` and `.json`: case-level hypothesis-led review
- `case_source_index.json`: per-collection source coverage and provenance
- `case_parser_errors.log`: parser errors grouped by collection
- `case_manifest.json`: case-level collection identity, settings, rules, and output hashes
- `caseweave_exports.json`: index of the per-collection CaseWeave bundles under
  portable relative `hosts/<collection_id>/caseweave_import_bundle.zip` paths

These CaseWeave files are contract-validation previews, not a released
end-to-end integration. The planned provenance rules, candidate/analyst trust
boundary, and import workflow are documented in
[`docs/CASEWEAVE_INTEGRATION.md`](docs/CASEWEAVE_INTEGRATION.md).

## CLI Usage

```bash
tracequarry /cases/uac-host01.tar.gz --out out/host01 \
  --incident-start 2026-06-16T08:00:00Z \
  --incident-end 2026-06-16T12:00:00Z \
  --year 2026 \
  --timezone UTC \
  --host host01 \
  --threat-type credential_compromise \
  --ioc 198.51.100.50 \
  --ioc rclone \
  --ioc-file known_iocs.csv
```

Multi-collection case workspace:

```bash
tracequarry --case-out out/case-acme-linux \
  --case-name "ACME Linux Intrusion" \
  --case-reference IR-2026-0711 \
  --case-workers 2 \
  --input /cases/uac-host01.tar.gz \
  --input /cases/uac-host02.tar.gz \
  --incident-start 2026-06-16T08:00:00Z \
  --incident-end 2026-06-16T12:00:00Z \
  --year 2026 \
  --timezone UTC \
  --threat-type apt_like_intrusion \
  --ioc 198.51.100.50 \
  --ioc rclone
```

Case mode can also read a manifest:

```bash
tracequarry --case-out out/case-acme-linux \
  --input-manifest case-inputs.txt \
  --case-workers 2 \
  --year 2026 \
  --timezone Asia/Hong_Kong
```

Installed console scripts:

- `tracequarry`
- `tracequarry-web`
- `uac-timeline`
- `uac-timeline-web`

IoC files accept either one value per line or CSV rows in this shape:

```text
value,kind,label
198.51.100.50,ip,known scanner
rclone,literal,exfiltration tooling
anydesk,literal,remote access tooling
/tmp/kworker,path,suspicious staging path
```

Accepted IoC kinds include `ip`, `domain`, `hash`, `path`, and `literal`.

## Web GUI Usage

The web GUI reuses the same parser pipeline as the CLI. It is useful when an
analyst wants to preview the time range, upload an archive from a browser, or let
another responder run the parser without building a command line.

```bash
python3 -m uac_parser.web --host 127.0.0.1 --port 8765 --work-dir web_runs
```

The GUI defaults to an 8 GiB upload-session limit, a 40 GiB work-directory
quota, two concurrent analysis slots, two collection workers per case, and a
30-minute per-request timeout. Adjust these for a dedicated analysis workstation
without removing the disk safety margin:

```bash
python3 -m uac_parser.web --host 127.0.0.1 --port 8765 --work-dir web_runs \
  --input-root /cases \
  --max-upload-gib 8 --max-work-dir-gib 40 \
  --max-concurrent-jobs 1 --case-workers 2 --request-timeout 1800 \
  --maintenance-interval 300 --state-retention-days 90
```

Server-side paths are accepted only beneath an allowed evidence root. Repeat
`--input-root` to approve multiple roots; when omitted, TraceQuarry allows only
the directory from which the GUI was launched. Browser uploads remain isolated
under the configured work directory.

### Large Browser Cases

For 50 to 150 or more browser-selected collections, drag the archives onto the
evidence drop zone or use **Browse files**. Additional drops are added to the
current selection and exact duplicates are skipped. TraceQuarry creates a staged
upload session instead of sending every archive in one multipart request. Four
files upload concurrently, each file is SHA-256 verified, and **Inspect Time
Range** and **Start Analysis** reuse the same staged evidence. Interrupted or
failed files can be retried without re-uploading files already marked **Staged**.

The **Live Run** collection queue shows pending, uploading, staged, parsing,
complete, and failed counts. Filter the table to find one collection and review
its current parser stage. The queue also displays a path such as
`uploads/staged-<session-id>`; resolve it beneath the configured `--work-dir` to
inspect the local staged files. Stale unclaimed sessions expire after seven days,
are rejected on access, and are removed by periodic maintenance.

For a large case, run one analysis job at a time and begin with two case workers.
Increase `--case-workers` only after observing available RAM, CPU, storage, and
event volume. Collection count alone is not a capacity estimate: one archive
with millions of records can cost more than many small archives.

Open `http://127.0.0.1:8765`, then:

1. Choose **Archive upload**, then drop or browse for `.tar.gz`, `.tgz`, `.tar`,
   or `.zip` UAC outputs, loose rotated logs, or SQLite databases. Select
   multiple inputs to create a case workspace.
2. Choose **Server path** for an archive, copied `/var/log` directory, loose log,
   or SQLite database already present on the analysis machine. Enter one path per
   line to create a case workspace.
3. Set log year and timezone.
4. Optionally enter a **Case reference** for the experimental CaseWeave export
   preview.
5. Click **Inspect Time Range**.
6. Set or refine the incident start and incident end.
7. Add known IoCs.
8. Run analysis, review or tag events, and export the investigation workbook or
   annotated timeline CSV.
9. Use **Previous cases** to reopen completed outputs from the configured work
   directory, including after restarting the local server.

If both upload and server path are filled, the selected source mode controls
which input is used.

When more than one input is provided, the Live Run panel shows upload and parser
status for each collection, collection and correlation counts, opens the case
summary preview, and links both case-level outputs and per-collection host
summaries.

The browser API uses a per-process request token and rejects non-loopback Host
and Origin values. Restarting the server invalidates open GUI pages and request
tokens; reload the page. Completed outputs are reconstructed from manifests and
remain available under **Previous cases** while they remain inside the same
work directory. Case and job references are transactionally indexed in
`web_runs/state/cases.sqlite3`; lifecycle transitions are validated and each
record carries a monotonic revision for conflict detection. Timelines, findings,
manifests, annotations, and
other derived evidence remain under `web_runs/outputs/<job-id>/`. Legacy
`state/jobs/*.json` records are imported automatically. Jobs interrupted by a
restart are retained as interrupted operational records rather than silently
disappearing, while completed output manifests can rebuild a missing index.

Local operators can query `/api/health`, `/api/ready`, and `/api/jobs`. Use
`--log-format json` for structured service logs. The supported hardened
single-node deployment model, retention controls, scale guidance, and explicit
shared-service limitations are documented in
[`docs/ENTERPRISE_DEPLOYMENT.md`](docs/ENTERPRISE_DEPLOYMENT.md).

## Direct Logs And SQLite

TraceQuarry accepts a UAC archive, an extracted collection, a copied Linux log
directory such as `host01/var/log`, or a single loose log. Plain text and gzip,
bzip2, and xz rotations are decoded by content. When using the GUI, the copied
evidence directory must be beneath a configured `--input-root`.

```bash
python3 -m uac_parser.cli /cases/host01/var/log --out out/host01-logs \
  --year 2026 --timezone UTC
```

SQLite databases are recognized from the `SQLite format 3` file signature, so
extensionless Synology files such as `.SYNOCONNDB` and `.SYNOSYSLOGDB` can be
ingested. TraceQuarry opens the database read-only and immutable, inventories
tables, normalizes rows with usable timestamp columns, and preserves each
extracted record in the raw timeline field. Extraction is bounded to 256 tables,
100,000 rows per table, 250,000 rows per database, 128 columns, and a 4 GiB
database file.

This is logical SQLite extraction, not deleted-record recovery. Uncheckpointed
WAL content is not merged, rows without usable timestamps are counted but not
expanded into timeline events, and unfamiliar schemas may require a dedicated
adapter. Preserve the original database and its `-wal` and `-shm` sidecars for
specialist examination.

## Capacity Baseline

The bounded synthetic capacity test on an 8-core Apple M3 system with 16 GB RAM
completed a 100,000-event archive and a 500-collection, 50,000-event case
workspace. For an interactive workflow on comparable hardware, start with a
50,000-event ceiling and run unusually large jobs one at a time. Output volume,
event mix, IoC count, and free disk can lower the practical limit.

Native ESXi logs are not currently parsed. TraceQuarry can inventory and hash
unmatched ESXi evidence, but `vmkernel.log`, `hostd.log`, `vpxa.log`,
`vobd.log`, and `fdm.log` require dedicated adapters before they can contribute
timeline events or findings. See the
[capacity test report](docs/performance/LOAD_TEST_2026-07-21.md) for measured
results, methodology, caveats, and reproduction instructions. The separate
[high-volume browser UAT](docs/performance/HIGH_VOLUME_UPLOAD_UAT_2026-07-23.md)
documents the staged 150-archive workflow and its narrower interpretation.

## Detection Coverage

Current coverage is tuned for Linux intrusion triage:

- Evidence handling: plain text plus gzip, bzip2, and xz compressed rotations;
  direct copied log directories, loose log files, and bounded read-only SQLite
  log extraction;
  native systemd journal and wtmp/btmp/lastlog databases remain inventoried as
  explicit unsupported sources instead of disappearing from coverage

- Authentication: SSH brute force, invalid users, successful login after repeated
  failures, root logins, login-history exports, account lock/unlock events, and
  password changes
- Execution: shell history commands, download-execute chains, staged execution
  from `/tmp`, `/var/tmp`, `/dev/shm`, and `/run`, reverse-shell-like syntax, and
  process-list signals
- Persistence: cron, systemd, journalctl text exports, rc.local, init.d, shell
  profiles, SSH authorized-key state, LD_PRELOAD, and PAM backdoor candidates
- Privilege escalation: UID 0 anomalies, sudoers risks, NOPASSWD entries,
  privileged group membership, SUID/SGID files, Linux capabilities, Docker/LXD
  group risk, and account backup diffing
- Credential access: SSH key access, credential file access, weak hash
  identification, plaintext password leakage in history, and shadow timestamp
  extraction. Normal local-password-hash presence is retained as state, not
  reported as credential dumping.
- Lateral movement: outbound SSH, SCP, rsync, network probes, and explicit
  negative findings when coverage is sufficient. `known_hosts` remains historical
  context and does not establish lateral movement.
- Exfiltration and tooling: `rclone`, cloud CLIs, archive utilities, database
  dumps, tunneling tools, miners, destructive commands, and ransomware-impact
  indicators
- Audit and account lifecycle: auditd account events, passwd/shadow/group backup
  comparisons, created/deleted/modified accounts, password changes, account
  unlocks, and privileged group additions

Actor-relevant matches are tradecraft hints only. Do not report them as
attribution without independent threat intelligence.

Timeline schema `1.2` separates `evidence_role` (`behavior`,
`state_observation`, `context`, or `inference`), confirmed behavioral `mitre`
mappings, and `mitre_candidates` that still require corroboration.
`attack_phases` contains tactics derived from confirmed mappings when the
technique has one tactic or the event context disambiguates a multi-tactic
technique. `attack_phase_candidates` retains ambiguous and state-derived tactic
possibilities. Events also retain source SHA-256, parser version, timestamp
precision/confidence, and observation intervals for integration with enterprise
timeline platforms.

Tool, TTP, malware/payload metadata, and non-attributive actor-similarity
profiles are consolidated in `rules/tagging_registry.yml`. Tool and TTP rules
enrich events at runtime; actor profiles prioritize combinations of observed
signals without claiming attribution. The registry hash is preserved in the run
manifest so analysts can identify the exact detection content used for a case.
Technique-to-tactic mappings are independently versioned in
`rules/attack_phases.yml`, pinned to MITRE ATT&CK v19.1, validated with the same
rules command, and fingerprinted in each run manifest.

Community additions are welcome. See the [detection-pack contribution guide](rules/README.md)
and validate changes before submitting them:

```bash
PYTHONPATH=. python3 -m uac_parser.rules_cli
```

## Evidence Readiness

The GUI's **Inspect Time Range** action also reports evidence readiness across
authentication, audit, command history, network state, process state, account,
persistence, and filesystem classes. A missing class is a coverage gap, not a
negative finding.

TraceQuarry only reports that no lateral-movement evidence was observed when
command history, network state, and SSH host-history evidence are available.
Otherwise the assessment is marked inconclusive and lists the missing sources.

## Finding Validation Playbook

For every high-impact finding:

1. Locate the source event in `timeline_mini.csv` or `timeline_full.csv`.
2. Open the original `source_path` from the extracted UAC content when available.
3. Capture the raw line, preceding lines, and following lines.
4. Confirm timestamp type: native log time, bodyfile time, audit time, or
   correlated timestamp.
5. Check whether the command was executed by an attacker, an administrator, an
   EDR/AV process, or a defensive grep/search command.
6. Correlate with SSH, sudo, process, network, account, persistence, and file
   timeline events within the same window.
7. Record confidence and uncertainty in the case notes.

Special caution: TraceQuarry attempts to avoid treating suspicious strings inside
defensive `grep` or `rg` indicator-search commands as confirmed payload
execution. Analysts should still verify context before writing conclusions.

## Reporting Guidance

Suggested language for defensible reporting:

- “TraceQuarry parsed the UAC collection and generated a normalized timeline.”
- “The finding indicates evidence consistent with...”
- “The source line was observed in `<source_path>` at `<timestamp>`.”
- “The timestamp was normalized using timezone `<timezone>` and log year
  `<year>`.”
- “This is a tradecraft similarity, not attribution.”
- “No evidence of outbound lateral movement was identified in the parsed sources”
  only when source coverage supports that statement.

Avoid overclaiming:

- Do not state that an action occurred if it only appeared inside a search,
  comment, detection rule, or scanner output.
- Do not state that no activity occurred if the relevant source was absent.
- Do not attribute to a named actor from TTP overlap alone.

## Frequently Asked Questions

### Does TraceQuarry require a UAC collection?

No. UAC is the primary collection format, but TraceQuarry also accepts copied
Linux log directories, individual recognizable logs, compressed rotations, and
supported SQLite log databases.

### Does TraceQuarry upload forensic evidence to the cloud?

No. TraceQuarry is local-first and does not require external evidence upload.
The web interface binds to loopback and is intended for a trusted analysis host.

### Is TraceQuarry an EDR, SIEM, or replacement for forensic validation?

No. It is a triage, timeline reconstruction, and evidence-review workbench.
Findings and actor-profile similarities are investigative leads that must be
validated against raw evidence and other incident data.

### Can TraceQuarry combine multiple Linux collections?

Yes. Case workspace mode preserves per-collection outputs and builds a merged
timeline, case findings, IoC results, and conservative cross-host correlations.

### Does TraceQuarry support MITRE ATT&CK tagging?

Yes. It distinguishes context-supported ATT&CK mappings from candidate mappings
that still require corroboration and includes tactic-phase fields in timeline
and reporting outputs.

### Is the CaseWeave integration available now?

Not as a supported end-to-end feature. TraceQuarry currently emits a developer
preview of the exchange bundle while the CaseWeave importer and collaborative
workflow await their own public release.

## Install

TraceQuarry supports Python 3.11 and 3.12. PyYAML is used to validate and load
the external detection registry.

```bash
git clone https://github.com/Chill-Ethical-People/TraceQuarry.git
cd TraceQuarry
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

### Ubuntu With `uv`

The following commands install an isolated Python 3.12 runtime without writing
packages into Ubuntu's system-managed Python environment:

```bash
sudo apt update
sudo apt install -y git
sudo snap install astral-uv --classic

git clone https://github.com/Chill-Ethical-People/TraceQuarry.git
cd TraceQuarry
uv python install 3.12
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install .
```

Start the loopback-only GUI:

```bash
python -m uac_parser.web \
  --host 127.0.0.1 \
  --port 8765 \
  --work-dir web_runs \
  --input-root "$PWD"
```

Open `http://127.0.0.1:8765`. To select copied evidence elsewhere, add its
parent directory as another `--input-root`. Do not work around an
`externally-managed-environment` message with `sudo pip`; confirm that
`which python` points inside `TraceQuarry/.venv/bin` and use `uv pip install .`.

You can also run it directly from the repository root with `PYTHONPATH`:

```bash
cd TraceQuarry
PYTHONPATH=. python3 -m uac_parser.cli tests/fixtures/uac_sample --out /tmp/tracequarry-sample
```

## License And Ownership

TraceQuarry is released under the Apache License, Version 2.0. You can use,
modify, and redistribute the software under that license. Kensho is the creator,
original copyright owner, and project steward. Chill Ethical People is the
project's organizational home and maintainer community.

Organization membership, repository access, or a maintainer role does not by
itself transfer ownership of the original project. Accepted contributors retain
copyright in their own contributions unless a separate written assignment says
otherwise; those contributions are licensed under Apache-2.0 for inclusion in
TraceQuarry. See [OWNERSHIP.md](OWNERSHIP.md) for the project record and
[GOVERNANCE.md](GOVERNANCE.md) for the official project's decision rights.

The license covers the software. The TraceQuarry name, logo, lockup, favicon,
brand assets, and Chill Ethical People marks remain project identity assets and
are not granted for unrelated branding or endorsement. Public forks and
modified distributions may truthfully describe their origin, but must not imply
that they are an official release or endorsed project. See
[TRADEMARKS.md](TRADEMARKS.md), [LICENSE](LICENSE), [NOTICE](NOTICE), and
[OWNERSHIP.md](OWNERSHIP.md) for the applicable terms and attribution record.

Contributions are welcome under the same Apache-2.0 terms and require a
`Signed-off-by` trailer under the [Developer Certificate of Origin](DCO). Do not
contribute real incident evidence, credentials, customer data, or third-party
material that you are not allowed to share. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before opening
public issues or pull requests.

## Community Acknowledgments

This public beta was strengthened by practical responder feedback and hands-on
testing. Thank you to
[James Navarro](https://www.linkedin.com/in/james-navarro-161955196/),
[Jacob W](https://www.linkedin.com/in/jacob-w-491ab28/), and
[Kaylin Malutich](https://www.linkedin.com/in/kaylin-malutich-0210a449/) for
testing real workflows, reporting friction, and helping shape the large-case
upload experience, timeline review, direct-log intake, export options, and case
reopening improvements.

## Validation And Analyst Confidence

TraceQuarry is validated with bundled fixture evidence and generated synthetic
scenarios. The automated suite covers:

- Single-collection and multi-collection case pipelines
- Timeline identity, provenance, correlation, and expected deduplication
- Threat-profile prioritization and IoC enrichment
- Archive traversal, member-size, and expansion-limit protections
- Output traversal, Host, Origin, and CSRF security regressions
- Public job-data redaction and restrictive evidence-file permissions
- Oversized HTTP request rejection and parser error reporting
- Concurrent upload reservation, enforced expiry, durable job-state recovery,
  health/readiness telemetry, and packaged web-resource validation

CI also runs Snyk Open Source against the pinned production dependency baseline
in `requirements.txt`. A scheduled weekly monitor checks that same baseline for
newly disclosed vulnerabilities; the Snyk badge above reflects the workflow's
latest result. Gitleaks scans the complete reachable Git history on pushes,
pull requests, a weekly schedule, and manual release checks.

These checks establish implementation confidence, not evidentiary conclusions.
For case reporting, verify decisive findings against the raw source lines,
collection coverage, host timezone, and incident-window assumptions. Record any
parser errors or missing sources as limitations in the investigation report.

## Smoke Test

Run the fixture smoke test before using a changed parser build on case evidence:

```bash
cd TraceQuarry
PYTHONPATH=. python3 -m uac_parser.cli tests/fixtures/uac_sample \
  --out /tmp/tracequarry-smoke \
  --incident-start 2026-06-16T09:58:00+08:00 \
  --incident-end 2026-06-16T18:01:40+08:00 \
  --year 2026 \
  --timezone Asia/Hong_Kong
```

- Confirm expected files exist in the smoke output:

```bash
ls /tmp/tracequarry-smoke/timeline_full.csv \
   /tmp/tracequarry-smoke/timeline_mini.csv \
   /tmp/tracequarry-smoke/findings.json \
   /tmp/tracequarry-smoke/source_index.json \
   /tmp/tracequarry-smoke/parser_errors.log
```

Run the automated correctness, archive-safety, correlation, and pipeline tests:

```bash
cd TraceQuarry
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Release Verification

GitHub releases include a source distribution, wheel, CycloneDX SBOM, and
`SHA256SUMS`. Verify downloaded artifacts before installation:

```bash
shasum -a 256 -c SHA256SUMS
python3 -m pip install tracequarry-*.whl
```

Security-sensitive issues should be reported privately through
[GitHub Security Advisories](https://github.com/Chill-Ethical-People/TraceQuarry/security/advisories/new)
or by email to [`contact@chillethicalpeople.com`](mailto:contact@chillethicalpeople.com).

Maintainers should complete the [public release checklist](docs/public-release-checklist.md)
when changing repository visibility or publishing a release tag.
