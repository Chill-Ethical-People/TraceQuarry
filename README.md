# TraceQuarry

<p align="center">
  <a href="https://github.com/Chill-Ethical-People/tracequarry/actions/workflows/ci.yml"><img src="https://github.com/Chill-Ethical-People/tracequarry/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/Chill-Ethical-People/tracequarry/actions/workflows/codeql.yml"><img src="https://github.com/Chill-Ethical-People/tracequarry/actions/workflows/codeql.yml/badge.svg" alt="CodeQL status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-5C7F67.svg" alt="Apache-2.0 license"></a>
  <a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB.svg" alt="Python 3.11 and 3.12"></a>
</p>

<p align="center">
  <img src="assets/tracequarry-favicon.svg" width="168" alt="TraceQuarry layered timeline mark">
</p>

TraceQuarry is a local-first Linux DFIR workbench for Unix-like Artifacts
Collector (UAC) evidence. It converts a UAC archive or extracted UAC directory
into defensible incident timelines, source coverage indexes, IoC hits, and
high-signal findings for responder review.

Tagline: **Excavate the timeline. Preserve the proof.**

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
cd tracequarry
python3 -m uac_parser.web --host 127.0.0.1 --port 8765 --work-dir web_runs
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
severity, and source-type filtering, and displays the original raw record with
host and collection provenance. Analyst dispositions, tags, and notes are saved
to `analyst_annotations.json`; they never modify the parser timeline or source
evidence.

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

Known caveat: rotated files with filenames that embed an older year can still
contain yearless log lines. If `--year 2026` is applied to a rotated file such as
`yum.log-20230101`, the parser may surface apparent future or shifted dates.
Review `source_index.json`, rotated filenames, and raw source lines before
finalizing the incident window.

State artifacts without native timestamps may receive `correlated_*` timestamps
when bodyfile or auditd PATH records support timeline placement.

## Output Review Order

For incident response, review outputs in this order:

1. `parser_errors.log`
   Confirm that critical sources did not fail to parse. An empty file is ideal.

2. `source_index.json`
   Check evidence coverage. Confirm whether auth logs, audit logs, shell history,
   login history, process state, network state, account files, sudoers, cron,
   systemd, PAM, SSH keys, and bodyfile data were present.

3. `summary.md`
   Read the responder summary for high-level findings, lateral movement notes,
   account lifecycle changes, brute-force summaries, and storylines.

4. `findings.json`
   Treat this as the queue of high-signal leads. Pivot each important finding to
   the raw source line, source file, timestamp type, user, process, command, and
   related events.

5. `timeline_mini.csv`
   Use this as the main analyst timeline for the suspected incident window.
   Filter by `severity`, `event_category`, `event_action`, `user`, `src_ip`,
   `process`, `command`, `ttp`, and `source_path`.

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
- `source_index.json`: discovered evidence sources and parse coverage
- `parser_errors.log`: non-fatal parser errors for analyst review
- `run_manifest.json`: input identity, source hashes, parser coverage, rule fingerprint,
  execution settings, and output hashes for reproducibility
- `assisted_investigation.md` and `.json`: hypothesis-led priorities, readiness,
  checklist status, evidence references, guardrails, and analyst pivots when a
  threat profile was selected

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

## CLI Usage

```bash
python3 -m uac_parser.cli /cases/uac-host01.tar.gz --out out/host01 \
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
python3 -m uac_parser.cli --case-out out/case-acme-linux \
  --case-name "ACME Linux Intrusion" \
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
python3 -m uac_parser.cli --case-out out/case-acme-linux \
  --input-manifest case-inputs.txt \
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
198.51.100.50,ip,synthetic source
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

The GUI defaults to an 8 GiB upload limit, a 40 GiB work-directory quota, two
concurrent analysis slots, and a 120-second request timeout. Adjust these for a
dedicated analysis workstation without removing the disk safety margin:

```bash
python3 -m uac_parser.web --host 127.0.0.1 --port 8765 --work-dir web_runs \
  --max-upload-gib 8 --max-work-dir-gib 40 \
  --max-concurrent-jobs 2 --request-timeout 120
```

Open `http://127.0.0.1:8765`, then:

1. Choose **Archive upload** for a browser-selected `.tar.gz`, `.tgz`, `.tar`, or
   `.zip` UAC output. Select multiple archives to create a case workspace.
2. Choose **Server path** for a file or extracted directory already present on
   the analysis machine. Enter one path per line to create a case workspace.
3. Set log year and timezone.
4. Click **Inspect Time Range**.
5. Set or refine the incident start and incident end.
6. Add known IoCs.
7. Run analysis and preserve the output directory path.

If both upload and server path are filled, the selected source mode controls
which input is used.

When more than one input is provided, the Live Run panel shows collection and
correlation counts, opens the case summary preview, and links both case-level
outputs and per-collection host summaries.

The browser API uses a per-process request token and rejects non-loopback Host
and Origin values. Restarting the server invalidates open GUI pages and makes
prior output URLs unavailable; reload the page and run or reopen the relevant
case from its filesystem output directory.

## Detection Coverage

Current coverage is tuned for Linux intrusion triage:

- Authentication: SSH brute force, invalid users, successful login after repeated
  failures, root logins, login-history exports, account lock/unlock events, and
  password changes
- Execution: shell history commands, download-execute chains, staged execution
  from `/tmp`, `/var/tmp`, `/dev/shm`, and `/run`, reverse-shell-like syntax, and
  process-list signals
- Persistence: cron, systemd, rc.local, init.d, shell profiles, unrestricted SSH
  authorized keys, LD_PRELOAD, and PAM backdoor candidates
- Privilege escalation: UID 0 anomalies, sudoers risks, NOPASSWD entries,
  privileged group membership, SUID/SGID files, Linux capabilities, Docker/LXD
  group risk, and account backup diffing
- Credential access: SSH key access, credential file access, local password hash
  metadata, weak hash identification, plaintext password leakage in history, and
  shadow timestamp extraction
- Lateral movement: outbound SSH, SCP, rsync, known_hosts, network probes, and
  explicit negative findings when no evidence is found
- Exfiltration and tooling: `rclone`, cloud CLIs, archive utilities, database
  dumps, tunneling tools, miners, destructive commands, and ransomware-impact
  indicators
- Audit and account lifecycle: auditd account events, passwd/shadow/group backup
  comparisons, created/deleted/modified accounts, password changes, account
  unlocks, and privileged group additions

Actor-relevant matches are tradecraft hints only. Do not report them as
attribution without independent threat intelligence.

Tool enrichment is loaded from `rules/tagging_registry.yml` at runtime. Each
matched event receives the registry tool ID, category, confidence, and MITRE
mapping. The registry hash is preserved in the run manifest so analysts can
identify the exact detection content used for a case.

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

## Install

TraceQuarry supports Python 3.11 and 3.12. PyYAML is used to validate and load
the external detection registry.

```bash
git clone https://github.com/Chill-Ethical-People/tracequarry.git
cd tracequarry
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

You can also run it directly from the repository root with `PYTHONPATH`:

```bash
cd tracequarry
PYTHONPATH=. python3 -m uac_parser.cli tests/fixtures/uac_sample --out /tmp/tracequarry-sample
```

## License And Ownership

TraceQuarry is released under the Apache License, Version 2.0. You can use,
modify, and redistribute the software under that license while Chill Ethical
People retains copyright ownership of the original project.

The license covers the software. The TraceQuarry name, logo, lockup, favicon,
brand assets, and Chill Ethical People marks remain project identity assets and
are not granted for unrelated branding or endorsement. See `LICENSE` and
`NOTICE` for the exact terms.

Contributions are welcome under the same Apache-2.0 terms. Do not contribute
real incident evidence, credentials, customer data, or third-party material that
you are not allowed to share. See `CONTRIBUTING.md` and `SECURITY.md` before
opening public issues or pull requests.

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

These checks establish implementation confidence, not evidentiary conclusions.
For case reporting, verify decisive findings against the raw source lines,
collection coverage, host timezone, and incident-window assumptions. Record any
parser errors or missing sources as limitations in the investigation report.

## Smoke Test

Run the fixture smoke test before using a changed parser build on case evidence:

```bash
cd tracequarry
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
cd tracequarry
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
[GitHub Security Advisories](https://github.com/Chill-Ethical-People/tracequarry/security/advisories/new)
or by email to [`contact@chillethicalpeople.com`](mailto:contact@chillethicalpeople.com).

Maintainers should complete the [public release checklist](docs/public-release-checklist.md)
when changing repository visibility or publishing a release tag.
