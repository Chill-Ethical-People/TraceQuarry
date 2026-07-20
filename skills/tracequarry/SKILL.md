---
name: tracequarry
description: Analyze one or more Unix-like Artifacts Collector (UAC) archives or extracted Linux evidence directories with TraceQuarry. Use when Codex needs to run or guide Linux DFIR triage, determine an incident window, normalize UTC timelines, match IoCs, prioritize ransomware, exploitation, credential, persistence, mining, or advanced-intrusion hypotheses, correlate activity across collections, validate findings against raw evidence, or prepare a defensible responder summary. Do not use it as proof of malware identity, lateral movement, or threat-actor attribution.
---

# TraceQuarry Linux DFIR

Use TraceQuarry as a triage and timeline-assistance system. Treat its findings as
investigative leads until the underlying evidence and surrounding context support
the conclusion.

## Apply Forensic Guardrails

- Preserve the original collection and analyze a verified working copy.
- Write derived output outside the evidence directory.
- Record the input hash, collection identity, parser version, rule fingerprint,
  log year, timezone, incident window, and command or GUI settings.
- Keep timestamps in UTC for correlation while retaining `timestamp_raw` and the
  timezone assumptions needed to reproduce normalization.
- Distinguish observed behavior, collection-time state, context, and inference.
- Report missing or unsupported evidence as a coverage gap, never as proof that
  activity did not occur.
- Phrase actor matches as tradecraft or profile similarity. Never attribute an
  actor from TraceQuarry tags alone.
- Redact passwords, tokens, private keys, and reusable hashes from reports and
  prompts. Preserve sensitive raw evidence only in the controlled case location.

## Establish Scope

1. Confirm whether the input is a single UAC collection or a multi-host case.
2. Confirm the suspected incident start and end, including timezone. Ask for the
   period when it materially changes the requested analysis and cannot be inferred.
3. Confirm the year for syslog-style timestamps that omit a year.
4. Collect known IoCs as IPs, domains, hashes, paths, usernames, or tool literals.
5. Select an assisted-investigation profile only as a prioritization aid. Use
   `comprehensive` when the intrusion hypothesis is unknown.
6. If the time range is unknown, use the GUI's **Inspect Time Range** action or
   run a full parse first; then choose a review window from corroborated events.

Read [references/investigation-pivots.md](references/investigation-pivots.md)
when choosing a profile or deciding which evidence sources to pivot into.

## Verify The Runtime

Prefer the installed `tracequarry` command. From a source checkout, use
`python3 -m uac_parser.cli` if the console command is unavailable.

```bash
tracequarry --help
tracequarry-rules
```

Do not install packages, upload evidence, or start a network-exposed service
without the user's approval. Keep the GUI bound to `127.0.0.1`.

## Run A Single Collection

```bash
tracequarry /cases/uac-host01.tar.gz --out /cases/derived/host01 \
  --incident-start 2026-06-16T08:00:00Z \
  --incident-end 2026-06-16T12:00:00Z \
  --year 2026 \
  --timezone UTC \
  --threat-type comprehensive \
  --ioc 198.51.100.50 \
  --ioc-file /cases/known-iocs.csv
```

Omit incident boundaries only for an intentional full-range parse. Use `--host`
only when collection metadata cannot identify the host; document the override.

## Run A Multi-Collection Case

```bash
tracequarry --case-out /cases/derived/case-linux \
  --case-name "Example Linux Incident" \
  --input /cases/uac-host01.tar.gz \
  --input /cases/uac-host02.tar.gz \
  --incident-start 2026-06-16T08:00:00Z \
  --incident-end 2026-06-16T12:00:00Z \
  --year 2026 \
  --timezone UTC \
  --threat-type comprehensive
```

Use `--input-manifest` for a newline-delimited collection list. Preserve each
collection's outputs and use case-level files for cross-host review. Do not claim
lateral movement unless evidence shows outbound access from one parsed host to
another; otherwise report shared activity or a possible campaign-level pattern.

## Use The Local GUI

```bash
tracequarry-web --host 127.0.0.1 --port 8765 \
  --work-dir /cases/derived/web-runs \
  --input-root /cases
```

Use the GUI to inspect temporal coverage, supply multiple archives or server-side
paths, set incident parameters, follow per-collection progress, preview summaries,
and review raw timeline evidence. Do not expose the development server directly
to a LAN or the Internet. Approve only case-scoped evidence directories through
`--input-root`; do not allow the filesystem root or a user's entire home directory.

## Review Outputs In Order

1. Review `run_manifest.json` or `case_manifest.json` for input identity,
   execution settings, versioning, rule fingerprint, and output hashes.
2. Review `source_index.json` or `case_source_index.json` for discovered,
   parsed, unsupported, unmatched, and excluded evidence.
3. Review `parser_errors.log` or `case_parser_errors.log`. Escalate errors that
   affect authentication, audit, process, network, persistence, account, or
   filesystem evidence.
4. Review assisted-investigation output for prioritized questions and missing
   source groups. Do not treat a selected profile as a classification result.
5. Review `findings.json` or `case_findings.json` as leads.
6. Review `timeline_mini.csv` or `case_timeline_mini.csv` for the incident window.
7. Expand into the full timeline at window edges, around precursor events, and
   wherever sequence or state cannot be established from the mini timeline.
8. Review IoC hits by first seen, last seen, host, user, action, and source path.

Read [references/evidence-and-output-guide.md](references/evidence-and-output-guide.md)
when interpreting schema fields, coverage, provenance, or case outputs.

## Validate Every Material Finding

1. Locate every referenced `event_id` and `related_event_ids` in JSONL or CSV.
2. Verify `source_path`, `source_sha256`, parser, collection provenance, and raw
   evidence. Review neighboring source lines when the artifact is line-oriented.
3. Evaluate `evidence_role` before describing action:
   - `behavior`: a source records an action or event.
   - `state_observation`: a collection-time state, not proof of execution time.
   - `context`: supporting configuration or history.
   - `inference`: parser-derived placement or relationship requiring corroboration.
4. Treat `mitre` as a behavior-supported mapping and `mitre_candidates` as review
   hypotheses. Neither field establishes intent or actor identity.
5. Check timestamp precision, confidence, raw value, and observation interval.
   Do not impose second-level ordering on date-only or inferred timestamps.
6. Distinguish execution from string presence. Defensive `grep`, `rg`, YARA, AV,
   EDR, package, or documentation content can contain attacker-tool literals.
7. Correlate high-impact leads across authentication, sudo/audit, process,
   network, account, persistence, file metadata, and external telemetry.
8. Record alternative explanations and evidence gaps before assigning confidence.

## Produce A Responder Deliverable

Report in this order:

1. Scope, host or collections, incident window, timezone, and parser/rule version.
2. Acquisition and derived-evidence integrity from the manifest.
3. Evidence coverage, unsupported sources, parser errors, and material limitations.
4. Findings ordered by impact and confidence, each with UTC time, host, event IDs,
   source path, short raw excerpt, corroboration, and alternative explanation.
5. A concise incident timeline separating observed behavior from state and inference.
6. IoCs, suspicious tooling, ATT&CK mappings, and actor-profile similarities with
   explicit caveats.
7. Unanswered questions, preservation needs, and recommended next pivots.

Use calibrated language such as "observed," "corroborated," "consistent with,"
"candidate," and "not observed in the available evidence." Avoid "confirmed"
unless independent evidence supports the claim.

## Stop Or Escalate

- Stop if extraction or parsing would overwrite source evidence.
- Escalate unsafe archives, collection fingerprint mismatches, or unexplained
  source-hash changes before continuing.
- Escalate missing critical source classes or native binary formats requiring a
  specialist parser; do not silently convert them into a clean assessment.
- Preserve suspicious binaries, scripts, keys, persistence targets, and relevant
  volatile/external telemetry before remediation changes the evidence.
