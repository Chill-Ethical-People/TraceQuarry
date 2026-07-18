# MVP Design

The MVP is a UAC-aware Linux forensic timeline engine.

## Parser Flow

1. Load UAC archive or directory.
2. Discover source files.
3. Parse source events, including logs and current-state artifacts.
4. Normalize timestamps and event schema.
5. Enrich common Linux attack TTPs.
6. Filter a mini timeline when incident period is provided.
7. Correlate high-signal state artifacts with bodyfile/audit timestamps where possible.
8. Emit JSONL, CSV, findings, and a markdown summary.

## Incident Period

The analyst should provide:

- `--incident-start`
- `--incident-end`

Both should be ISO 8601 timestamps. Use UTC where possible.

## Accuracy Principles

- Prefer behavior over attribution.
- Preserve raw evidence lines in every parsed event.
- Mark timezone assumptions.
- Keep actor-relevant matches low-confidence unless supported by malware, infrastructure, wallet, or CTI indicators.
- Preserve original evidence actions and add TTP detections as separate flags.
- Use explicit timezone assumptions for syslog-style local timestamps.
- Make every finding explainable through event IDs.

## Added Parser Coverage

- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- `/etc/sudoers` and `/etc/sudoers.d/*`
- SSH `authorized_keys`, `known_hosts`, and `sshd_config`
- cron files and user crontabs
- systemd service/timer units
- shell profiles, `/etc/profile.d`, `rc.local`, and init scripts
- `/etc/ld.so.preload`
- PAM configuration
- bodyfile-derived SUID/SGID indicators
- capability output files
- grouped auditd records
- text exports of `last` / `lastb` login history

## Correlation

Untimestamped state artifacts such as `authorized_keys`, sudoers rules, cron entries, systemd units, PAM entries, and `ld.so.preload` can be assigned an inferred `correlated_*` timestamp when the same path appears in bodyfile or auditd PATH records. The event keeps `related_event_ids` so the analyst can validate the inferred time.
