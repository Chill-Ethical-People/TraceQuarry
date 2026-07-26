from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from uac_parser.enrich.attack_phases import (
    attack_phase_metadata,
    attack_phases,
)
from uac_parser.output.permissions import secure_file
from uac_parser.timeline.event import TimelineEvent

CSV_FIELDS = [
    "schema_version",
    "event_id",
    "timestamp",
    "timestamp_raw",
    "time_start",
    "time_end",
    "timezone",
    "timezone_confidence",
    "timestamp_type",
    "timestamp_precision",
    "timestamp_confidence",
    "evidence_role",
    "host",
    "collection_id",
    "collection_name",
    "collection_input",
    "collection_host",
    "source_path",
    "source_sha256",
    "source_type",
    "parser",
    "parser_version",
    "event_category",
    "event_action",
    "user",
    "uid",
    "gid",
    "src_ip",
    "dst_ip",
    "port",
    "process",
    "pid",
    "command",
    "file_path",
    "severity",
    "confidence",
    "attack_phases",
    "attack_phase_candidates",
    "mitre",
    "mitre_candidates",
    "detection_names",
    "ttp_flags",
    "tags",
    "related_event_ids",
    "summary",
    "raw",
    "extra",
]


def write_jsonl(path: Path, events: list[TimelineEvent]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(
                json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n"
            )
    secure_file(path)


def write_csv(path: Path, events: list[TimelineEvent]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for event in events:
            writer.writerow(_csv_row(event, event.to_dict()))
    secure_file(path)


def write_timeline(
    jsonl_path: Path,
    csv_path: Path,
    events: list[TimelineEvent],
) -> None:
    """Write both timeline formats while materializing each event only once."""
    with (
        jsonl_path.open("w", encoding="utf-8") as jsonl_handle,
        csv_path.open("w", newline="", encoding="utf-8") as csv_handle,
    ):
        writer = csv.DictWriter(csv_handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for event in events:
            record = event.to_dict()
            jsonl_handle.write(
                json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
            )
            writer.writerow(_csv_row(event, record))
    secure_file(jsonl_path)
    secure_file(csv_path)


def _csv_row(
    event: TimelineEvent,
    record: dict[str, Any],
) -> dict[str, Any]:
    row = record.copy()
    row["mitre"] = ",".join(event.mitre)
    row["mitre_candidates"] = ",".join(event.mitre_candidates)
    row["attack_phases"] = ",".join(event.attack_phases)
    row["attack_phase_candidates"] = ",".join(event.attack_phase_candidates)
    row["detection_names"] = ",".join(event.detection_names)
    row["ttp_flags"] = ",".join(event.ttp_flags)
    row["tags"] = ",".join(event.tags)
    row["related_event_ids"] = ",".join(event.related_event_ids)
    row["extra"] = json.dumps(event.extra, ensure_ascii=False, sort_keys=True)
    return {field: row.get(field) for field in CSV_FIELDS}


def write_json(path: Path, data: object) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    secure_file(path)


def write_summary(
    path: Path,
    events: list[TimelineEvent],
    findings: list[dict[str, Any]],
    storylines: list[dict[str, Any]],
    *,
    context_events: list[TimelineEvent] | None = None,
) -> None:
    all_context = context_events if context_events is not None else events
    lines = _summary_header(events, all_context, findings, storylines)
    lines.extend(_attack_phase_summary(events))
    lines.extend(
        _finding_section(
            "Lateral Movement Assessment",
            findings,
            "lateral_movement",
            "No lateral movement analysis available.",
            alternate_tag="negative_finding",
        )
    )
    lines.extend(_account_lifecycle_summary(all_context, findings))
    lines.extend(
        _finding_section(
            "Brute-Force Campaigns",
            findings,
            "bruteforce_campaign",
            "No brute-force campaigns detected.",
        )
    )
    lines.extend(_network_state_summary(all_context))
    lines.extend(_storyline_summary(storylines))
    lines.extend(
        [
            "",
            "## Recommended Next Steps",
            "- Validate suspicious commands against the original source files.",
            "- Review SSH source IPs, new users, sudo activity, and authorized_keys changes.",
            "- Preserve suspicious binaries/scripts referenced in high-severity events.",
            "- Correlate exfiltration, tunneling, mining, and destructive indicators with network telemetry.",
            "- Verify all account lifecycle changes were authorized.",
            "- Treat actor-like findings as tradecraft hints, not attribution.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    secure_file(path)


def _summary_header(
    events: list[TimelineEvent],
    all_context: list[TimelineEvent],
    findings: list[dict[str, Any]],
    storylines: list[dict[str, Any]],
) -> list[str]:
    high = [finding for finding in findings if finding.get("severity") == "high"]
    lines = [
        "# TraceQuarry Summary",
        "",
        f"Events in review scope: {len(events)}",
        f"Total parsed events: {len(all_context)}",
        f"Findings: {len(findings)}",
        f"High severity findings: {len(high)}",
        f"Storylines: {len(storylines)}",
        "",
        "## High Severity Findings",
    ]
    if not high:
        lines.append("- None")
    for finding in high:
        lines.append(f"- **{finding.get('title')}**: {finding.get('summary')}")
    return lines


def _attack_phase_summary(events: list[TimelineEvent]) -> list[str]:
    metadata = attack_phase_metadata()
    phase_counts = {
        phase.key: sum(phase.key in event.attack_phases for event in events)
        for phase in attack_phases()
    }
    phase_candidate_counts = {
        phase.key: sum(phase.key in event.attack_phase_candidates for event in events)
        for phase in attack_phases()
    }
    lines = [
        "",
        "## MITRE ATT&CK Phase Breakdown",
        "",
        (
            "Confirmed phases require behavior-backed techniques with an unambiguous "
            "tactic or matching event context; ambiguous and state-derived mappings "
            "remain candidates."
        ),
        f"ATT&CK mapping version: {metadata['attack_version']}",
    ]
    observed_phase = False
    for phase in attack_phases():
        confirmed = phase_counts[phase.key]
        candidate = phase_candidate_counts[phase.key]
        if not confirmed and not candidate:
            continue
        observed_phase = True
        lines.append(
            f"- **{phase.label} ({phase.tactic_id})**: {confirmed} confirmed event(s), "
            f"{candidate} candidate event(s)"
        )
    if not observed_phase:
        lines.append("- No evidence-derived ATT&CK phases were assigned.")
    return lines


def _finding_section(
    title: str,
    findings: list[dict[str, Any]],
    tag: str,
    empty_message: str,
    *,
    alternate_tag: str = "",
) -> list[str]:
    selected = [
        finding
        for finding in findings
        if tag in (finding.get("tags") or [])
        or (alternate_tag and alternate_tag in (finding.get("tags") or []))
    ]
    lines = ["", f"## {title}"]
    if selected:
        lines.extend(f"- {finding.get('summary')}" for finding in selected)
    else:
        lines.append(f"- {empty_message}")
    return lines


def _account_lifecycle_summary(
    all_context: list[TimelineEvent], findings: list[dict[str, Any]]
) -> list[str]:
    lines = ["", "## Account Lifecycle Changes"]
    acct_findings = [
        f for f in findings if "account_lifecycle" in (f.get("tags") or [])
    ]
    acct_events = [e for e in all_context if e.source_type == "account_diff"]
    if acct_findings:
        for f in acct_findings:
            lines.append(f"- {f.get('summary')}")
    elif acct_events:
        lines.append(f"- {len(acct_events)} account diff event(s) detected.")
    else:
        lines.append("- No backup files found for diffing (passwd-/shadow-/group-).")

    created = [
        e for e in acct_events if e.event_action == "account_created_since_backup"
    ]
    deleted = [
        e for e in acct_events if e.event_action == "account_deleted_since_backup"
    ]
    pw_changes = [
        e
        for e in acct_events
        if e.event_action
        in {"password_changed", "account_unlocked", "password_set_new_account"}
    ]
    group_changes = [e for e in acct_events if "group_member" in e.event_action]
    if created:
        users = sorted({event.user for event in created if event.user})
        if users:
            lines.append(f"  - Accounts created: {', '.join(users)}")
        else:
            lines.append("  - Account creation evidence has no parsed username.")
    if deleted:
        users = sorted({event.user for event in deleted if event.user})
        if users:
            lines.append(f"  - Accounts deleted: {', '.join(users)}")
        else:
            lines.append("  - Account deletion evidence has no parsed username.")
    if pw_changes:
        users = sorted({event.user for event in pw_changes if event.user})
        if users:
            lines.append(f"  - Password changes: {', '.join(users)}")
        else:
            lines.append("  - Password-change evidence has no parsed username.")
    if group_changes:
        for e in group_changes:
            lines.append(f"  - {e.summary}")
    return lines


def _network_state_summary(all_context: list[TimelineEvent]) -> list[str]:
    lines = ["", "## Network State"]
    net_events = [e for e in all_context if e.source_type == "network_state"]
    listening = [e for e in net_events if e.event_action == "listening_port"]
    outbound = [e for e in net_events if "outbound" in e.event_action]
    inbound = [e for e in net_events if "inbound" in e.event_action]
    if net_events:
        untimed = sum(not event.timestamp for event in net_events)
        lines.append(
            f"- {len(listening)} listening port(s), {len(inbound)} inbound connection(s), {len(outbound)} outbound connection(s)"
        )
        if untimed:
            lines.append(
                f"  - {untimed} network snapshot event(s) have no point-in-time timestamp and are reported as collection state."
            )
        suspicious_net = [
            e for e in net_events if e.severity in {"medium", "high", "critical"}
        ]
        for e in suspicious_net[:10]:
            lines.append(f"  - [{e.severity.upper()}] {e.summary}")
    else:
        lines.append("- No network state data (ss/netstat) found in collection.")
    return lines


def _storyline_summary(storylines: list[dict[str, Any]]) -> list[str]:
    lines = ["", "## Storylines"]
    if storylines:
        for s in storylines:
            lines.append(
                f"- **{s.get('title')}** ({s.get('start')} to {s.get('end')}): {s.get('summary')}"
            )
    else:
        lines.append("- No storylines identified.")
    return lines
