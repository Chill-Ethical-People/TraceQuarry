from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from uac_parser.output.permissions import secure_file
from uac_parser.timeline.event import TimelineEvent

CSV_FIELDS = [
    "event_id",
    "timestamp",
    "timestamp_raw",
    "timezone",
    "timezone_confidence",
    "timestamp_type",
    "host",
    "collection_id",
    "collection_name",
    "collection_input",
    "collection_host",
    "source_path",
    "source_type",
    "parser",
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
    "mitre",
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
            row = event.to_dict()
            row["mitre"] = ",".join(event.mitre)
            row["detection_names"] = ",".join(event.detection_names)
            row["ttp_flags"] = ",".join(event.ttp_flags)
            row["tags"] = ",".join(event.tags)
            row["related_event_ids"] = ",".join(event.related_event_ids)
            row["extra"] = json.dumps(event.extra, ensure_ascii=False, sort_keys=True)
            writer.writerow({field: row.get(field) for field in CSV_FIELDS})
    secure_file(path)


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
) -> None:
    high = [f for f in findings if f.get("severity") == "high"]
    lines = [
        "# TraceQuarry Summary",
        "",
        f"Total events: {len(events)}",
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

    lines.extend(["", "## Lateral Movement Assessment"])
    lat_findings = [
        f
        for f in findings
        if any(
            t in (f.get("tags") or []) for t in ["lateral_movement", "negative_finding"]
        )
    ]
    if lat_findings:
        for f in lat_findings:
            lines.append(f"- {f.get('summary')}")
    else:
        lines.append("- No lateral movement analysis available.")

    lines.extend(["", "## Account Lifecycle Changes"])
    acct_findings = [
        f for f in findings if "account_lifecycle" in (f.get("tags") or [])
    ]
    acct_events = [e for e in events if e.source_type == "account_diff"]
    if acct_findings:
        for f in acct_findings:
            lines.append(f"- {f.get('summary')}")
    elif acct_events:
        lines.append(f"- {len(acct_events)} account diff event(s) detected.")
    else:
        lines.append("- No backup files found for diffing (passwd-/shadow-/group-).")

    created = [e for e in acct_events if "created" in e.event_action]
    deleted = [e for e in acct_events if "deleted" in e.event_action]
    pw_changes = [
        e
        for e in acct_events
        if e.event_action
        in {"password_changed", "account_unlocked", "password_set_new_account"}
    ]
    group_changes = [e for e in acct_events if "group_member" in e.event_action]
    if created:
        lines.append(
            f"  - Accounts created: {', '.join(e.user or '?' for e in created)}"
        )
    if deleted:
        lines.append(
            f"  - Accounts deleted: {', '.join(e.user or '?' for e in deleted)}"
        )
    if pw_changes:
        lines.append(
            f"  - Password changes: {', '.join(e.user or '?' for e in pw_changes)}"
        )
    if group_changes:
        for e in group_changes:
            lines.append(f"  - {e.summary}")

    lines.extend(["", "## Brute-Force Campaigns"])
    bf_findings = [
        f for f in findings if "bruteforce_campaign" in (f.get("tags") or [])
    ]
    if bf_findings:
        for f in bf_findings:
            lines.append(f"- {f.get('summary')}")
    else:
        lines.append("- No brute-force campaigns detected.")

    lines.extend(["", "## Network State"])
    net_events = [e for e in events if e.source_type == "network_state"]
    listening = [e for e in net_events if e.event_action == "listening_port"]
    outbound = [e for e in net_events if "outbound" in e.event_action]
    inbound = [e for e in net_events if "inbound" in e.event_action]
    if net_events:
        lines.append(
            f"- {len(listening)} listening port(s), {len(inbound)} inbound connection(s), {len(outbound)} outbound connection(s)"
        )
        suspicious_net = [
            e for e in net_events if e.severity in {"medium", "high", "critical"}
        ]
        for e in suspicious_net[:10]:
            lines.append(f"  - [{e.severity.upper()}] {e.summary}")
    else:
        lines.append("- No network state data (ss/netstat) found in collection.")

    lines.extend(["", "## Storylines"])
    if storylines:
        for s in storylines:
            lines.append(
                f"- **{s.get('title')}** ({s.get('start')} to {s.get('end')}): {s.get('summary')}"
            )
    else:
        lines.append("- No storylines identified.")

    lines.extend(["", "## Recommended Next Steps"])
    lines.extend(
        [
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
