from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_syslog

from .common import read_text_lines

PROC_RE = re.compile(
    r"^\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)


def parse(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for raw in read_text_lines(path):
        timestamp = parse_syslog(raw, year=year, timezone_name=timezone_name)
        if not timestamp:
            continue
        match = PROC_RE.match(raw)
        proc = match.group("proc") if match else None
        msg = match.group("msg") if match else raw
        action = None
        category = "system"
        severity = "informational"
        tags = ["syslog"]
        mitre: list[str] = []
        if "Started " in msg or "Starting " in msg:
            action = "service_started"
            tags.append("service")
        elif "Stopped " in msg or "Stopping " in msg:
            action = "service_stopped"
            tags.append("service")
        elif "session opened" in msg:
            action = "session_opened"
            category = "authentication"
        elif "CRON" in raw or proc == "CRON":
            action = "cron_execution"
            category = "persistence"
            tags.extend(["cron", "scheduled_task"])
            mitre = ["T1053.003"]
        if not action:
            continue
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                timestamp_raw=raw[:15],
                timezone=timezone_name,
                timezone_confidence="assumed_local",
                timestamp_type="log_time",
                host=host or (match.group("host") if match else ""),
                source_path=relative,
                source_type="syslog",
                parser="syslog",
                event_category=category,
                event_action=action,
                process=proc,
                pid=match.group("pid") if match else None,
                mitre=mitre,
                severity=severity,
                confidence="medium",
                tags=tags,
                summary=msg,
                raw=raw,
            )
        )
    return events
