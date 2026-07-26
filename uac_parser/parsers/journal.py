from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_iso, parse_syslog

from .common import read_text_lines

ISO_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
SHORT_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
SSH_SUCCESS_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SSH_FAILURE_RE = re.compile(
    r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(r"USER=(?P<runas>[^;]+)\s*;\s*COMMAND=(?P<command>.*)")


def parse(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
) -> list[TimelineEvent]:
    events = []
    for line_number, raw in enumerate(read_text_lines(path), start=1):
        match = ISO_LINE_RE.match(raw) or SHORT_LINE_RE.match(raw)
        if not match:
            continue
        timestamp_raw = match.group("ts")
        timestamp = parse_iso(timestamp_raw) or parse_syslog(
            timestamp_raw, year=year, timezone_name=timezone_name
        )
        if not timestamp:
            continue
        process = match.group("proc")
        message = match.group("msg")
        event = TimelineEvent(
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            timezone=timezone_name,
            timezone_confidence=(
                "source_offset" if ISO_LINE_RE.match(raw) else "assumed_local"
            ),
            timestamp_type="log_time",
            evidence_role="behavior",
            host=host or match.group("host"),
            source_path=relative,
            source_type="journal_text",
            parser="journal",
            event_category="system",
            event_action="journal_message",
            process=process,
            pid=match.group("pid"),
            severity="informational",
            confidence="medium",
            tags=["journal"],
            summary=message,
            raw=raw,
            extra={"line": line_number},
        )
        _classify(event, message)
        events.append(event)
    return events


def _classify(event: TimelineEvent, message: str) -> None:
    if success := SSH_SUCCESS_RE.search(message):
        event.event_category = "authentication"
        event.event_action = "ssh_login_success"
        event.user = success.group("user")
        event.src_ip = success.group("src_ip")
        event.port = success.group("port")
        event.severity = "medium"
        event.confidence = "high"
        event.tags.extend(["ssh", "login_success"])
        event.mitre = ["T1078"]
        return
    if failure := SSH_FAILURE_RE.search(message):
        event.event_category = "authentication"
        event.event_action = "ssh_login_failure"
        event.user = failure.group("user")
        event.src_ip = failure.group("src_ip")
        event.port = failure.group("port")
        event.severity = "low"
        event.confidence = "high"
        event.tags.extend(["ssh", "login_failure"])
        event.mitre = ["T1110"]
        return
    if sudo := SUDO_RE.search(message):
        event.event_category = "privilege"
        event.event_action = "sudo_command"
        event.command = sudo.group("command")
        event.severity = "medium"
        event.confidence = "high"
        event.tags.extend(["sudo", "privilege"])
        event.mitre = ["T1548.003"]
        return
    if "Started " in message or "Starting " in message:
        event.event_action = "service_started"
        event.tags.append("service")
        return
    if "Stopped " in message or "Stopping " in message:
        event.event_action = "service_stopped"
        event.tags.append("service")
        return
    if "CRON" in message or event.process == "CRON":
        event.event_category = "persistence"
        event.event_action = "cron_execution"
        event.tags.extend(["cron", "scheduled_task"])
        event.mitre = ["T1053.003"]
        return
    lowered = message.lower()
    if "out of memory" in lowered or "oom-killer" in lowered:
        event.event_category = "availability"
        event.event_action = "out_of_memory"
        event.severity = "medium"
        event.tags.append("resource_exhaustion")
    elif "segfault" in lowered:
        event.event_category = "process"
        event.event_action = "process_crash"
        event.severity = "medium"
        event.tags.append("crash")
