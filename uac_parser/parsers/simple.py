from __future__ import annotations

from pathlib import Path
import re

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_any, parse_syslog

from .common import read_text_lines


BASH_TS_RE = re.compile(r"^#(?P<epoch>\d{9,11})$")
WEB_RE = re.compile(r'(?P<src_ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+) [^"]+" (?P<status>\d{3}) (?P<size>\S+)')


def parse_cron(path: Path, relative: str, host: str = "", year: int | None = None, timezone_name: str = "UTC") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        ts = parse_syslog(raw, year=year, timezone_name=timezone_name)
        if not ts:
            continue
        events.append(TimelineEvent(
            timestamp=ts, timestamp_raw=raw[:15], timezone=timezone_name, timezone_confidence="assumed_local",
            timestamp_type="log_time", host=host, source_path=relative, source_type="cron",
            parser="cron", event_category="persistence", event_action="cron_execution",
            mitre=["T1053.003"], severity="low", confidence="medium",
            tags=["cron", "scheduled_task"], summary=raw, raw=raw,
        ))
    return events


def parse_shell_history(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    pending_ts = None
    line_no = 0
    for raw in read_text_lines(path):
        line_no += 1
        match = BASH_TS_RE.match(raw.strip())
        if match:
            from uac_parser.timeline.timestamp import parse_epoch
            pending_ts = parse_epoch(match.group("epoch"))
            continue
        command = raw.strip()
        if not command:
            continue
        events.append(TimelineEvent(
            timestamp=pending_ts or "",
            timestamp_raw=str(line_no) if not pending_ts else pending_ts,
            timezone="UTC",
            timezone_confidence="source_epoch" if pending_ts else "missing",
            timestamp_type="command_time" if pending_ts else "unknown",
            host=host,
            source_path=relative,
            source_type="shell_history",
            parser="shell_history",
            event_category="execution",
            event_action="shell_command",
            command=command,
            severity="low",
            confidence="medium" if pending_ts else "low",
            tags=["shell_history", "command"],
            summary=f"Shell command: {command}",
            raw=raw,
            extra={"line": line_no},
        ))
        pending_ts = None
    return events


def parse_package_log(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        ts = parse_any(raw[:25])
        if not ts:
            continue
        action = "package_activity"
        if " install " in raw.lower() or " installed " in raw.lower():
            action = "package_installed"
        elif " remove " in raw.lower() or " removed " in raw.lower():
            action = "package_removed"
        elif " upgrade " in raw.lower() or " upgraded " in raw.lower():
            action = "package_updated"
        events.append(TimelineEvent(
            timestamp=ts, timestamp_raw=raw[:25], timezone="UTC", timezone_confidence="assumed",
            timestamp_type="log_time", host=host, source_path=relative, source_type="package_log",
            parser="package_log", event_category="software", event_action=action,
            severity="informational", confidence="medium", tags=["package", "software"],
            summary=raw, raw=raw,
        ))
    return events


def parse_systemd(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    content = "\n".join(read_text_lines(path))
    action = "systemd_unit_observed"
    severity = "low"
    tags = ["systemd"]
    mitre = ["T1543.002"]
    if "[Service]" in content or "[Timer]" in content:
        if "ExecStart=" in content:
            action = "systemd_service_definition"
            severity = "medium"
    events.append(TimelineEvent(
        timestamp="", timestamp_raw="", timezone="UTC", timezone_confidence="missing",
        timestamp_type="file_observed", host=host, source_path=relative, source_type="systemd",
        parser="systemd", event_category="persistence", event_action=action,
        file_path=relative, mitre=mitre, severity=severity, confidence="medium",
        tags=tags, summary=f"Systemd unit observed: {relative}", raw=content[:4000],
    ))
    return events


def parse_web_log(path: Path, relative: str, host: str = "", year: int | None = None, timezone_name: str = "UTC") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        match = WEB_RE.search(raw)
        if not match:
            continue
        ts = parse_any(match.group("ts"), year=year, timezone_name=timezone_name)
        if not ts:
            continue
        uri = match.group("uri")
        severity = "informational"
        tags = ["web", "http"]
        if any(x in uri.lower() for x in ("cmd=", "shell", "upload", ".php", "../", "%2e%2e")):
            severity = "medium"
            tags.append("web_attack_candidate")
        events.append(TimelineEvent(
            timestamp=ts, timestamp_raw=match.group("ts"), timezone="UTC", timezone_confidence="source_or_assumed",
            timestamp_type="log_time", host=host, source_path=relative, source_type="web_log",
            parser="web_log", event_category="web", event_action="http_request",
            src_ip=match.group("src_ip"), severity=severity, confidence="medium", tags=tags,
            summary=f"{match.group('method')} {uri} returned {match.group('status')}",
            raw=raw, extra={"method": match.group("method"), "uri": uri, "status": match.group("status")},
        ))
    return events
