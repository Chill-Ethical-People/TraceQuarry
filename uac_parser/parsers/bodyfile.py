from __future__ import annotations

from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_epoch

from .common import read_text_lines


def parse(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for raw in read_text_lines(path):
        if not raw.strip() or raw.startswith("#"):
            continue
        parts = raw.split("|")
        if len(parts) < 11:
            continue
        name = parts[1]
        meta = {
            "inode": parts[2],
            "mode": parts[3],
            "uid": parts[4],
            "gid": parts[5],
            "size": parts[6],
        }
        timestamps = [
            ("atime", "file_accessed", parts[7]),
            ("mtime", "file_modified", parts[8]),
            ("ctime", "metadata_changed", parts[9]),
            ("birthtime", "file_created", parts[10]),
        ]
        for ts_type, action, value in timestamps:
            timestamp = parse_epoch(value)
            if not timestamp:
                continue
            events.append(TimelineEvent(
                timestamp=timestamp,
                timestamp_raw=value,
                timezone="UTC",
                timezone_confidence="source_epoch",
                timestamp_type=ts_type,
                host=host,
                source_path=relative,
                source_type="bodyfile",
                parser="bodyfile",
                event_category="filesystem",
                event_action=action,
                uid=meta["uid"],
                gid=meta["gid"],
                file_path=name,
                severity="informational",
                confidence="medium",
                tags=["bodyfile", "filesystem", ts_type],
                summary=f"{action.replace('_', ' ').title()}: {name}",
                raw=raw,
                extra=meta,
            ))
    return events

