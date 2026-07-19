from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_last_style

from .common import read_text_lines

LAST_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<src>\S+)\s+"
    r"(?P<dow>[A-Z][a-z]{2})\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2})(?:\s+(?P<year>\d{4}))?"
)


def parse_last_output(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
) -> list[TimelineEvent]:
    events = []
    failed = (
        "lastb" in relative.lower()
        or "btmp" in relative.lower()
        or "failed" in relative.lower()
    )
    for raw in read_text_lines(path):
        if not raw.strip() or raw.startswith(("wtmp", "btmp", "reboot", "shutdown")):
            continue
        match = LAST_RE.match(raw)
        if not match:
            continue
        timestamp = parse_last_style(
            match.group("mon"),
            match.group("day"),
            match.group("time"),
            int(match.group("year") or year or 0) or None,
            timezone_name,
        )
        events.append(
            TimelineEvent(
                timestamp=timestamp or "",
                timestamp_raw=" ".join(
                    filter(
                        None,
                        [
                            match.group("mon"),
                            match.group("day"),
                            match.group("time"),
                            match.group("year") or str(year or ""),
                        ],
                    )
                ),
                timezone=timezone_name,
                timezone_confidence="assumed_local" if timestamp else "missing",
                timestamp_type="log_time" if timestamp else "unknown",
                host=host,
                source_path=relative,
                source_type="login_history",
                parser="login",
                event_category="authentication",
                event_action="login_failed" if failed else "login_session",
                user=match.group("user"),
                src_ip=match.group("src"),
                severity="medium" if failed else "low",
                confidence="medium",
                tags=["login_history", "btmp" if failed else "wtmp"],
                detection_names=["failed_login_history"] if failed else [],
                ttp_flags=["failed_login_history"] if failed else [],
                mitre=["T1110"] if failed else ["T1078"],
                summary=f"{'Failed login' if failed else 'Login session'} for {match.group('user')} from {match.group('src')}",
                raw=raw,
                extra={"tty": match.group("tty")},
            )
        )
    return events
