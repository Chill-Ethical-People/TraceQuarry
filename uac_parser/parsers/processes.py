from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent

from .common import read_text_lines

PS_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\S+)\s+(?P<mem>\S+)\s+"
    r"(?P<vsz>\d+)\s+(?P<rss>\d+)\s+(?P<tty>\S+)\s+(?P<stat>\S+)\s+"
    r"(?P<start>\S+)\s+(?P<time>\S+)\s+(?P<command>.+)$"
)

SUSPICIOUS_PROCS = re.compile(
    r"\b(xmrig|kinsing|minerd|xmr-stak|cryptonight|"
    r"chisel|frpc?|ngrok|cloudflared|"
    r"nc\s+-[el]|ncat\s+-[el]|socat\s+tcp|"
    r"bash\s+-i|python.*pty\.spawn|perl.*socket|"
    r"rclone|megacmd)\b",
    re.I,
)

SUSPICIOUS_PATHS = re.compile(
    r"(/tmp/|/var/tmp/|/dev/shm/|/run/user/\d+/|/home/[^/]+/\.cache/)", re.I
)


def parse_ps(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        match = PS_RE.match(raw)
        if not match:
            continue
        user = match.group("user")
        pid = match.group("pid")
        command = match.group("command").strip()
        stat = match.group("stat")

        detections: list[str] = ["process_observed"]
        severity = "informational"
        tags = ["process"]
        mitre: list[str] = []

        if SUSPICIOUS_PROCS.search(command):
            detections.append("suspicious_process")
            severity = "high"
            tags.append("suspicious")
            mitre = ["T1059"]

        if SUSPICIOUS_PATHS.search(command):
            detections.append("process_from_suspicious_path")
            severity = max(
                severity,
                "medium",
                key=lambda s: {
                    "informational": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                }.get(s, 0),
            )
            tags.append("tmp_execution")
            mitre = mitre or ["T1059.004"]

        if user == "root" and "[" not in command:
            cmd_base = command.split()[0] if command.split() else ""
            if (
                cmd_base
                and not cmd_base.startswith(
                    ("/usr/", "/sbin/", "/bin/", "/lib/", "/opt/", "[")
                )
                and any(
                    p in cmd_base for p in ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/")
                )
            ):
                detections.append("root_process_from_unusual_path")
                severity = "high"
                tags.append("privilege_risk")

        if severity == "informational":
            continue

        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                evidence_role="state_observation",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="process_list",
                parser="processes",
                event_category="execution",
                event_action="process_running",
                user=user,
                pid=pid,
                command=command,
                process=command.split()[0] if command else None,
                severity=severity,
                confidence="medium",
                tags=tags,
                detection_names=detections,
                ttp_flags=detections,
                mitre_candidates=mitre,
                summary=f"Process running: {user} pid={pid} {command[:120]}",
                raw=raw,
                extra={
                    "stat": stat,
                    "cpu": match.group("cpu"),
                    "mem": match.group("mem"),
                },
            )
        )
    return events
