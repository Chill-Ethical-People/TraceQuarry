from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent

from .common import read_text_lines

KEY_RE = re.compile(
    r"^(?P<opts>(?:[^ ]+,)*[^ ]+\s+)?(?P<type>ssh-[a-z0-9-]+|ecdsa-[a-z0-9-]+|sk-[a-z0-9-]+)\s+(?P<key>\S+)(?:\s+(?P<comment>.*))?$"
)


def parse_authorized_keys(
    path: Path, relative: str, host: str = ""
) -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        match = KEY_RE.match(text)
        detections = ["authorized_key_present"]
        severity = "medium"
        tags = ["ssh", "authorized_keys", "persistence"]
        if text.startswith("command=") or "from=" in text:
            tags.append("restricted_key")
        if "no-pty" not in text and "command=" not in text:
            detections.append("unrestricted_authorized_key")
            severity = "high"
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="authorized_keys",
                parser="ssh",
                event_category="persistence",
                event_action="authorized_key_observed",
                file_path=relative,
                severity=severity,
                confidence="medium",
                tags=tags,
                detection_names=detections,
                ttp_flags=detections,
                mitre=["T1098.004"],
                summary=f"SSH authorized key observed in {relative}:{lineno}",
                raw=raw,
                extra={
                    "line": lineno,
                    "key_type": match.group("type") if match else "",
                    "comment": match.group("comment") if match else "",
                },
            )
        )
    return events


def parse_known_hosts(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        host_field = text.split()[0] if text.split() else ""
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="known_hosts",
                parser="ssh",
                event_category="lateral_movement",
                event_action="known_host_observed",
                dst_ip=host_field if any(c.isdigit() for c in host_field) else None,
                file_path=relative,
                severity="low",
                confidence="low",
                tags=["ssh", "known_hosts"],
                detection_names=["ssh_known_host_observed"],
                ttp_flags=["ssh_known_host_observed"],
                mitre=["T1021.004"],
                summary=f"SSH known host observed: {host_field}",
                raw=raw,
                extra={"line": lineno},
            )
        )
    return events


def parse_sshd_config(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    risky = {
        "permitrootlogin": {"yes", "without-password", "prohibit-password"},
        "passwordauthentication": {"yes"},
        "permitemptypasswords": {"yes"},
    }
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].lower(), parts[1].strip().lower()
        detections = []
        severity = "informational"
        if key in risky and value in risky[key]:
            detections.append(f"risky_sshd_{key}")
            severity = "medium"
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="sshd_config",
                parser="ssh",
                event_category="configuration",
                event_action="sshd_config_observed",
                file_path=relative,
                severity=severity,
                confidence="medium",
                tags=["ssh", "configuration"],
                detection_names=detections,
                ttp_flags=detections,
                mitre=["T1021.004"] if detections else [],
                summary=f"sshd config {parts[0]}={parts[1]}",
                raw=raw,
                extra={"line": lineno, "key": key, "value": value},
            )
        )
    return events
