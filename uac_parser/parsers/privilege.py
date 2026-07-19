from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent

from .common import read_text_lines

DANGEROUS_SUDO = re.compile(
    r"\b(vim|vi|nano|less|more|find|bash|sh|python|perl|ruby|tar|zip|rsync|scp|docker|systemctl|service|journalctl)\b",
    re.I,
)


def parse_sudoers(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for lineno, raw in enumerate(read_text_lines(path), start=1):
        text = raw.strip()
        if not text or text.startswith("#") or text.startswith("Defaults"):
            continue
        detections = ["sudoers_rule_observed"]
        severity = "low"
        if "NOPASSWD" in text:
            detections.append("nopasswd_sudo_rule")
            severity = "high"
        if DANGEROUS_SUDO.search(text):
            detections.append("dangerous_sudo_rule_candidate")
            severity = "high" if "NOPASSWD" in text else "medium"
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="sudoers",
                parser="privilege",
                event_category="privilege",
                event_action="sudoers_rule_observed",
                command=text,
                file_path=relative,
                severity=severity,
                confidence="medium",
                tags=["sudo", "privilege"],
                detection_names=detections,
                ttp_flags=detections,
                mitre=["T1548.003"],
                summary=f"Sudoers rule observed in {relative}:{lineno}",
                raw=raw,
                extra={"line": lineno},
            )
        )
    return events


def parse_bodyfile_privilege(
    path: Path, relative: str, host: str = ""
) -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        parts = raw.split("|")
        if len(parts) < 11:
            continue
        name, mode, uid, gid, size = parts[1], parts[3], parts[4], parts[5], parts[6]
        try:
            mode_int = int(mode, 8)
        except ValueError:
            continue
        detections = []
        if mode_int & 0o4000:
            detections.append("suid_file_observed")
        if mode_int & 0o2000:
            detections.append("sgid_file_observed")
        if mode_int & 0o002 and _sensitive_writable_path(name):
            detections.append("world_writable_sensitive_file")
        if not detections:
            continue
        severity = (
            "high"
            if name.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/home/"))
            else "medium"
        )
        if "world_writable_sensitive_file" in detections:
            severity = "high"
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="bodyfile_privilege",
                parser="privilege",
                event_category="privilege",
                event_action="privileged_file_observed",
                uid=uid,
                gid=gid,
                file_path=name,
                severity=severity,
                confidence="medium",
                tags=["suid_sgid", "privilege"],
                detection_names=detections,
                ttp_flags=detections,
                mitre=["T1548.001"],
                summary=f"Privileged file mode observed: {mode} {name}",
                raw=raw,
                extra={"mode": mode, "size": size},
            )
        )
    return events


def _sensitive_writable_path(name: str) -> bool:
    sensitive_prefixes = (
        "/etc/cron",
        "/etc/systemd/system",
        "/etc/init.d",
        "/etc/profile",
        "/etc/pam.d",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt",
    )
    return name.startswith(sensitive_prefixes)


def parse_capabilities(
    path: Path, relative: str, host: str = ""
) -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        text = raw.strip()
        if not text or "=" not in text:
            continue
        detections = ["file_capability_observed"]
        severity = "medium"
        if "cap_setuid" in text or "cap_dac_override" in text:
            detections.append("dangerous_file_capability")
            severity = "high"
        file_path = text.split("=", 1)[0].strip()
        events.append(
            TimelineEvent(
                timestamp="",
                timestamp_type="state_observed",
                timezone_confidence="missing",
                host=host,
                source_path=relative,
                source_type="capabilities",
                parser="privilege",
                event_category="privilege",
                event_action="file_capability_observed",
                file_path=file_path,
                severity=severity,
                confidence="medium",
                tags=["capabilities", "privilege"],
                detection_names=detections,
                ttp_flags=detections,
                mitre=["T1548"],
                summary=f"File capability observed: {text}",
                raw=raw,
            )
        )
    return events
