from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import to_utc_iso

from .common import read_text_lines


LOGIN_SHELLS = {"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/usr/bin/bash", "/usr/bin/zsh"}
NOLOGIN_SHELLS = {"/bin/false", "/usr/sbin/nologin", "/sbin/nologin", "/bin/sync"}
_EPOCH_ORIGIN = date(1970, 1, 1)


def parse_passwd(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        user, _, uid, gid, comment, home, shell = parts[:7]
        tags = ["account", "passwd"]
        detections = []
        severity = "informational"
        if uid == "0" and user != "root":
            detections.append("uid0_non_root_account")
            tags.append("privilege_risk")
            severity = "high"
        if uid.isdigit() and 0 < int(uid) < 1000 and shell in LOGIN_SHELLS:
            detections.append("interactive_shell_for_system_account")
            severity = "medium"
        event = TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="passwd", parser="accounts",
            event_category="account", event_action="account_observed", user=user, uid=uid, gid=gid,
            file_path="/etc/passwd", severity=severity, confidence="medium", tags=tags,
            summary=f"Account observed: {user} uid={uid} shell={shell}", raw=raw,
            detection_names=detections, ttp_flags=detections,
            mitre=["T1136.001"] if detections else [],
            extra={"comment": comment, "home": home, "shell": shell},
        )
        events.append(event)
    return events


def _shadow_day_to_iso(day_str: str) -> str:
    try:
        days = int(day_str)
    except (ValueError, TypeError):
        return ""
    if days <= 0:
        return ""
    d = _EPOCH_ORIGIN + timedelta(days=days)
    dt = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    return to_utc_iso(dt)


def parse_shadow(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 2:
            continue
        user, pwd_hash = parts[0], parts[1]
        last_change_day = parts[2] if len(parts) > 2 else ""
        timestamp = _shadow_day_to_iso(last_change_day)
        detections = []
        severity = "informational"
        if pwd_hash and pwd_hash not in {"*", "!", "!!", "x"}:
            detections.append("local_password_hash_present")
            severity = "low"
        if pwd_hash.startswith("$1$"):
            detections.append("weak_md5_password_hash")
            severity = "medium"
        events.append(TimelineEvent(
            timestamp=timestamp,
            timestamp_type="password_change_time" if timestamp else "state_observed",
            timezone="UTC",
            timezone_confidence="source_epoch" if timestamp else "missing",
            host=host, source_path=relative, source_type="shadow", parser="accounts",
            event_category="account", event_action="password_state_observed", user=user,
            file_path="/etc/shadow", severity=severity, confidence="medium",
            tags=["account", "shadow"], detection_names=detections, ttp_flags=detections,
            mitre=["T1003.008"] if detections else [],
            summary=f"Password state observed for {user} (last changed: {last_change_day}d)",
            raw="[shadow hash redacted]",
            extra={"last_change_day": last_change_day, "hash_type": _hash_type(pwd_hash)},
        ))
    return events


def _hash_type(pwd_hash: str) -> str:
    if pwd_hash.startswith("$1$"):
        return "MD5"
    if pwd_hash.startswith("$5$"):
        return "SHA-256"
    if pwd_hash.startswith("$6$"):
        return "SHA-512"
    if pwd_hash.startswith("$y$"):
        return "yescrypt"
    if pwd_hash in {"*", "!", "!!", "x", ""}:
        return "locked_or_disabled"
    return "unknown"


def parse_group(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    events = []
    privileged = {"root", "sudo", "wheel", "admin", "docker", "lxd"}
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 4:
            continue
        group, _, gid, members = parts[:4]
        member_list = [m for m in members.split(",") if m]
        detections = []
        severity = "informational"
        if group in privileged and member_list:
            detections.append("privileged_group_membership")
            severity = "medium"
        if group in {"docker", "lxd"} and member_list:
            detections.append("container_group_privilege_risk")
            severity = "high"
        events.append(TimelineEvent(
            timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
            host=host, source_path=relative, source_type="group", parser="accounts",
            event_category="account", event_action="group_observed", gid=gid,
            file_path="/etc/group", severity=severity, confidence="medium",
            tags=["account", "group"], detection_names=detections, ttp_flags=detections,
            mitre=["T1611", "T1548"] if detections else [],
            summary=f"Group observed: {group} members={members}", raw=raw,
            extra={"group": group, "members": member_list},
        ))
    return events

