from __future__ import annotations

import re
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_syslog

from .common import read_syslog_lines

PROC_RE = re.compile(
    r"^\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
SSH_SUCCESS_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SSH_FAIL_RE = re.compile(
    r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*(?:TTY=(?P<tty>[^;]+)\s*;\s*)?PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<runas>[^;]+)\s*;\s*COMMAND=(?P<command>.*)"
)
SU_RE = re.compile(r"session opened for user (?P<user>\S+)")
PASSWD_CHANGE_RE = re.compile(r"password changed for (?P<user>\S+)")
USERADD_RE = re.compile(
    r"new user: name=(?P<user>[^,\s]+)"
    r"(?:,\s*UID=(?P<uid>\d+))?"
    r"(?:,\s*GID=(?P<gid>\d+))?"
    r"(?:,\s*home=(?P<home>[^,\s]+))?"
    r"(?:,\s*shell=(?P<shell>[^,\s]+))?"
)
GROUPADD_RE = re.compile(r"new group: name=(?P<group>[^,\s]+)(?:,\s*GID=(?P<gid>\d+))?")
USERDEL_RE = re.compile(r"delete user '(?P<user>\S+?)'")
USERMOD_RE = re.compile(r"change user '(?P<user>\S+?)'")
GROUP_MEMBER_RE = re.compile(r"members of '(?P<group>\S+?)': (?P<members>.*)")
ACCT_LOCK_RE = re.compile(r"user (?P<user>\S+) account (?P<action>locked|unlocked)")
SSH_DISCONNECT_RE = re.compile(
    r"Disconnected from (?:authenticating\s+)?user (?P<user>\S+) (?P<src_ip>\S+) port (?P<port>\d+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)"
)


def parse(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for raw, resolved_year in read_syslog_lines(path, year):
        timestamp = parse_syslog(raw, year=resolved_year, timezone_name=timezone_name)
        if not timestamp:
            continue
        match = PROC_RE.match(raw)
        proc = match.group("proc") if match else None
        pid = match.group("pid") if match else None
        msg = match.group("msg") if match else raw
        event = TimelineEvent(
            timestamp=timestamp,
            timestamp_raw=raw[:15],
            timezone=timezone_name,
            timezone_confidence="assumed_local",
            timestamp_type="log_time",
            host=host or (match.group("host") if match else ""),
            source_path=relative,
            source_type="auth_log",
            parser="auth",
            process=proc,
            pid=pid,
            raw=raw,
        )
        if _classify_event(event, msg, proc):
            events.append(event)
    return events


def _classify_event(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    handlers = (
        _ssh_success,
        _ssh_failure,
        _sudo_command,
        _su_session,
        _password_change,
        _user_created,
        _group_created,
        _user_deleted,
        _user_modified,
        _account_lock_change,
        _invalid_user,
    )
    return any(handler(event, msg, proc) for handler in handlers)


def _ssh_success(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = (
        SSH_SUCCESS_RE.search(msg) if "Accepted " in msg and " from " in msg else None
    )
    if not match:
        return False
    event.event_category = "authentication"
    event.event_action = "ssh_login_success"
    event.user = match.group("user")
    event.src_ip = match.group("src_ip")
    event.port = match.group("port")
    event.mitre = ["T1078", "T1021.004"]
    event.severity = "medium"
    event.confidence = "high"
    event.tags = ["ssh", "remote_access", "valid_account"]
    event.summary = f"Successful SSH login for {event.user} from {event.src_ip}"
    return True


def _ssh_failure(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = SSH_FAIL_RE.search(msg) if "Failed " in msg and " from " in msg else None
    if not match:
        return False
    event.event_category = "authentication"
    event.event_action = "ssh_login_failure"
    event.user = match.group("user")
    event.src_ip = match.group("src_ip")
    event.port = match.group("port")
    event.mitre = ["T1110"]
    event.severity = "low"
    event.confidence = "high"
    event.tags = ["ssh", "bruteforce", "authentication_failure"]
    event.summary = f"Failed SSH login for {event.user} from {event.src_ip}"
    return True


def _sudo_command(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = SUDO_RE.search(msg) if proc and "sudo" in proc else None
    if not match:
        return False
    event.event_category = "privilege"
    event.event_action = "sudo_command"
    event.user = match.group("user")
    event.command = match.group("command").strip()
    event.mitre = ["T1548.003"]
    event.severity = "medium"
    event.confidence = "high"
    event.tags = ["sudo", "privilege_escalation", "command"]
    event.summary = f"{event.user} ran sudo command: {event.command}"
    event.extra = {
        "pwd": match.group("pwd").strip(),
        "runas": match.group("runas").strip(),
    }
    return True


def _su_session(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    if not proc or "su" not in proc or "session opened" not in msg:
        return False
    match = SU_RE.search(msg)
    event.event_category = "privilege"
    event.event_action = "su_session_opened"
    event.user = match.group("user") if match else None
    event.mitre = ["T1078"]
    event.severity = "low"
    event.confidence = "medium"
    event.tags = ["su", "session"]
    event.summary = f"su session opened for {event.user or 'unknown user'}"
    return True


def _password_change(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = PASSWD_CHANGE_RE.search(msg) if "password changed for" in msg else None
    if not match:
        return False
    event.event_category = "credential_change"
    event.event_action = "password_changed"
    event.user = match.group("user")
    event.mitre = ["T1098"]
    event.severity = "high" if event.user == "root" else "medium"
    event.confidence = "high"
    event.tags = ["password_change", "credential"]
    event.detection_names = ["auth_password_changed"]
    event.ttp_flags = ["auth_password_changed"]
    if event.user == "root":
        event.detection_names.append("root_password_changed")
        event.ttp_flags.append("root_password_changed")
    event.summary = f"Password changed for {event.user}"
    return True


def _user_created(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = USERADD_RE.search(msg) if "new user:" in msg else None
    if not match:
        return False
    event.event_category = "persistence"
    event.event_action = "user_created"
    event.user = match.group("user")
    event.uid = match.group("uid")
    event.gid = match.group("gid")
    event.mitre = ["T1136.001"]
    event.severity = "high"
    event.confidence = "high"
    event.tags = ["account_management", "user_created"]
    event.detection_names = ["auth_user_created"]
    event.ttp_flags = ["auth_user_created"]
    event.summary = f"New user created: {event.user} uid={event.uid or '?'}"
    event.extra = {"home": match.group("home"), "shell": match.group("shell")}
    return True


def _group_created(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = GROUPADD_RE.search(msg) if "new group:" in msg else None
    if not match:
        return False
    event.event_category = "persistence"
    event.event_action = "group_created"
    event.gid = match.group("gid")
    event.mitre = ["T1136.001"]
    event.severity = "medium"
    event.confidence = "high"
    event.tags = ["account_management", "group_created"]
    event.detection_names = ["auth_group_created"]
    event.ttp_flags = ["auth_group_created"]
    event.summary = f"New group created: {match.group('group')} gid={event.gid or '?'}"
    event.extra = {"group": match.group("group")}
    return True


def _user_deleted(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = USERDEL_RE.search(msg) if "delete user" in msg else None
    if not match:
        return False
    event.event_category = "persistence"
    event.event_action = "user_deleted"
    event.user = match.group("user")
    event.mitre = ["T1531"]
    event.severity = "high"
    event.confidence = "high"
    event.tags = ["account_management", "user_deleted"]
    event.detection_names = ["auth_user_deleted"]
    event.ttp_flags = ["auth_user_deleted"]
    event.summary = f"User deleted: {event.user}"
    return True


def _user_modified(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = USERMOD_RE.search(msg) if "change user" in msg else None
    if not match:
        return False
    event.event_category = "persistence"
    event.event_action = "user_modified"
    event.user = match.group("user")
    event.mitre = ["T1098"]
    event.severity = "medium"
    event.confidence = "high"
    event.tags = ["account_management", "user_modified"]
    event.detection_names = ["auth_user_modified"]
    event.ttp_flags = ["auth_user_modified"]
    event.summary = f"User modified: {event.user}"
    return True


def _account_lock_change(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    relevant = "account locked" in msg or "account unlocked" in msg
    match = ACCT_LOCK_RE.search(msg) if relevant else None
    if not match:
        return False
    action = match.group("action")
    event.event_category = "credential_change"
    event.event_action = f"account_{action}"
    event.user = match.group("user")
    event.mitre = ["T1098"] if action == "unlocked" else ["T1531"]
    event.severity = "medium"
    event.confidence = "high"
    event.tags = ["account_management", f"account_{action}"]
    event.detection_names = [f"auth_account_{action}"]
    event.ttp_flags = [f"auth_account_{action}"]
    event.summary = f"Account {action}: {event.user}"
    return True


def _invalid_user(event: TimelineEvent, msg: str, proc: str | None) -> bool:
    match = INVALID_USER_RE.search(msg) if "Invalid user" in msg else None
    if not match:
        return False
    event.event_category = "authentication"
    event.event_action = "ssh_invalid_user"
    event.user = match.group("user")
    event.src_ip = match.group("src_ip")
    event.port = match.group("port")
    event.mitre = ["T1110"]
    event.severity = "low"
    event.confidence = "high"
    event.tags = ["ssh", "bruteforce", "invalid_user"]
    event.detection_names = ["ssh_invalid_user_attempt"]
    event.ttp_flags = ["ssh_invalid_user_attempt"]
    event.summary = f"Invalid user {event.user} from {event.src_ip}"
    return True
