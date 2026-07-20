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
        if "Accepted " in msg and " from " in msg:
            sm = SSH_SUCCESS_RE.search(msg)
            if sm:
                event.event_category = "authentication"
                event.event_action = "ssh_login_success"
                event.user = sm.group("user")
                event.src_ip = sm.group("src_ip")
                event.port = sm.group("port")
                event.mitre = ["T1078", "T1021.004"]
                event.severity = "medium"
                event.confidence = "high"
                event.tags = ["ssh", "remote_access", "valid_account"]
                event.summary = (
                    f"Successful SSH login for {event.user} from {event.src_ip}"
                )
                events.append(event)
                continue
        if "Failed " in msg and " from " in msg:
            fm = SSH_FAIL_RE.search(msg)
            if fm:
                event.event_category = "authentication"
                event.event_action = "ssh_login_failure"
                event.user = fm.group("user")
                event.src_ip = fm.group("src_ip")
                event.port = fm.group("port")
                event.mitre = ["T1110"]
                event.severity = "low"
                event.confidence = "high"
                event.tags = ["ssh", "bruteforce", "authentication_failure"]
                event.summary = f"Failed SSH login for {event.user} from {event.src_ip}"
                events.append(event)
                continue
        if proc and "sudo" in proc:
            sudo = SUDO_RE.search(msg)
            if sudo:
                event.event_category = "privilege"
                event.event_action = "sudo_command"
                event.user = sudo.group("user")
                event.command = sudo.group("command").strip()
                event.mitre = ["T1548.003"]
                event.severity = "medium"
                event.confidence = "high"
                event.tags = ["sudo", "privilege_escalation", "command"]
                event.summary = f"{event.user} ran sudo command: {event.command}"
                event.extra = {
                    "pwd": sudo.group("pwd").strip(),
                    "runas": sudo.group("runas").strip(),
                }
                events.append(event)
                continue
        if proc and "su" in proc and "session opened" in msg:
            su = SU_RE.search(msg)
            event.event_category = "privilege"
            event.event_action = "su_session_opened"
            event.user = su.group("user") if su else None
            event.mitre = ["T1078"]
            event.severity = "low"
            event.confidence = "medium"
            event.tags = ["su", "session"]
            event.summary = f"su session opened for {event.user or 'unknown user'}"
            events.append(event)
            continue
        if "password changed for" in msg:
            pm = PASSWD_CHANGE_RE.search(msg)
            if pm:
                event.event_category = "credential_change"
                event.event_action = "password_changed"
                event.user = pm.group("user")
                event.mitre = ["T1098"]
                event.severity = "high" if pm.group("user") == "root" else "medium"
                event.confidence = "high"
                event.tags = ["password_change", "credential"]
                event.detection_names = ["auth_password_changed"]
                event.ttp_flags = ["auth_password_changed"]
                if pm.group("user") == "root":
                    event.detection_names.append("root_password_changed")
                    event.ttp_flags.append("root_password_changed")
                event.summary = f"Password changed for {event.user}"
                events.append(event)
                continue
        if "new user:" in msg:
            um = USERADD_RE.search(msg)
            if um:
                event.event_category = "persistence"
                event.event_action = "user_created"
                event.user = um.group("user")
                event.uid = um.group("uid")
                event.gid = um.group("gid")
                event.mitre = ["T1136.001"]
                event.severity = "high"
                event.confidence = "high"
                event.tags = ["account_management", "user_created"]
                event.detection_names = ["auth_user_created"]
                event.ttp_flags = ["auth_user_created"]
                event.summary = f"New user created: {event.user} uid={event.uid or '?'}"
                event.extra = {"home": um.group("home"), "shell": um.group("shell")}
                events.append(event)
                continue
        if "new group:" in msg:
            gm = GROUPADD_RE.search(msg)
            if gm:
                event.event_category = "persistence"
                event.event_action = "group_created"
                event.gid = gm.group("gid")
                event.mitre = ["T1136.001"]
                event.severity = "medium"
                event.confidence = "high"
                event.tags = ["account_management", "group_created"]
                event.detection_names = ["auth_group_created"]
                event.ttp_flags = ["auth_group_created"]
                event.summary = (
                    f"New group created: {gm.group('group')} gid={event.gid or '?'}"
                )
                event.extra = {"group": gm.group("group")}
                events.append(event)
                continue
        if "delete user" in msg:
            dm = USERDEL_RE.search(msg)
            if dm:
                event.event_category = "persistence"
                event.event_action = "user_deleted"
                event.user = dm.group("user")
                event.mitre = ["T1531"]
                event.severity = "high"
                event.confidence = "high"
                event.tags = ["account_management", "user_deleted"]
                event.detection_names = ["auth_user_deleted"]
                event.ttp_flags = ["auth_user_deleted"]
                event.summary = f"User deleted: {event.user}"
                events.append(event)
                continue
        if "change user" in msg:
            cm = USERMOD_RE.search(msg)
            if cm:
                event.event_category = "persistence"
                event.event_action = "user_modified"
                event.user = cm.group("user")
                event.mitre = ["T1098"]
                event.severity = "medium"
                event.confidence = "high"
                event.tags = ["account_management", "user_modified"]
                event.detection_names = ["auth_user_modified"]
                event.ttp_flags = ["auth_user_modified"]
                event.summary = f"User modified: {event.user}"
                events.append(event)
                continue
        if "account locked" in msg or "account unlocked" in msg:
            lm = ACCT_LOCK_RE.search(msg)
            if lm:
                action = lm.group("action")
                event.event_category = "credential_change"
                event.event_action = f"account_{action}"
                event.user = lm.group("user")
                event.mitre = ["T1098"] if action == "unlocked" else ["T1531"]
                event.severity = "medium"
                event.confidence = "high"
                event.tags = ["account_management", f"account_{action}"]
                event.detection_names = [f"auth_account_{action}"]
                event.ttp_flags = [f"auth_account_{action}"]
                event.summary = f"Account {action}: {event.user}"
                events.append(event)
                continue
        if "Invalid user" in msg:
            iu = INVALID_USER_RE.search(msg)
            if iu:
                event.event_category = "authentication"
                event.event_action = "ssh_invalid_user"
                event.user = iu.group("user")
                event.src_ip = iu.group("src_ip")
                event.port = iu.group("port")
                event.mitre = ["T1110"]
                event.severity = "low"
                event.confidence = "high"
                event.tags = ["ssh", "bruteforce", "invalid_user"]
                event.detection_names = ["ssh_invalid_user_attempt"]
                event.ttp_flags = ["ssh_invalid_user_attempt"]
                event.summary = f"Invalid user {event.user} from {event.src_ip}"
                events.append(event)
                continue
    return events
