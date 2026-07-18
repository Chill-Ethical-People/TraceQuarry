from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import to_utc_iso

from .common import read_text_lines

EPOCH_ORIGIN = date(1970, 1, 1)


def _shadow_date_to_iso(days_str: str) -> str:
    try:
        days = int(days_str)
    except (ValueError, TypeError):
        return ""
    if days <= 0:
        return ""
    d = EPOCH_ORIGIN + timedelta(days=days)
    from datetime import datetime, timezone
    dt = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    return to_utc_iso(dt)


def _parse_passwd_dict(path: Path) -> dict[str, dict[str, str]]:
    result = {}
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        user = parts[0]
        result[user] = {
            "uid": parts[2], "gid": parts[3], "comment": parts[4],
            "home": parts[5], "shell": parts[6], "raw": raw,
        }
    return result


def _parse_shadow_dict(path: Path) -> dict[str, dict[str, str]]:
    result = {}
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 2:
            continue
        user = parts[0]
        result[user] = {
            "hash": parts[1],
            "last_change_day": parts[2] if len(parts) > 2 else "",
            "raw": raw,
        }
    return result


def _parse_group_dict(path: Path) -> dict[str, dict[str, str]]:
    result = {}
    for raw in read_text_lines(path):
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(":")
        if len(parts) < 4:
            continue
        group = parts[0]
        result[group] = {
            "gid": parts[2],
            "members": parts[3],
            "raw": raw,
        }
    return result


def _is_locked(hash_val: str) -> bool:
    return hash_val in {"*", "!", "!!", "x", ""} or hash_val.startswith("!")


def diff_accounts(root: Path, host: str = "") -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    events.extend(_diff_passwd(root, host))
    events.extend(_diff_shadow(root, host))
    events.extend(_diff_group(root, host))
    return events


def _find_file(root: Path, *candidates: str) -> Path | None:
    for candidate in candidates:
        for path in root.rglob(candidate):
            if path.is_file():
                return path
    return None


def _diff_passwd(root: Path, host: str) -> list[TimelineEvent]:
    current_path = _find_file(root, "etc/passwd")
    backup_path = _find_file(root, "etc/passwd-")
    if not current_path or not backup_path:
        return []
    current = _parse_passwd_dict(current_path)
    backup = _parse_passwd_dict(backup_path)
    events = []
    for user, info in current.items():
        if user not in backup:
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/passwd vs etc/passwd-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="account_created_since_backup", user=user, uid=info["uid"],
                file_path="/etc/passwd", severity="high", confidence="high",
                tags=["account", "account_diff", "account_created"],
                detection_names=["account_created_since_backup"],
                ttp_flags=["account_created_since_backup"], mitre=["T1136.001"],
                summary=f"Account created since backup: {user} uid={info['uid']} shell={info['shell']}",
                raw=info["raw"],
                extra={"shell": info["shell"], "home": info["home"], "comment": info["comment"]},
            ))
        else:
            old = backup[user]
            changes = []
            if info["shell"] != old["shell"]:
                changes.append(f"shell: {old['shell']} -> {info['shell']}")
            if info["uid"] != old["uid"]:
                changes.append(f"uid: {old['uid']} -> {info['uid']}")
            if info["home"] != old["home"]:
                changes.append(f"home: {old['home']} -> {info['home']}")
            if changes:
                events.append(TimelineEvent(
                    timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                    host=host, source_path="etc/passwd vs etc/passwd-", source_type="account_diff",
                    parser="account_diff", event_category="persistence",
                    event_action="account_modified_since_backup", user=user, uid=info["uid"],
                    file_path="/etc/passwd", severity="medium", confidence="high",
                    tags=["account", "account_diff", "account_modified"],
                    detection_names=["account_modified_since_backup"],
                    ttp_flags=["account_modified_since_backup"], mitre=["T1098"],
                    summary=f"Account modified since backup: {user} ({', '.join(changes)})",
                    raw=info["raw"], extra={"changes": changes},
                ))
    for user, info in backup.items():
        if user not in current:
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/passwd vs etc/passwd-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="account_deleted_since_backup", user=user, uid=info["uid"],
                file_path="/etc/passwd", severity="high", confidence="high",
                tags=["account", "account_diff", "account_deleted"],
                detection_names=["account_deleted_since_backup"],
                ttp_flags=["account_deleted_since_backup"], mitre=["T1531"],
                summary=f"Account deleted since backup: {user} uid={info['uid']}",
                raw=info["raw"],
            ))
    return events


def _diff_shadow(root: Path, host: str) -> list[TimelineEvent]:
    current_path = _find_file(root, "etc/shadow")
    backup_path = _find_file(root, "etc/shadow-")
    if not current_path or not backup_path:
        return []
    current = _parse_shadow_dict(current_path)
    backup = _parse_shadow_dict(backup_path)
    events = []
    for user, info in current.items():
        old = backup.get(user)
        if not old:
            ts = _shadow_date_to_iso(info["last_change_day"])
            events.append(TimelineEvent(
                timestamp=ts, timestamp_type="password_change_time" if ts else "state_observed",
                timezone="UTC", timezone_confidence="source_epoch" if ts else "missing",
                host=host, source_path="etc/shadow vs etc/shadow-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="password_set_new_account", user=user,
                file_path="/etc/shadow", severity="high", confidence="high",
                tags=["account", "account_diff", "password_set", "new_account"],
                detection_names=["password_set_new_account"],
                ttp_flags=["password_set_new_account"], mitre=["T1136.001"],
                summary=f"Password set for new account: {user}",
                raw="[shadow hash redacted]",
                extra={"last_change_day": info["last_change_day"]},
            ))
            continue
        if info["hash"] != old["hash"]:
            was_locked = _is_locked(old["hash"])
            now_locked = _is_locked(info["hash"])
            ts = _shadow_date_to_iso(info["last_change_day"])
            if was_locked and not now_locked:
                action = "account_unlocked"
                summary = f"Account unlocked (password set): {user}"
                severity = "high"
                detections = ["account_unlocked_since_backup"]
                mitre = ["T1098"]
            elif not was_locked and now_locked:
                action = "account_locked"
                summary = f"Account locked: {user}"
                severity = "medium"
                detections = ["account_locked_since_backup"]
                mitre = ["T1531"]
            else:
                action = "password_changed"
                summary = f"Password changed for: {user}"
                severity = "high" if user == "root" else "medium"
                detections = ["password_changed_since_backup"]
                if user == "root":
                    detections.append("root_password_changed")
                mitre = ["T1098"]
            events.append(TimelineEvent(
                timestamp=ts, timestamp_type="password_change_time" if ts else "state_observed",
                timezone="UTC", timezone_confidence="source_epoch" if ts else "missing",
                host=host, source_path="etc/shadow vs etc/shadow-", source_type="account_diff",
                parser="account_diff", event_category="credential_change",
                event_action=action, user=user,
                file_path="/etc/shadow", severity=severity, confidence="high",
                tags=["account", "account_diff", "credential_change"],
                detection_names=detections, ttp_flags=detections, mitre=mitre,
                summary=summary, raw="[shadow hash redacted]",
                extra={
                    "was_locked": was_locked, "now_locked": now_locked,
                    "last_change_day": info["last_change_day"],
                },
            ))
    return events


def _diff_group(root: Path, host: str) -> list[TimelineEvent]:
    current_path = _find_file(root, "etc/group")
    backup_path = _find_file(root, "etc/group-")
    if not current_path or not backup_path:
        return []
    current = _parse_group_dict(current_path)
    backup = _parse_group_dict(backup_path)
    privileged = {"root", "sudo", "wheel", "admin", "docker", "lxd", "shadow", "adm"}
    events = []
    for group, info in current.items():
        old = backup.get(group)
        if not old:
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/group vs etc/group-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="group_created_since_backup",
                file_path="/etc/group", severity="medium", confidence="high",
                tags=["account", "account_diff", "group_created"],
                detection_names=["group_created_since_backup"],
                ttp_flags=["group_created_since_backup"], mitre=["T1136.001"],
                summary=f"Group created since backup: {group} gid={info['gid']} members={info['members']}",
                raw=info["raw"], extra={"group": group, "members": info["members"]},
            ))
            continue
        cur_members = set(m for m in info["members"].split(",") if m)
        old_members = set(m for m in old["members"].split(",") if m)
        added = cur_members - old_members
        removed = old_members - cur_members
        is_priv = group in privileged
        for member in added:
            severity = "high" if is_priv else "medium"
            detections = ["group_member_added"]
            if is_priv:
                detections.append("privileged_group_member_added")
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/group vs etc/group-", source_type="account_diff",
                parser="account_diff", event_category="privilege",
                event_action="group_member_added", user=member,
                file_path="/etc/group", severity=severity, confidence="high",
                tags=["account", "account_diff", "group_membership"],
                detection_names=detections, ttp_flags=detections,
                mitre=["T1098"] if is_priv else [],
                summary=f"User {member} added to group {group} since backup",
                raw=info["raw"], extra={"group": group, "old_members": sorted(old_members)},
            ))
        for member in removed:
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/group vs etc/group-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="group_member_removed", user=member,
                file_path="/etc/group", severity="medium", confidence="high",
                tags=["account", "account_diff", "group_membership"],
                detection_names=["group_member_removed"],
                ttp_flags=["group_member_removed"], mitre=[],
                summary=f"User {member} removed from group {group} since backup",
                raw=old["raw"], extra={"group": group},
            ))
    for group, info in backup.items():
        if group not in current:
            events.append(TimelineEvent(
                timestamp="", timestamp_type="state_observed", timezone_confidence="missing",
                host=host, source_path="etc/group vs etc/group-", source_type="account_diff",
                parser="account_diff", event_category="persistence",
                event_action="group_deleted_since_backup",
                file_path="/etc/group", severity="medium", confidence="high",
                tags=["account", "account_diff", "group_deleted"],
                detection_names=["group_deleted_since_backup"],
                ttp_flags=["group_deleted_since_backup"], mitre=[],
                summary=f"Group deleted since backup: {group}",
                raw=info["raw"], extra={"group": group},
            ))
    return events
