from __future__ import annotations

import binascii
import re
from collections import OrderedDict, defaultdict
from pathlib import Path

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_epoch

from .common import read_text_lines

AUDIT_RE = re.compile(
    r"type=(?P<type>\w+)\s+msg=audit\((?P<epoch>\d+\.\d+):(?P<id>\d+)\):\s*(?P<body>.*)"
)
NODE_RE = re.compile(r"(?:^|\s)node=(?P<node>\S+)")
KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
MAX_PENDING_AUDIT_EVENTS = 4096


def _kv(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in KV_RE.findall(body):
        result[key] = value.strip('"')
    return result


def _decode_audit_value(value: str | None) -> str | None:
    if not value:
        return value
    if re.fullmatch(r"[0-9A-Fa-f]+", value) and len(value) % 2 == 0:
        try:
            decoded = (
                binascii.unhexlify(value)
                .replace(b"\x00", b" ")
                .decode("utf-8", "replace")
                .strip()
            )
            if decoded:
                return decoded
        except (binascii.Error, ValueError):
            return value
    return value


def parse(path: Path, relative: str, host: str = "") -> list[TimelineEvent]:
    grouped: OrderedDict[tuple[str, str, str], list[tuple[str, str, str, str]]] = (
        OrderedDict()
    )
    events: list[TimelineEvent] = []
    for raw in read_text_lines(path):
        match = AUDIT_RE.search(raw)
        if not match:
            continue
        node_match = NODE_RE.search(raw)
        node = node_match.group("node") if node_match else ""
        key = (node, match.group("epoch"), match.group("id"))
        grouped.setdefault(key, []).append(
            (match.group("type"), match.group("epoch"), match.group("body"), raw)
        )
        grouped.move_to_end(key)
        if match.group("type") == "EOE":
            records = grouped.pop(key)
            if event := _event_from_records(key, records, relative, host):
                events.append(event)
        elif len(grouped) > MAX_PENDING_AUDIT_EVENTS:
            oldest_key, records = grouped.popitem(last=False)
            if event := _event_from_records(oldest_key, records, relative, host):
                events.append(event)
    for key, records in grouped.items():
        if event := _event_from_records(key, records, relative, host):
            events.append(event)
    return events


def _event_from_records(
    audit_key: tuple[str, str, str],
    records: list[tuple[str, str, str, str]],
    relative: str,
    host: str,
) -> TimelineEvent | None:
    node, epoch, audit_id = audit_key
    timestamp = parse_epoch(epoch)
    if not timestamp:
        return None
    by_type: dict[str, list[dict[str, str]]] = defaultdict(list)
    raw_lines = []
    for audit_type, _epoch, body, raw in records:
        by_type[audit_type].append(_kv(body))
        raw_lines.append(raw)
    fields: dict[str, str] = {}
    for type_fields in by_type.values():
        for item in type_fields:
            fields.update(item)
    event_type = _primary_type(by_type)
    action, category, severity, mitre, tags, detections = _classify(
        event_type, by_type, fields
    )
    command = _command_from_records(by_type, fields)
    file_path = _path_from_records(by_type)
    event = TimelineEvent(
        timestamp=timestamp,
        timestamp_raw=epoch,
        timezone="UTC",
        timezone_confidence="source_epoch",
        timestamp_type="log_time",
        evidence_role="behavior",
        host=host or node,
        source_path=relative,
        source_type="auditd",
        parser="auditd",
        event_category=category,
        event_action=action,
        uid=fields.get("uid"),
        user=fields.get("acct") or fields.get("auid"),
        process=fields.get("comm") or fields.get("exe"),
        pid=fields.get("pid"),
        src_ip=fields.get("addr"),
        file_path=file_path,
        command=command,
        mitre=mitre,
        severity=severity,
        confidence="medium",
        tags=tags,
        detection_names=detections,
        ttp_flags=detections,
        summary=(
            f"Audit {event_type}: {command or file_path or fields.get('exe') or ''}"
        ).strip(),
        raw="\n".join(raw_lines),
        extra={
            "audit_id": audit_id,
            "audit_node": node,
            "audit_epoch": epoch,
            "record_types": sorted(by_type),
            "fields": fields,
            "auid": fields.get("auid"),
            "session": fields.get("ses"),
            "terminal": fields.get("terminal") or fields.get("tty"),
            "result": fields.get("res") or fields.get("success"),
            "syscall": fields.get("syscall"),
        },
    )
    if rule_key := fields.get("key"):
        event.tags.append(f"audit_key:{rule_key}")
        event.detection_names.extend(_detections_from_key(rule_key))
        event.ttp_flags.extend(_detections_from_key(rule_key))
        event.detection_names = sorted(set(event.detection_names))
        event.ttp_flags = sorted(set(event.ttp_flags))
    return event


def _primary_type(by_type: dict[str, list[dict[str, str]]]) -> str:
    for candidate in (
        "EXECVE",
        "USER_CMD",
        "SYSCALL",
        "PATH",
        "USER_LOGIN",
        "USER_AUTH",
        "SERVICE_START",
        "SERVICE_STOP",
    ):
        if candidate in by_type:
            return candidate
    return next(iter(by_type))


def _command_from_records(
    by_type: dict[str, list[dict[str, str]]], fields: dict[str, str]
) -> str | None:
    if "EXECVE" in by_type:
        args = []
        merged = {}
        for record in by_type["EXECVE"]:
            merged.update(record)
        argc = int(merged.get("argc", "0") or "0")
        for idx in range(argc):
            value = merged.get(f"a{idx}")
            if value:
                args.append(_decode_audit_value(value) or value)
        if args:
            return " ".join(args)
    return _decode_audit_value(fields.get("proctitle")) or fields.get("cmd")


def _path_from_records(by_type: dict[str, list[dict[str, str]]]) -> str | None:
    paths = [
        record.get("name") for record in by_type.get("PATH", []) if record.get("name")
    ]
    return paths[0] if paths else None


def _classify(
    event_type: str, by_type: dict[str, list[dict[str, str]]], fields: dict[str, str]
) -> tuple[str, str, str, list[str], list[str], list[str]]:
    action = "audit_event"
    category = "audit"
    severity = "informational"
    mitre: list[str] = []
    tags = ["auditd", event_type.lower()]
    detections: list[str] = []
    if event_type in {"EXECVE", "USER_CMD"}:
        action = "process_execution"
        category = "execution"
        severity = "low"
        mitre = ["T1059.004"]
    elif event_type in {
        "USER_CHAUTHTOK",
        "USER_ACCT",
        "ADD_USER",
        "DEL_USER",
        "USER_MGMT",
    }:
        action = "user_account_change"
        category = "persistence"
        severity = "medium"
        mitre = ["T1136.001"]
        detections.append("audit_user_account_change")
    elif event_type in {"SERVICE_START", "SERVICE_STOP"}:
        action = event_type.lower()
        category = "system"
    elif event_type in {"USER_LOGIN", "USER_AUTH"}:
        action = event_type.lower()
        category = "authentication"
        severity = "low"
        mitre = ["T1078"]
        if fields.get("res") == "failed" or fields.get("success") == "no":
            detections.append("audit_authentication_failure")
    elif event_type in {"ANOM_ABEND", "ANOM_PROMISCUOUS", "ANOM_LOGIN_FAILURES"}:
        action = event_type.lower()
        category = "anomaly"
        severity = "medium"
        detections.append("audit_anomaly")
    if fields.get("success") == "no":
        tags.append("failed")
    return action, category, severity, mitre, tags, detections


def _detections_from_key(key: str) -> list[str]:
    mapping = {
        "credential_access": "audit_credential_access",
        "cron_persistence": "audit_cron_persistence",
        "ssh_key_tampering": "audit_ssh_key_tampering",
        "kernel_module_load": "audit_kernel_module_load",
        "kernel_module_remove": "audit_kernel_module_remove",
        "log_tampering": "audit_log_tampering",
        "privilege_escalation": "audit_privilege_escalation",
        "exec_from_tmp": "audit_exec_from_tmp",
        "exec_from_shm": "audit_exec_from_shm",
    }
    return [value for needle, value in mapping.items() if needle in key]
