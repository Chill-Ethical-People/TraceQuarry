from __future__ import annotations

from collections import defaultdict

from uac_parser.timeline.event import TimelineEvent

STATE_SOURCES = {
    "authorized_keys",
    "cron_file",
    "ld_preload",
    "pam_config",
    "profile",
    "rc_local",
    "sshd_config",
    "sudoers",
    "systemd_unit",
}


def correlate_state_events(events: list[TimelineEvent]) -> list[TimelineEvent]:
    bodyfile_by_path: dict[str, list[TimelineEvent]] = defaultdict(list)
    audit_by_path: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        normalized = _norm(event.file_path)
        if not normalized:
            continue
        if event.source_type == "bodyfile":
            bodyfile_by_path[normalized].append(event)
        if event.source_type == "auditd" and event.timestamp:
            audit_by_path[normalized].append(event)

    for event in events:
        if event.timestamp or event.source_type not in STATE_SOURCES:
            continue
        candidates = _candidate_paths(event)
        correlated = []
        for candidate in candidates:
            correlated.extend(bodyfile_by_path.get(candidate, []))
            correlated.extend(audit_by_path.get(candidate, []))
        if not correlated:
            continue
        best = _best_timestamp(correlated)
        if not best:
            continue
        event.timestamp = best.timestamp
        event.timestamp_raw = best.timestamp_raw
        event.timestamp_type = f"correlated_{best.timestamp_type}"
        event.timestamp_precision = best.timestamp_precision
        event.timestamp_confidence = "low"
        event.evidence_role = "inference"
        event.time_start = best.timestamp
        event.time_end = event.time_end or best.timestamp
        event.timezone = best.timezone
        event.timezone_confidence = "correlated"
        event.confidence = _lower_confidence(event.confidence)
        event.tags = sorted(set(event.tags + ["correlated_time"]))
        event.detection_names = sorted(
            set(event.detection_names + ["state_time_correlated"])
        )
        event.ttp_flags = sorted(set(event.ttp_flags + ["state_time_correlated"]))
        event.related_event_ids = sorted({e.event_id for e in correlated if e.event_id})
        event.extra["correlation"] = {
            "method": "bodyfile_or_audit_path_match",
            "matched_paths": sorted(candidates),
            "source_event_count": len(correlated),
            "source_timestamp_type": best.timestamp_type,
        }
    return events


def _candidate_paths(event: TimelineEvent) -> set[str]:
    paths = {_norm(event.file_path), _norm(event.source_path)}
    if event.source_path and not event.source_path.startswith("/"):
        paths.add(_norm("/" + event.source_path))
    if event.file_path and not event.file_path.startswith("/"):
        paths.add(_norm("/" + event.file_path))
    return {p for p in paths if p}


def _norm(path: str | None) -> str:
    if not path:
        return ""
    value = path.strip()
    if value.startswith("./"):
        value = value[1:]
    if (
        value.startswith("root/")
        or value.startswith("etc/")
        or value.startswith("home/")
        or value.startswith("var/")
    ):
        value = "/" + value
    return value.replace("//", "/")


def _best_timestamp(events: list[TimelineEvent]) -> TimelineEvent | None:
    priority = {"mtime": 0, "ctime": 1, "birthtime": 2, "log_time": 3, "atime": 4}
    timestamped = [event for event in events if event.timestamp]
    if not timestamped:
        return None
    return sorted(
        timestamped, key=lambda e: (priority.get(e.timestamp_type, 99), e.timestamp)
    )[0]


def _lower_confidence(confidence: str) -> str:
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "medium"
    return confidence
