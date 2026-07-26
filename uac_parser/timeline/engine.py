from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import replace
from hashlib import sha256

from .event import TimelineEvent


def assign_event_ids(events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
    output: list[TimelineEvent] = []
    claimed_events: dict[str, TimelineEvent] = {}
    claimed_bases: dict[str, str] = {}

    def claimed_basis(event_id: str) -> str:
        basis = claimed_bases.get(event_id)
        if basis is None:
            basis = _event_identity_basis(claimed_events[event_id])
            claimed_bases[event_id] = basis
        return basis

    for event in events:
        if event.event_id:
            if event.event_id in claimed_events and claimed_basis(
                event.event_id
            ) != _event_identity_basis(event):
                raise ValueError(
                    f"Event ID collision for non-identical evidence: {event.event_id}"
                )
            claimed_events.setdefault(event.event_id, event)
            output.append(event)
            continue
        basis = _event_identity_basis(event)
        digest = sha256(basis.encode("utf-8", "replace")).hexdigest()
        length = 20
        event_id = "evt_" + digest[:length]
        while event_id in claimed_events and claimed_basis(event_id) != basis:
            length += 4
            if length > len(digest):
                raise ValueError("Unable to allocate a collision-free event ID")
            event_id = "evt_" + digest[:length]
        assigned = replace(event, event_id=event_id)
        claimed_events[event_id] = assigned
        claimed_bases[event_id] = basis
        output.append(assigned)
    return output


def _event_identity_basis(event: TimelineEvent) -> str:
    identity = {
        "collection_id": event.collection_id,
        "timestamp": event.timestamp,
        "timestamp_raw": event.timestamp_raw,
        "time_start": event.time_start,
        "time_end": event.time_end,
        "evidence_role": event.evidence_role,
        "source_path": event.source_path,
        "source_sha256": event.source_sha256,
        "source_type": event.source_type,
        "parser": event.parser,
        "event_action": event.event_action,
        "host": event.host,
        "user": event.user,
        "uid": event.uid,
        "gid": event.gid,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "port": event.port,
        "process": event.process,
        "pid": event.pid,
        "command": event.command,
        "file_path": event.file_path,
        "raw": event.raw,
        "extra": event.extra,
    }
    return json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )


def sort_events(events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
    return sorted(
        events,
        key=lambda e: (e.timestamp or "9999", e.source_path, e.event_action, e.raw),
    )


def dedupe_events(events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
    """Remove only exact normalized duplicates while preserving distinct evidence."""
    seen: set[tuple[object, ...]] = set()
    output: list[TimelineEvent] = []
    for event in events:
        key = (
            event.collection_id,
            event.timestamp,
            event.time_start,
            event.time_end,
            event.evidence_role,
            event.source_path,
            event.source_sha256,
            event.event_action,
            event.host,
            event.user,
            event.src_ip,
            event.dst_ip,
            event.command or "",
            event.file_path or "",
            event.raw,
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(event)
    return output


def filter_window(
    events: Iterable[TimelineEvent], start: str | None, end: str | None
) -> list[TimelineEvent]:
    output = []
    for event in events:
        if not event.timestamp:
            continue
        if start and event.timestamp < start:
            continue
        if end and event.timestamp > end:
            continue
        output.append(event)
    return output
