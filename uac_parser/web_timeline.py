from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from uac_parser.analyst_audit import append_annotation_audit
from uac_parser.enrich.attack_phases import (
    attack_phases,
    classify_attack_phases,
    order_attack_phases,
)
from uac_parser.output.writers import CSV_FIELDS

CSV_EXPORT_FIELDS = [
    *CSV_FIELDS,
    "summary_selection",
    "analyst_disposition",
    "analyst_tags",
    "analyst_note",
    "analyst_updated_at",
]

_ANNOTATIONS_LOCK = threading.Lock()
_EMPTY_ANNOTATIONS = {
    "schema_version": "1.1",
    "updated_at": "",
    "annotations": {},
}


class ResponseTextWriter:
    """Encode csv.writer text onto an HTTP response byte stream."""

    def __init__(self, target: Any) -> None:
        self.target = target

    def write(self, value: str) -> int:
        encoded = value.encode("utf-8")
        self.target.write(encoded)
        return len(value)


def timeline_file(output_dir: Path, scope: str) -> tuple[Path, str]:
    requested = "full" if scope == "full" else "mini"
    candidates = (
        [("case_timeline_mini.jsonl", "mini"), ("case_timeline_full.jsonl", "full")]
        if requested == "mini"
        else [("case_timeline_full.jsonl", "full")]
    )
    candidates += (
        [("timeline_mini.jsonl", "mini"), ("timeline_full.jsonl", "full")]
        if requested == "mini"
        else [("timeline_full.jsonl", "full")]
    )
    for name, actual_scope in candidates:
        path = output_dir / name
        if path.exists():
            return path, actual_scope
    raise FileNotFoundError("Timeline output is unavailable for this job.")


def timeline_page(
    output_dir: Path,
    job_id: str,
    query: dict[str, list[str]],
) -> dict[str, Any]:
    scope = query_value(query, "scope", "mini")
    path, actual_scope = timeline_file(output_dir, scope)
    search = query_value(query, "q", "").strip().lower()[:200]
    severity = query_value(query, "severity", "").strip().lower()
    source_type = query_value(query, "source_type", "").strip()
    attack_phase = query_value(query, "attack_phase", "").strip().lower()
    summary_filter = query_value(query, "summary", "").strip().lower()
    offset = max(0, query_int(query, "offset", 0))
    limit = min(200, max(20, query_int(query, "limit", 80)))
    annotations = load_annotations(output_dir).get("annotations", {})
    items: list[dict[str, Any]] = []
    total = 0
    severity_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    phase_counts: dict[str, int] = {}
    selected_count = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            backfill_event_attack_phases(event)
            event_severity = str(event.get("severity") or "informational")
            event_source = str(event.get("source_type") or "unknown")
            severity_counts[event_severity] = severity_counts.get(event_severity, 0) + 1
            source_counts[event_source] = source_counts.get(event_source, 0) + 1
            for phase in event.get("attack_phases") or []:
                phase_counts[str(phase)] = phase_counts.get(str(phase), 0) + 1
            event_id = str(event.get("event_id") or "")
            annotation = annotations.get(event_id, {})
            if not isinstance(annotation, dict):
                annotation = {}
            if annotation.get("include_in_summary") is True:
                selected_count += 1
            if not event_matches(
                event, search, severity, source_type, attack_phase
            ) or not summary_filter_matches(annotation, summary_filter):
                continue
            if total >= offset and len(items) < limit:
                event["analyst_annotation"] = annotation
                items.append(event)
            total += 1
    return {
        "job_id": job_id,
        "scope": actual_scope,
        "offset": offset,
        "limit": limit,
        "total": total,
        "has_more": offset + len(items) < total,
        "items": items,
        "facets": {
            "severity": dict(sorted(severity_counts.items())),
            "source_type": dict(sorted(source_counts.items())),
            "attack_phase": {
                phase.key: phase_counts.get(phase.key, 0)
                for phase in attack_phases()
                if phase_counts.get(phase.key, 0)
            },
            "summary": {
                "selected": selected_count,
                "unselected": max(0, sum(severity_counts.values()) - selected_count),
            },
        },
    }


def save_annotation(output_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    event_id = str(payload.get("event_id") or "").strip()
    if not re.fullmatch(r"evt_[A-Za-z0-9]+|evt-[A-Za-z0-9_.-]+", event_id):
        raise ValueError("A valid timeline event ID is required.")
    if not event_exists(output_dir, event_id):
        raise ValueError("The referenced event does not exist in this job timeline.")
    raw_tags = payload.get("tags") or []
    if not isinstance(raw_tags, list):
        raise ValueError("Annotation tags must be a list.")
    tags = []
    for value in raw_tags[:10]:
        tag = re.sub(r"\s+", "_", str(value).strip().lower())[:40]
        tag = re.sub(r"[^a-z0-9_.-]", "", tag)
        if tag and tag not in tags:
            tags.append(tag)
    note = str(payload.get("note") or "").strip()[:2000]
    include_in_summary = payload.get("include_in_summary", False)
    if not isinstance(include_in_summary, bool):
        raise ValueError("Summary selection must be true or false.")
    disposition = str(payload.get("disposition") or "unreviewed").strip().lower()
    allowed_dispositions = {
        "unreviewed",
        "suspicious",
        "malicious",
        "benign",
        "needs_context",
    }
    if disposition not in allowed_dispositions:
        raise ValueError("Unsupported analyst disposition.")

    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    with _ANNOTATIONS_LOCK:
        document = load_annotations(output_dir)
        annotations = document.setdefault("annotations", {})
        before = dict(annotations.get(event_id) or {})
        if tags or note or disposition != "unreviewed" or include_in_summary:
            annotations[event_id] = {
                "tags": tags,
                "note": note,
                "disposition": disposition,
                "include_in_summary": include_in_summary,
                "updated_at": now,
            }
        else:
            annotations.pop(event_id, None)
        document["updated_at"] = now
        document["schema_version"] = "1.1"
        after = dict(annotations.get(event_id) or {})
        target = output_dir / "analyst_annotations.json"
        previous_document = (
            load_annotations(output_dir)
            if target.exists()
            else {**_EMPTY_ANNOTATIONS, "annotations": {}}
        )
        write_annotations(target, document)
        try:
            append_annotation_audit(
                output_dir / "analyst_audit.jsonl",
                event_id=event_id,
                before=before,
                after=after,
            )
        except ValueError:
            write_annotations(target, previous_document)
            raise
        except OSError as exc:
            write_annotations(target, previous_document)
            raise ValueError("Unable to commit the analyst audit record.") from exc
    return {
        "event_id": event_id,
        "annotation": annotations.get(event_id, {}),
        "saved": True,
    }


def write_annotations(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)


def load_annotations(output_dir: Path) -> dict[str, Any]:
    path = output_dir / "analyst_annotations.json"
    if not path.exists():
        return {**_EMPTY_ANNOTATIONS, "annotations": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {**_EMPTY_ANNOTATIONS, "annotations": {}}
    if not isinstance(data, dict) or not isinstance(data.get("annotations"), dict):
        return {**_EMPTY_ANNOTATIONS, "annotations": {}}
    return data


def event_exists(output_dir: Path, event_id: str) -> bool:
    path, _ = timeline_file(output_dir, "full")
    needle = f'"event_id": "{event_id}"'
    with path.open(encoding="utf-8", errors="replace") as handle:
        return any(needle in line for line in handle)


def iter_review_rows(
    path: Path,
    annotations: dict[str, Any],
    *,
    search: str = "",
    severity: str = "",
    source_type: str = "",
    attack_phase: str = "",
    summary_filter: str = "",
) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            backfill_event_attack_phases(event)
            annotation = annotations.get(str(event.get("event_id") or ""), {})
            if not isinstance(annotation, dict):
                annotation = {}
            if not event_matches(
                event, search, severity, source_type, attack_phase
            ) or not summary_filter_matches(annotation, summary_filter):
                continue
            yield review_csv_row(event, annotation)


def review_csv_row(event: dict[str, Any], annotation: dict[str, Any]) -> dict[str, Any]:
    row = dict(event)
    for field in (
        "attack_phases",
        "attack_phase_candidates",
        "mitre",
        "mitre_candidates",
        "detection_names",
        "ttp_flags",
        "tags",
        "related_event_ids",
    ):
        value = row.get(field)
        if isinstance(value, list):
            row[field] = ",".join(str(item) for item in value)
    if isinstance(row.get("extra"), dict):
        row["extra"] = json.dumps(row["extra"], ensure_ascii=False, sort_keys=True)
    annotation_tags = annotation.get("tags") or []
    row.update(
        {
            "summary_selection": (
                "Summary" if annotation.get("include_in_summary") is True else ""
            ),
            "analyst_disposition": annotation.get("disposition", "unreviewed"),
            "analyst_tags": ",".join(str(tag) for tag in annotation_tags),
            "analyst_note": annotation.get("note", ""),
            "analyst_updated_at": annotation.get("updated_at", ""),
        }
    )
    return {field: row.get(field) for field in CSV_EXPORT_FIELDS}


def event_matches(
    event: dict[str, Any],
    search: str,
    severity: str,
    source_type: str,
    attack_phase: str = "",
) -> bool:
    event_severity = str(event.get("severity") or "informational")
    event_source = str(event.get("source_type") or "unknown")
    if severity and event_severity.lower() != severity:
        return False
    if source_type and event_source != source_type:
        return False
    if attack_phase and attack_phase not in (event.get("attack_phases") or []):
        return False
    return not search or search in searchable_event_text(event)


def summary_filter_matches(annotation: dict[str, Any], value: str) -> bool:
    selected = annotation.get("include_in_summary") is True
    if value == "selected":
        return selected
    if value == "unselected":
        return not selected
    return True


def backfill_event_attack_phases(event: dict[str, Any]) -> None:
    confirmed = event.get("attack_phases")
    candidates = event.get("attack_phase_candidates")
    if not isinstance(confirmed, list):
        confirmed = []
    if not isinstance(candidates, list):
        candidates = []
    mitre = event.get("mitre")
    mitre_candidates = event.get("mitre_candidates")
    if (
        not confirmed
        and not candidates
        and (isinstance(mitre, list) or isinstance(mitre_candidates, list))
    ):
        confirmed, candidates = classify_attack_phases(
            [str(value) for value in mitre] if isinstance(mitre, list) else [],
            (
                [str(value) for value in mitre_candidates]
                if isinstance(mitre_candidates, list)
                else []
            ),
            evidence_role=str(event.get("evidence_role") or "behavior"),
            signals=[
                str(event.get("event_category") or ""),
                str(event.get("event_action") or ""),
                *[str(value) for value in event.get("tags") or []],
                *[str(value) for value in event.get("detection_names") or []],
                *[str(value) for value in event.get("ttp_flags") or []],
            ],
        )
    confirmed_set = set(confirmed)
    event["attack_phases"] = order_attack_phases(list(confirmed_set))
    event["attack_phase_candidates"] = order_attack_phases(
        [phase for phase in candidates if phase not in confirmed_set]
    )


def searchable_event_text(event: dict[str, Any]) -> str:
    fields = [
        "timestamp",
        "host",
        "collection_host",
        "collection_name",
        "source_path",
        "source_type",
        "event_category",
        "event_action",
        "user",
        "src_ip",
        "dst_ip",
        "process",
        "command",
        "file_path",
        "summary",
        "raw",
        "severity",
        "attack_phases",
        "attack_phase_candidates",
        "tags",
        "mitre",
        "detection_names",
    ]
    return " ".join(str(event.get(field) or "").lower() for field in fields)


def query_value(query: dict[str, list[str]], key: str, default: str) -> str:
    values = query.get(key)
    return values[0] if values else default


def query_int(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(query_value(query, key, str(default)))
    except ValueError:
        return default
