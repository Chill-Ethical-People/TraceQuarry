from __future__ import annotations

import json
import mimetypes
import tarfile
import unicodedata
import zipfile
from collections.abc import Iterable
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from uac_parser import __version__
from uac_parser.enrich.attack_phases import attack_phases
from uac_parser.loaders.uac_layout import EvidenceFile
from uac_parser.output.permissions import secure_file
from uac_parser.timeline.engine import assign_event_ids
from uac_parser.timeline.event import TimelineEvent

BUNDLE_SCHEMA = "caseweave.tracequarry-import-bundle"
BUNDLE_VERSION = "1.0.0"
INVENTORY_VERSION = "1.0.0"
CASEWEAVE_BUNDLE_NAME = "caseweave_import_bundle.zip"
INCIDENT_TYPE_BY_PROFILE = {
    "credential_compromise": "credential_compromise",
    "ransomware_extortion": "ransomware",
}


def write_caseweave_bundle(
    output_dir: Path,
    *,
    collection_id: str,
    collection_name: str,
    collection_host: str,
    collection_fingerprint: str,
    acquisition_time: str,
    input_record: dict[str, Any],
    custody_reference: str,
    evidence_inventory: list[EvidenceFile],
    events: list[TimelineEvent],
    findings: list[dict[str, Any]],
    case_reference: str,
    suggested_name: str,
    incident_type: str = "",
) -> dict[str, Any]:
    """Write a CaseWeave v1 producer bundle without claiming analyst decisions."""
    created_at = _utc_now()
    export_input_record, source_package_path = _export_input_record(
        output_dir,
        input_record,
        evidence_inventory,
    )
    provisional_members = _evidence_members(
        "inventory",
        evidence_inventory,
        export_input_record,
    )[1]
    inventory_fingerprint = _inventory_fingerprint(provisional_members)
    custody_reference = custody_reference.strip()
    if not custody_reference:
        raise ValueError("CaseWeave custody reference must not be empty.")
    export_collection_id = f"tqcol_{custody_reference}"
    member_by_path, members = _evidence_members(
        export_collection_id,
        evidence_inventory,
        export_input_record,
    )
    synthetic_host = collection_host in {"", collection_id, collection_name}
    export_collection_host = "" if synthetic_host else collection_host
    canonical_events, old_to_new = _canonical_events(
        events,
        export_collection_id,
        source_fallback_host=collection_host if synthetic_host else "",
    )
    event_records: list[dict[str, Any]] = []
    exported_events: list[TimelineEvent] = []
    omissions: list[dict[str, Any]] = []
    for original, event in zip(events, canonical_events, strict=True):
        record = _event_record(event, member_by_path)
        reason = _event_omission_reason(record)
        if reason:
            omissions.append(
                _omission_record(
                    record_type="normalized_event",
                    producer_record_id=event.event_id,
                    collection_id=export_collection_id,
                    source_path=original.source_path,
                    parser=original.parser,
                    reason=reason,
                )
            )
            continue
        event_records.append(record)
        exported_events.append(event)
    event_by_id = {event.event_id: event for event in exported_events if event.event_id}
    timeline_records = []
    for event in exported_events:
        if not _is_timeline_candidate(event):
            continue
        candidate = _timeline_candidate(event, member_by_path)
        if candidate is None:
            omissions.append(
                _omission_record(
                    record_type="timeline_candidate",
                    producer_record_id=event.event_id,
                    collection_id=export_collection_id,
                    source_path=event.source_path,
                    parser=event.parser,
                    reason="source_reference_unresolved",
                )
            )
            continue
        timeline_records.append(candidate)
    timeline_id_by_event = {
        str(item["source_event_ids"][0]): str(item["candidate_id"])
        for item in timeline_records
    }
    finding_records = []
    for finding in findings:
        candidate = _finding_candidate(
            finding,
            export_collection_id,
            event_by_id,
            timeline_id_by_event,
            old_to_new,
        )
        if candidate is None:
            omissions.append(
                _omission_record(
                    record_type="finding_candidate",
                    producer_record_id=_finding_source_id(finding, old_to_new),
                    collection_id=export_collection_id,
                    source_path="",
                    parser="tracequarry.findings",
                    reason="no_exported_supporting_event",
                )
            )
            continue
        finding_records.append(candidate)

    datasets_content = {
        "events.jsonl": _jsonl_bytes(event_records),
        "timeline-candidates.jsonl": _jsonl_bytes(timeline_records),
        "finding-candidates.jsonl": _jsonl_bytes(finding_records),
        "omissions.jsonl": _jsonl_bytes(omissions),
    }
    datasets = {
        "events": _dataset_ref(
            "events.jsonl",
            "tracequarry.normalized-event",
            "1.2",
            datasets_content["events.jsonl"],
            len(event_records),
        ),
        "timeline_candidates": _dataset_ref(
            "timeline-candidates.jsonl",
            "caseweave.timeline-candidate",
            BUNDLE_VERSION,
            datasets_content["timeline-candidates.jsonl"],
            len(timeline_records),
        ),
        "finding_candidates": _dataset_ref(
            "finding-candidates.jsonl",
            "caseweave.finding-candidate",
            BUNDLE_VERSION,
            datasets_content["finding-candidates.jsonl"],
            len(finding_records),
        ),
    }
    omissions_dataset = _dataset_ref(
        "omissions.jsonl",
        "caseweave.producer-omission",
        BUNDLE_VERSION,
        datasets_content["omissions.jsonl"],
        len(omissions),
    )
    source_package = _source_package(export_input_record, collection_fingerprint)
    package_id = f"urn:tracequarry:package:{source_package['sha256']}"
    bundle_basis = "\0".join(
        [
            case_reference,
            export_collection_id,
            inventory_fingerprint,
            str(source_package["sha256"]),
            *(str(item["sha256"]) for item in datasets.values()),
            str(omissions_dataset["sha256"]),
        ]
    )
    bundle_id = f"urn:tracequarry:bundle:{sha256(bundle_basis.encode()).hexdigest()}"
    case: dict[str, Any] = {
        "requested_action": "create_if_missing",
        "case_reference": case_reference,
        "suggested_name": suggested_name,
        "lifecycle_hint": "open",
    }
    mapped_incident_type = INCIDENT_TYPE_BY_PROFILE.get(incident_type)
    if mapped_incident_type:
        case["incident_type"] = mapped_incident_type
    manifest = {
        "schema_name": BUNDLE_SCHEMA,
        "schema_version": BUNDLE_VERSION,
        "bundle_id": bundle_id,
        "created_at_utc": created_at,
        "producer": {
            "producer_id": "tracequarry",
            "producer_version": __version__,
        },
        "case": case,
        "collection": {
            "collection_id": export_collection_id,
            "collection_name": collection_name,
            "host": (
                {"hostname": export_collection_host} if export_collection_host else {}
            ),
            "acquired_from_utc": acquisition_time or None,
            "acquired_to_utc": acquisition_time or None,
            "acquisition_time_confidence": "high" if acquisition_time else "unknown",
            "acquisition_time_source": (
                "filename" if acquisition_time else "unavailable"
            ),
        },
        "package": {
            "package_id": package_id,
            "inventory_schema_version": INVENTORY_VERSION,
            "inventory_fingerprint": inventory_fingerprint,
            "source_package": source_package,
            "members": members,
        },
        "datasets": datasets,
        "counts": {
            "evidence_members": len(members),
            "events": len(event_records),
            "timeline_candidates": len(timeline_records),
            "finding_candidates": len(finding_records),
        },
        "extensions": {
            "tracequarry_collection_fingerprint": collection_fingerprint,
            "tracequarry_workspace_collection_id": collection_id,
            "tracequarry_investigation_profile": incident_type or None,
            "analyst_decisions_included": False,
            "omission_count": len(omissions),
            "omissions_dataset": omissions_dataset,
            "source_package_exclusions": list(
                input_record.get("archive_exclusions") or []
            ),
        },
    }
    manifest_bytes = _json_bytes(manifest)
    target = output_dir / CASEWEAVE_BUNDLE_NAME
    with zipfile.ZipFile(
        target,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as archive:
        archive.writestr("manifest.json", manifest_bytes)
        for name, content in datasets_content.items():
            archive.writestr(name, content)
    secure_file(target)
    result = {
        "schema_version": BUNDLE_VERSION,
        "bundle_id": bundle_id,
        "collection_id": export_collection_id,
        "case_reference": case_reference,
        "inventory_fingerprint": inventory_fingerprint,
        "events": len(event_records),
        "timeline_candidates": len(timeline_records),
        "finding_candidates": len(finding_records),
        "omissions": len(omissions),
        "path": target.name,
        "size": target.stat().st_size,
        "sha256": _file_sha256(target),
    }
    if source_package_path:
        result["source_package_path"] = source_package_path
    return result


def default_case_reference(case_name: str, collection_id: str) -> str:
    normalized = "-".join(case_name.upper().split())
    normalized = "".join(
        character for character in normalized if character.isalnum() or character == "-"
    ).strip("-")
    stem = normalized[:32] or "TRACEQUARRY"
    digest = sha256(f"{case_name}\0{collection_id}".encode()).hexdigest()[:10]
    return f"TQ-{stem}-{digest.upper()}"


def _evidence_members(
    collection_id: str,
    evidence_inventory: list[EvidenceFile],
    input_record: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    members = []
    by_path = {}
    source_package = _source_package(input_record, "")
    for evidence in sorted(evidence_inventory, key=lambda item: item.relative):
        relative = _normalized_relative_path(evidence.relative)
        member_id = (
            "member_" + sha256(f"{collection_id}\0{relative}".encode()).hexdigest()[:24]
        )
        status = evidence.coverage_status
        if status not in {
            "parsed",
            "partially_parsed",
            "unsupported",
            "unmatched",
            "error",
        }:
            status = "unmatched"
        member_path = _external_member_path(relative, input_record)
        member = {
            "member_id": member_id,
            "relative_path": relative,
            "byte_size": evidence.size,
            "sha256": evidence.sha256,
            "role": "original",
            "availability": "external",
            "parsing_status": status,
            "external_ref": {
                "schema_name": "caseweave.external-evidence-ref",
                "schema_version": BUNDLE_VERSION,
                "source_package_id": source_package["source_package_id"],
                "source_package_sha256": source_package["sha256"],
                "member_path": member_path,
            },
        }
        media_type = mimetypes.guess_type(relative)[0]
        if media_type:
            member["media_type"] = media_type
        members.append(member)
        by_path[relative] = member
    for excluded in input_record.get("archive_exclusions") or []:
        source_path = _normalized_relative_path(str(excluded["relative"]))
        relative = _logical_member_path(source_path, input_record)
        member_id = (
            "member_" + sha256(f"{collection_id}\0{relative}".encode()).hexdigest()[:24]
        )
        member = {
            "member_id": member_id,
            "relative_path": relative,
            "byte_size": int(excluded.get("byte_size") or 0),
            "sha256": str(excluded.get("sha256") or ""),
            "role": "original",
            "availability": "external",
            "parsing_status": "unsupported",
            "member_type": str(excluded.get("member_type") or "special"),
            "coverage_reason": str(excluded.get("reason") or "not_materialized"),
            "external_ref": {
                "schema_name": "caseweave.external-evidence-ref",
                "schema_version": BUNDLE_VERSION,
                "source_package_id": source_package["source_package_id"],
                "source_package_sha256": source_package["sha256"],
                "member_path": source_path,
            },
        }
        members.append(member)
    return by_path, members


def _external_member_path(relative: str, input_record: dict[str, Any]) -> str:
    prefix = str(input_record.get("member_prefix") or "").strip("/")
    return _normalized_relative_path(f"{prefix}/{relative}" if prefix else relative)


def _logical_member_path(source_path: str, input_record: dict[str, Any]) -> str:
    prefix = str(input_record.get("member_prefix") or "").strip("/")
    if prefix and source_path.startswith(f"{prefix}/"):
        return _normalized_relative_path(source_path[len(prefix) + 1 :])
    return source_path


def _source_package(
    input_record: dict[str, Any], collection_fingerprint: str
) -> dict[str, Any]:
    digest = str(input_record.get("sha256") or collection_fingerprint)
    kind = str(input_record.get("source_kind") or input_record.get("kind") or "unknown")
    payload: dict[str, Any] = {
        "schema_name": "caseweave.source-package",
        "schema_version": BUNDLE_VERSION,
        "source_package_id": f"source_{digest[:24]}",
        "sha256": digest,
        "byte_size": int(input_record.get("size") or 0),
        "tracequarry_input_kind": kind,
    }
    source_path = str(input_record.get("path") or "")
    if source_path:
        payload["file_name"] = Path(source_path).name
    return payload


def _export_input_record(
    output_dir: Path,
    input_record: dict[str, Any],
    evidence_inventory: list[EvidenceFile],
) -> tuple[dict[str, Any], str]:
    if input_record.get("kind") != "directory":
        return input_record, ""
    target = output_dir / "caseweave_source_package.tar"
    _write_deterministic_tar(
        target,
        evidence_inventory,
        list(input_record.get("archive_exclusions") or []),
    )
    return (
        {
            **input_record,
            "kind": "archive",
            "source_kind": "directory_snapshot",
            "path": str(target),
            "size": target.stat().st_size,
            "sha256": _file_sha256(target),
            "member_prefix": "",
        },
        target.name,
    )


def _write_deterministic_tar(
    target: Path,
    evidence_inventory: list[EvidenceFile],
    exclusions: list[dict[str, Any]],
) -> None:
    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
        for evidence in sorted(evidence_inventory, key=lambda item: item.relative):
            if evidence.path.is_symlink():
                raise ValueError(
                    f"Refusing to package symlinked evidence: {evidence.relative}"
                )
            relative = _normalized_relative_path(evidence.relative)
            info = tarfile.TarInfo(relative)
            info.size = evidence.size
            info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with evidence.path.open("rb") as source:
                archive.addfile(info, source)
        for excluded in sorted(exclusions, key=lambda item: str(item["relative"])):
            member_type = str(excluded.get("member_type") or "")
            if member_type not in {"symlink", "hardlink", "special"}:
                continue
            info = tarfile.TarInfo(_normalized_relative_path(str(excluded["relative"])))
            if member_type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = str(excluded.get("link_target") or "")
                info.mode = 0o777
            elif member_type == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = str(excluded.get("link_target") or "")
                info.mode = 0o600
            else:
                type_flag = str(excluded.get("type_flag") or "")
                if len(type_flag.encode("ascii", "strict")) != 1:
                    raise ValueError(
                        "Special evidence member has an invalid type flag."
                    )
                info.type = type_flag.encode("ascii")
                info.devmajor = int(excluded.get("device_major") or 0)
                info.devminor = int(excluded.get("device_minor") or 0)
                info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info)
    secure_file(target)


def _inventory_fingerprint(members: list[dict[str, Any]]) -> str:
    lines = ["caseweave-inventory-v1"]
    for member in sorted(
        members,
        key=lambda item: (
            str(item["relative_path"]),
            str(item.get("member_type") or ""),
        ),
    ):
        fields = [
            str(member["relative_path"]),
            str(member["byte_size"]),
            str(member["sha256"]),
            str(member["role"]),
        ]
        member_type = str(member.get("member_type") or "")
        if member_type:
            fields.append(member_type)
        lines.append("\t".join(fields))
    return sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def _canonical_events(
    events: list[TimelineEvent],
    collection_id: str,
    *,
    source_fallback_host: str,
) -> tuple[list[TimelineEvent], dict[str, str]]:
    """Assign exchange IDs that do not depend on input path or case ordering."""
    prepared = []
    for event in events:
        extra = dict(event.extra)
        extra.pop("collection_event_id", None)
        prepared.append(
            replace(
                event,
                event_id="",
                collection_id=collection_id,
                collection_input="",
                collection_host=(
                    ""
                    if event.collection_host == source_fallback_host
                    else event.collection_host
                ),
                host="" if event.host == source_fallback_host else event.host,
                related_event_ids=[],
                extra=extra,
            )
        )
    assigned = assign_event_ids(prepared)
    old_to_new = {
        original.event_id: canonical.event_id
        for original, canonical in zip(events, assigned, strict=True)
        if original.event_id
    }
    canonical_events = [
        replace(
            canonical,
            related_event_ids=sorted(
                {
                    old_to_new.get(event_id, event_id)
                    for event_id in original.related_event_ids
                }
            ),
        )
        for original, canonical in zip(events, assigned, strict=True)
    ]
    return canonical_events, old_to_new


def _event_omission_reason(record: dict[str, Any]) -> str:
    has_point = bool(record.get("timestamp"))
    has_interval = bool(record.get("time_start") and record.get("time_end"))
    if not has_point and not has_interval:
        return "missing_acquisition_interval"
    if not record.get("source_locator") and not str(record.get("raw") or ""):
        return "missing_exact_source"
    return ""


def _omission_record(
    *,
    record_type: str,
    producer_record_id: str,
    collection_id: str,
    source_path: str,
    parser: str,
    reason: str,
) -> dict[str, Any]:
    basis = "\0".join(
        [record_type, producer_record_id, collection_id, source_path, parser, reason]
    )
    return {
        "schema_name": "caseweave.producer-omission",
        "schema_version": BUNDLE_VERSION,
        "omission_id": "omission_" + sha256(basis.encode()).hexdigest()[:24],
        "record_type": record_type,
        "producer_record_id": producer_record_id,
        "collection_id": collection_id,
        "source_path": source_path,
        "parser": parser,
        "reason": reason,
    }


def _finding_source_id(finding: dict[str, Any], old_to_new: dict[str, str]) -> str:
    event_ids = finding.get("event_ids", finding.get("related_event_ids", []))
    basis = json.dumps(
        {
            "title": finding.get("title"),
            "summary": finding.get("summary"),
            "event_ids": sorted(
                old_to_new.get(str(event_id), str(event_id)) for event_id in event_ids
            ),
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return "tracequarry_finding_" + sha256(basis.encode()).hexdigest()[:24]


def _event_record(
    event: TimelineEvent,
    member_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    record = event.to_dict()
    locator = _source_locator(event, member_by_path)
    if locator:
        record["source_locator"] = locator
    score = _confidence_score(event.confidence)
    record["confidence_score"] = score
    record["confidence_reasons"] = [
        f"TraceQuarry parser confidence: {event.confidence}.",
        "Producer enrichment requires responder validation in CaseWeave.",
    ]
    record["assessment"] = _producer_assessment(event.severity)
    return record


def _timeline_candidate(
    event: TimelineEvent,
    member_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    locator = _source_locator(event, member_by_path)
    member = _source_member(event, member_by_path)
    referenced_member = member or _first_source_member(event, member_by_path)
    if not referenced_member:
        return None
    source_ref: dict[str, Any] = {
        "source_event_id": event.event_id,
        "member_id": str(referenced_member["member_id"]),
    }
    if locator:
        source_ref["locator"] = locator
    phase_ids = {phase.key: phase.tactic_id for phase in attack_phases()}
    payload: dict[str, Any] = {
        "schema_name": "caseweave.timeline-candidate",
        "schema_version": BUNDLE_VERSION,
        "candidate_id": f"timeline_{event.event_id}",
        "collection_id": event.collection_id,
        "source_event_ids": [event.event_id],
        "timestamp_raw": event.timestamp_raw,
        "timestamp_precision": event.timestamp_precision,
        "timestamp_confidence": event.timestamp_confidence,
        "host": event.host,
        "summary": event.summary,
        "details": event.raw,
        "confirmed_technique_ids": list(event.mitre),
        "candidate_technique_ids": list(event.mitre_candidates),
        "confidence_score": _confidence_score(event.confidence),
        "confidence_reasons": [
            "Selected by TraceQuarry as a high-signal forensic event.",
            "Responder promotion is required before it becomes a CaseWeave timeline entry.",
        ],
        "producer_assessment": _producer_assessment(event.severity),
        "source_refs": [source_ref],
    }
    if event.timestamp:
        payload["occurred_at_utc"] = event.timestamp
    elif event.time_start and event.time_end:
        payload["interval_start_utc"] = event.time_start
        payload["interval_end_utc"] = event.time_end
    if event.user:
        payload["user"] = event.user
    if event.attack_phases:
        payload["attack_phase"] = phase_ids.get(
            event.attack_phases[0], event.attack_phases[0]
        )
    return payload


def _finding_candidate(
    finding: dict[str, Any],
    collection_id: str,
    event_by_id: dict[str, TimelineEvent],
    timeline_id_by_event: dict[str, str],
    old_to_new: dict[str, str],
) -> dict[str, Any] | None:
    event_ids = [
        old_to_new[str(value)]
        for value in finding.get("event_ids", finding.get("related_event_ids", []))
        if old_to_new.get(str(value)) in event_by_id
    ]
    if not event_ids:
        return None
    related_events = [event_by_id[event_id] for event_id in event_ids]
    confirmed = sorted({value for event in related_events for value in event.mitre})
    candidates = sorted(
        {value for event in related_events for value in event.mitre_candidates}
    )
    basis = json.dumps(
        {
            "collection_id": collection_id,
            "title": finding.get("title"),
            "summary": finding.get("summary"),
            "event_ids": sorted(event_ids),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    confidence = str(finding.get("confidence") or "medium")
    payload: dict[str, Any] = {
        "schema_name": "caseweave.finding-candidate",
        "schema_version": BUNDLE_VERSION,
        "candidate_id": "finding_" + sha256(basis.encode()).hexdigest()[:24],
        "collection_id": collection_id,
        "title": str(finding.get("title") or "TraceQuarry finding"),
        "summary": str(finding.get("summary") or ""),
        "producer_assessment": _producer_assessment(
            str(finding.get("severity") or "informational")
        ),
        "confidence_score": _confidence_score(confidence),
        "confidence_reasons": [
            f"TraceQuarry finding confidence: {confidence}.",
            "Imported as a producer candidate; analyst confirmation is not implied.",
        ],
        "severity": str(finding.get("severity") or "informational"),
        "severity_reasons": ["Severity assigned by TraceQuarry detection logic."],
        "related_event_ids": event_ids,
        "related_timeline_candidate_ids": [
            timeline_id_by_event[event_id]
            for event_id in event_ids
            if event_id in timeline_id_by_event
        ],
        "confirmed_technique_ids": confirmed,
        "candidate_technique_ids": candidates,
    }
    profile_id = str(finding.get("profile_id") or "")
    if profile_id:
        payload["attribution"] = {
            "kind": "profile_similarity",
            "profile": profile_id,
            "score": min(_confidence_score(confidence), 0.6),
            "reasons": [
                *[str(value) for value in finding.get("matched_strong_indicators", [])],
                *[
                    str(value)
                    for value in finding.get("matched_supporting_indicators", [])
                ],
            ],
            "limitations": [
                "Tradecraft overlap is not threat actor attribution.",
                "Independent intelligence and multi-source corroboration are required.",
            ],
        }
    return payload


def _source_member(
    event: TimelineEvent,
    member_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    source_path = event.source_path.split("#", 1)[0].lstrip("/")
    if " vs " in source_path:
        return None
    member = member_by_path.get(source_path)
    if not member or member.get("sha256") != event.source_sha256:
        return None
    return member


def _first_source_member(
    event: TimelineEvent,
    member_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    for value in event.source_path.split(" vs "):
        source_path = value.split("#", 1)[0].strip().lstrip("/")
        if source_path in member_by_path:
            return member_by_path[source_path]
    return None


def _source_locator(
    event: TimelineEvent,
    member_by_path: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    member = _source_member(event, member_by_path)
    if not member:
        return None
    line = event.extra.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        return {
            "kind": "line",
            "member_id": member["member_id"],
            "line_number": line,
        }
    record = event.extra.get("row_index")
    if isinstance(record, int) and not isinstance(record, bool) and record > 0:
        return {
            "kind": "record",
            "member_id": member["member_id"],
            "record_number": record,
        }
    return None


def _is_timeline_candidate(event: TimelineEvent) -> bool:
    return bool(
        event.severity in {"medium", "high", "critical"}
        or event.detection_names
        or event.ttp_flags
        or event.attack_phases
        or event.attack_phase_candidates
    )


def _confidence_score(value: str) -> float:
    return {
        "none": 0.1,
        "low": 0.35,
        "medium": 0.6,
        "high": 0.85,
    }.get(value.lower(), 0.5)


def _producer_assessment(severity: str) -> str:
    if severity.lower() in {"medium", "high", "critical"}:
        return "suspicious"
    return "informational"


def _dataset_ref(
    path: str,
    schema_name: str,
    schema_version: str,
    content: bytes,
    record_count: int,
) -> dict[str, Any]:
    return {
        "path": path,
        "media_type": "application/x-ndjson",
        "schema_name": schema_name,
        "schema_version": schema_version,
        "record_count": record_count,
        "byte_size": len(content),
        "sha256": sha256(content).hexdigest(),
    }


def _jsonl_bytes(records: Iterable[dict[str, Any]]) -> bytes:
    return b"".join(_json_line(record) for record in records)


def _json_line(record: dict[str, Any]) -> bytes:
    return (
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _json_bytes(record: dict[str, Any]) -> bytes:
    return (
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _normalized_relative_path(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value.replace("\\", "/")).strip("/")
    parts = normalized.split("/")
    if not normalized or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"Unsafe evidence inventory path: {value!r}")
    return normalized


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
