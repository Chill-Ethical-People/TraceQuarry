from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from uac_parser.enrich.attack_phases import (
    AttackPhase,
    attack_phase_metadata,
    attack_phases,
)
from uac_parser.web_timeline import (
    backfill_event_attack_phases,
    load_annotations,
    timeline_file,
)


def build_incident_briefing(
    output_dir: Path,
    job_id: str,
    case_name: str,
    requested_scope: str = "mini",
) -> dict[str, Any]:
    path, scope = timeline_file(output_dir, requested_scope)
    annotations = load_annotations(output_dir).get("annotations", {})
    if not isinstance(annotations, dict):
        annotations = {}
    findings = findings_for_output(output_dir)
    ioc_hits = ioc_hit_count(output_dir)
    definitions = attack_phases()
    scan = _scan_timeline(path, annotations, definitions)
    narrative = scan.narrative()
    metrics = {
        "timeline_events": scan.total,
        "timestamped_events": scan.timestamped,
        "selected_events": scan.selected_total,
        "hosts": len(scan.hosts),
        "phases_observed": sum(bool(count) for count in scan.confirmed_counts.values()),
        "timeline_start": scan.earliest,
        "timeline_end": scan.latest,
        "findings": len(findings),
        "high_severity_findings": sum(
            str(finding.get("severity") or "").lower() in {"high", "critical"}
            for finding in findings
        ),
        "ioc_hits": ioc_hits,
    }
    return {
        "schema_version": "1.0",
        "job_id": job_id,
        "case_name": case_name,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "scope": scope,
        "attack": attack_phase_metadata(),
        "metrics": metrics,
        "narrative": narrative,
        "executive": executive_briefing(scan.selected_events, metrics, narrative),
        "phase_breakdown": scan.phase_breakdown(),
        "selected_events": scan.selected_events,
        "selected_events_returned": len(scan.selected_events),
        "selected_events_truncated": scan.selected_total > len(scan.selected_events),
        "evidence_note": (
            "Summary promotion is stored separately from parser evidence and recorded in "
            "the append-only analyst audit. Machine phase tags do not establish intent, "
            "maliciousness, or actor attribution."
        ),
    }


class _BriefingAccumulator:
    def __init__(
        self,
        definitions: tuple[AttackPhase, ...],
        annotations: dict[str, Any],
    ) -> None:
        self.definitions = definitions
        self.annotations = annotations
        self.confirmed_counts = {phase.key: 0 for phase in definitions}
        self.candidate_counts = {phase.key: 0 for phase in definitions}
        self.selected_phase_counts = {phase.key: 0 for phase in definitions}
        self.phase_ranges: dict[str, list[str]] = {
            phase.key: [] for phase in definitions
        }
        self.hosts: set[str] = set()
        self.selected_events: list[dict[str, Any]] = []
        self.selected_total = 0
        self.total = 0
        self.timestamped = 0
        self.earliest = ""
        self.latest = ""

    def observe(self, event: dict[str, Any]) -> None:
        backfill_event_attack_phases(event)
        self.total += 1
        timestamp = str(event.get("timestamp") or "")
        self._observe_timestamp(timestamp)
        host = str(event.get("collection_host") or event.get("host") or "").strip()
        if host:
            self.hosts.add(host)
        event_phases = [str(value) for value in event["attack_phases"]]
        self._observe_phases(event_phases, event["attack_phase_candidates"], timestamp)

        annotation = self.annotations.get(str(event.get("event_id") or ""), {})
        if not isinstance(annotation, dict):
            annotation = {}
        if annotation.get("include_in_summary") is not True:
            return
        self.selected_total += 1
        for phase_key in event_phases:
            if phase_key in self.selected_phase_counts:
                self.selected_phase_counts[phase_key] += 1
        if len(self.selected_events) < 500:
            self.selected_events.append(briefing_event(event, annotation))

    def _observe_timestamp(self, timestamp: str) -> None:
        if not timestamp:
            return
        self.timestamped += 1
        self.earliest = (
            timestamp
            if not self.earliest or timestamp < self.earliest
            else self.earliest
        )
        self.latest = (
            timestamp if not self.latest or timestamp > self.latest else self.latest
        )

    def _observe_phases(
        self, event_phases: list[str], candidates: object, timestamp: str
    ) -> None:
        for phase_key in event_phases:
            if phase_key not in self.confirmed_counts:
                continue
            self.confirmed_counts[phase_key] += 1
            if timestamp:
                self.phase_ranges[phase_key].append(timestamp)
        if not isinstance(candidates, list):
            return
        for value in candidates:
            phase_key = str(value)
            if phase_key in self.candidate_counts:
                self.candidate_counts[phase_key] += 1

    def phase_breakdown(self) -> list[dict[str, Any]]:
        breakdown = []
        for phase in self.definitions:
            confirmed = self.confirmed_counts[phase.key]
            candidate = self.candidate_counts[phase.key]
            selected = self.selected_phase_counts[phase.key]
            if not confirmed and not candidate and not selected:
                continue
            timestamps = self.phase_ranges[phase.key]
            breakdown.append(
                {
                    "key": phase.key,
                    "tactic_id": phase.tactic_id,
                    "label": phase.label,
                    "confirmed_events": confirmed,
                    "candidate_events": candidate,
                    "selected_events": selected,
                    "first_observed": min(timestamps) if timestamps else "",
                    "last_observed": max(timestamps) if timestamps else "",
                }
            )
        return breakdown

    def narrative(self) -> str:
        if not self.selected_total:
            return (
                "No events have been promoted into the reconstructed timeline. Review the "
                "evidence timeline and mark pivotal, validated records as Include in summary."
            )
        selected_labels = [
            phase.label
            for phase in self.definitions
            if self.selected_phase_counts[phase.key]
        ]
        phase_text = (
            ", ".join(selected_labels) if selected_labels else "unphased evidence"
        )
        return (
            f"The reconstructed timeline contains {self.selected_total} analyst-selected "
            f"event(s) across {len(self.hosts)} host(s). Selected evidence spans {phase_text}. "
            "These entries are review decisions, not automated conclusions; validate each "
            "statement against its retained raw record and source provenance."
        )


def _scan_timeline(
    path: Path,
    annotations: dict[str, Any],
    definitions: tuple[AttackPhase, ...],
) -> _BriefingAccumulator:
    scan = _BriefingAccumulator(definitions, annotations)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                scan.observe(event)
    scan.selected_events.sort(
        key=lambda event: (not bool(event["timestamp"]), event["timestamp"])
    )
    return scan


def briefing_event(event: dict[str, Any], annotation: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": str(event.get("event_id") or ""),
        "timestamp": str(event.get("timestamp") or ""),
        "host": str(event.get("collection_host") or event.get("host") or ""),
        "attack_phases": list(event.get("attack_phases") or []),
        "severity": str(event.get("severity") or "informational"),
        "summary": str(event.get("summary") or event.get("event_action") or ""),
        "source_type": str(event.get("source_type") or ""),
        "source_path": str(event.get("source_path") or ""),
        "source_sha256": str(event.get("source_sha256") or ""),
        "user": str(event.get("user") or ""),
        "src_ip": str(event.get("src_ip") or ""),
        "dst_ip": str(event.get("dst_ip") or ""),
        "command": str(event.get("command") or ""),
        "file_path": str(event.get("file_path") or ""),
        "raw": str(event.get("raw") or event.get("command") or "")[:16000],
        "analyst_disposition": str(annotation.get("disposition") or "unreviewed"),
        "analyst_tags": list(annotation.get("tags") or []),
        "analyst_note": str(annotation.get("note") or ""),
        "analyst_updated_at": str(annotation.get("updated_at") or ""),
    }


def findings_for_output(output_dir: Path) -> list[dict[str, Any]]:
    for name in ("case_findings.json", "findings.json"):
        path = output_dir / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        values = payload.get("findings", []) if isinstance(payload, dict) else payload
        if isinstance(values, list):
            return [item for item in values if isinstance(item, dict)]
    return []


def ioc_hit_count(output_dir: Path) -> int:
    for name in ("case_ioc_hits.json", "ioc_hits.json"):
        path = output_dir / name
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            return len(payload)
        if isinstance(payload, dict) and isinstance(payload.get("hits"), list):
            return len(payload["hits"])
    return 0


def executive_briefing(
    selected_events: list[dict[str, Any]],
    metrics: dict[str, Any],
    narrative: str,
) -> dict[str, Any]:
    timed = [event for event in selected_events if event.get("timestamp")]
    start = str(timed[0].get("timestamp") or "") if timed else ""
    end = str(timed[-1].get("timestamp") or "") if timed else ""
    accounts = sorted(
        {
            str(event.get("user") or "").strip()
            for event in selected_events
            if str(event.get("user") or "").strip()
            and not str(event.get("user") or "").strip().isdigit()
        }
    )
    exfiltration = [
        str(event.get("summary") or "")
        for event in selected_events
        if "exfiltration" in (event.get("attack_phases") or [])
    ]
    impact = [
        str(event.get("summary") or "")
        for event in selected_events
        if "impact" in (event.get("attack_phases") or [])
    ]
    sequence = [str(event.get("summary") or "") for event in selected_events[:5]]
    if selected_events:
        range_text = (
            f" between {start} and {end}" if start and end else " in the reviewed scope"
        )
        summary = (
            f"TraceQuarry normalized {metrics.get('timeline_events', 0)} event(s) "
            f"across {metrics.get('hosts', 0)} host(s). Analysts promoted "
            f"{metrics.get('selected_events', 0)} pivotal record(s){range_text}. "
            f"The selected chronology includes: {'; '.join(sequence)}. "
            "This is a review reconstruction, not an automated attribution or proof that "
            "a transfer, command, or destructive action completed successfully."
        )
    else:
        summary = narrative
    return {
        "summary": summary,
        "incident_timeline": selected_events[:5],
        "key_metrics": [
            {"label": "Timeline events", "value": metrics.get("timeline_events", 0)},
            {
                "label": "Selected milestones",
                "value": metrics.get("selected_events", 0),
            },
            {"label": "Findings", "value": metrics.get("findings", 0)},
            {"label": "IoC hits", "value": metrics.get("ioc_hits", 0)},
            {"label": "Hosts in scope", "value": metrics.get("hosts", 0)},
        ],
        "threat_actions": [
            {
                "timestamp": event.get("timestamp", ""),
                "summary": event.get("summary", ""),
                "attack_phases": event.get("attack_phases", []),
            }
            for event in selected_events[:5]
        ],
        "data_exfiltration": exfiltration
        or ["No analyst-selected exfiltration milestone."],
        "impact": impact or ["No analyst-selected impact milestone."],
        "accounts": accounts or ["No account promoted in the selected chronology."],
        "legal_note": (
            "LEGAL CONSIDERATION: Data exposure, notification duties, and business impact "
            "require assessment by the incident owner and qualified legal counsel; they "
            "are not inferred by TraceQuarry."
        ),
    }
