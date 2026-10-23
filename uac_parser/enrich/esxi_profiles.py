"""Conservative, source-linked payload candidates and actor-neutral ESXi profiles."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from typing import Any

from uac_parser.enrich.rule_registry import load_registry
from uac_parser.parsers.esxi_activity import invoked_payload, shell_tokens
from uac_parser.timeline.event import TimelineEvent


def profile_assessment(
    events: list[TimelineEvent], findings: list[dict[str, Any]]
) -> dict[str, Any]:
    """Make absence of actor matches explicit rather than silently implying no threat."""
    registry = load_registry()
    actor_matches = [finding for finding in findings if finding.get("profile_id")]
    return {
        "assessment_scope": "Parsed events in the selected analysis window; not all raw evidence.",
        "attribution": "not_assessed",
        "actor_profiles_evaluated": len(registry["actor_similarity_profiles"]),
        "qualified_actor_similarities": actor_matches,
        "actor_assessment": "Similarity only; not attribution."
        if actor_matches
        else "No actor profile met its evidence thresholds. This is not evidence of absence of compromise. Generic ransomware behavior and publicly available tools are not actor identifiers.",
        "payload_candidates": [
            finding
            for finding in findings
            if "esxi_payload_candidate" in finding.get("tags", [])
        ],
        "actor_neutral_profiles": [
            finding
            for finding in findings
            if finding.get("profile_kind") == "actor_neutral_tradecraft"
        ],
        "esxi_events_in_scope": sum(event.parser == "esxi" for event in events),
        "active_esxi_payload_rules": [
            name
            for name, rule in registry["malware_payload_tags"].items()
            if rule.get("esxi_match")
        ],
        "source_references": {
            name: source
            for name, source in registry["source_references"].items()
            if any(name in finding.get("source_refs", []) for finding in findings)
        },
        "limitations": [
            "Payload candidates do not establish family identity, successful encryption, or actor identity.",
            "VMkatz invocation does not establish successful credential recovery.",
            "Renamed payloads, commands inside scripts and uncollected logs may not be detectable.",
        ],
    }


def apply_payload_candidates(
    event: TimelineEvent, rules: dict[str, dict[str, Any]]
) -> None:
    if event.parser != "esxi":
        return
    if event.extra.get("read_only_inspection") or event.extra.get(
        "literal_arguments_only"
    ):
        return
    payload, arguments, _ = invoked_payload(shell_tokens(event.command or ""))
    basename = PurePosixPath(payload).name.lower()
    # Inspection, transfers and arbitrary quoted text are not payload invocation.
    if basename in {
        "echo",
        "printf",
        "grep",
        "rg",
        "cat",
        "less",
        "head",
        "tail",
        "cp",
        "mv",
        "ls",
        "find",
        "scp",
        "sftp",
        "curl",
        "wget",
    }:
        payload, basename, arguments = "", "", []
    vmfs_target = any(t.startswith("/vmfs/volumes/") for t in arguments)
    artifact = PurePosixPath(event.file_path or "").name.lower()
    matches = []
    for rule_id, rule in rules.items():
        selector = rule.get("esxi_match")
        if not selector:
            continue
        executables = selector.get("executables", [])
        required_args = selector.get("required_arguments", [])
        invocation = bool(payload) and bool(executables or required_args)
        invocation = invocation and (not executables or basename in executables)
        invocation = invocation and all(arg in arguments for arg in required_args)
        invocation = invocation and (
            not selector.get("require_vmfs_target") or vmfs_target
        )
        observation = bool(artifact) and (
            artifact in selector.get("artifact_names", [])
            or any(
                artifact.endswith(suffix)
                for suffix in selector.get("artifact_suffixes", [])
            )
        )
        if not invocation and not observation:
            continue
        basis = "recorded_invocation" if invocation else "artifact_name_observed"
        matches.append(
            {
                "profile_id": rule_id,
                "basis": basis,
                "matched_value": payload if invocation else event.file_path,
                "confidence": "low",
                "source_refs": list(rule.get("source_refs", [])),
                "limitation": rule.get(
                    "analyst_note",
                    "Name/extension match only; verify payload and effects. No actor attribution.",
                ),
            }
        )
        event.tags = sorted(
            set(
                event.tags
                + [
                    f"payload_candidate.{rule_id}",
                    "requires_corroboration",
                    "not_attribution",
                ]
            )
        )
        event.mitre_candidates = sorted(set(event.mitre_candidates + ["T1486"]))
    if matches:
        event.extra["payload_candidates"] = matches
        event.detection_names = sorted(
            set(event.detection_names + ["esxi_payload_candidate"])
        )
        if event.severity in {"informational", "low"}:
            event.severity = "medium"


def _time(event: TimelineEvent) -> datetime | None:
    try:
        value = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        return value if value.tzinfo else None
    except (TypeError, ValueError, AttributeError):
        return None


def esxi_profile_findings(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    registry = load_registry()
    findings: list[dict[str, Any]] = []
    candidate_events: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        for candidate in event.extra.get("payload_candidates", []):
            candidate_events[candidate["profile_id"]].append(event)
    for rule_id, matches in sorted(candidate_events.items()):
        findings.append(
            {
                "title": "ESXi payload candidate: " + rule_id.replace("_", " "),
                "severity": "medium",
                "confidence": "low",
                "event_ids": [event.event_id for event in matches],
                "summary": f"{len(matches)} event(s) match an explicit filename, artifact or argument selector. Recover the payload and validate effects; this is not confirmed ransomware, family identity or actor attribution.",
                "tags": [
                    "esxi_payload_candidate",
                    f"payload_candidate.{rule_id}",
                    "not_attribution",
                ],
                "source_refs": list(
                    registry["malware_payload_tags"][rule_id].get("source_refs", [])
                ),
            }
        )

    for profile_id, profile in registry.get("esxi_behavior_profiles", {}).items():
        anchors = set(profile["anchor_detections"])
        stage_rules = {
            stage: set(names) for stage, names in profile["supporting_stages"].items()
        }
        relevant = anchors.union(*stage_rules.values())
        scopes: dict[tuple[str, str], list[tuple[datetime, TimelineEvent]]] = (
            defaultdict(list)
        )
        for event in events:
            if event.parser != "esxi" or event.evidence_role != "behavior":
                continue
            if not relevant.intersection(event.detection_names):
                continue
            timestamp = _time(event)
            if timestamp and (event.collection_id or event.host):
                scopes[(event.collection_id, event.host)].append((timestamp, event))
        for scope, records in sorted(scopes.items()):
            records.sort(key=lambda record: record[0])
            consumed: set[str] = set()
            for anchor_time, anchor in reversed(records):
                if (
                    not anchors.intersection(anchor.detection_names)
                    or anchor.event_id in consumed
                ):
                    continue
                window = timedelta(hours=profile["window_hours"])
                # A trailing window anchors the preparation to a later payload observation.
                nearby = [
                    event
                    for timestamp, event in records
                    if timedelta(0) <= anchor_time - timestamp <= window
                ]
                # Copies of the same raw record in rotated logs are not independent evidence.
                unique = {(event.timestamp, event.raw): event for event in nearby}
                nearby = list(unique.values())
                stages = {
                    stage
                    for event in nearby
                    if event is not anchor
                    for stage, names in stage_rules.items()
                    if names.intersection(event.detection_names)
                }
                if (
                    len(nearby) < profile["minimum_event_count"]
                    or len(stages) < profile["minimum_supporting_stages"]
                ):
                    continue
                tag = f"profile_similarity.{profile_id}"
                for event in nearby:
                    event.tags = sorted(set(event.tags + [tag, "not_attribution"]))
                ids = [event.event_id for event in nearby]
                consumed.update(ids)
                findings.append(
                    {
                        "title": profile["display_name"],
                        "severity": "high",
                        "confidence": "medium",
                        "event_ids": ids,
                        "summary": f"Payload/encryption candidate and {len(stages)} preparation stages across {len(nearby)} records on one host within {profile['window_hours']} hours. {profile['analyst_warning']}",
                        "tags": [tag, "esxi_behavior_profile", "not_attribution"],
                        "profile_kind": "actor_neutral_tradecraft",
                        "behavior_profile_id": profile_id,
                        "collection_id": scope[0],
                        "host": scope[1],
                        "matched_stages": sorted(stages),
                        "anchor_event_id": anchor.event_id,
                        "window_hours": profile["window_hours"],
                        "source_refs": profile["source_refs"],
                    }
                )
    return findings
