from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from uac_parser.enrich.rule_registry import UniqueKeySafeLoader
from uac_parser.resources import resource_file
from uac_parser.timeline.event import TimelineEvent

ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TACTIC_ID = re.compile(r"^TA\d{4}$")
PHASE_KEY = re.compile(r"^[a-z][a-z0-9_]*$")


class AttackPhaseRegistryError(ValueError):
    pass


@dataclass(frozen=True)
class AttackPhase:
    key: str
    tactic_id: str
    label: str
    order: int


def attack_phase_registry_path() -> Path:
    return resource_file("rules", "attack_phases.yml")


@lru_cache(maxsize=1)
def load_attack_phase_registry() -> dict[str, Any]:
    path = attack_phase_registry_path()
    if not path.is_file():
        raise AttackPhaseRegistryError(f"ATT&CK phase registry not found: {path}")
    return load_attack_phase_registry_file(path)


def load_attack_phase_registry_file(path: Path) -> dict[str, Any]:
    try:
        # UniqueKeySafeLoader inherits SafeLoader and only rejects duplicates.
        data = yaml.load(  # nosec B506
            path.read_text(encoding="utf-8"), Loader=UniqueKeySafeLoader
        )
    except (OSError, yaml.YAMLError) as exc:
        raise AttackPhaseRegistryError(
            f"Unable to load ATT&CK phase registry {path}: {exc}"
        ) from exc
    return validate_attack_phase_registry(data)


def validate_attack_phase_registry(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise AttackPhaseRegistryError("ATT&CK phase registry must be a mapping.")
    metadata = data.get("metadata")
    phases = data.get("phases")
    phase_signals = data.get("phase_signals")
    techniques = data.get("techniques")
    if (
        not isinstance(metadata, dict)
        or not str(metadata.get("schema_version") or "").strip()
    ):
        raise AttackPhaseRegistryError("metadata.schema_version is required.")
    if not isinstance(phases, dict) or not phases:
        raise AttackPhaseRegistryError("phases must be a non-empty mapping.")
    if not isinstance(techniques, dict):
        raise AttackPhaseRegistryError("techniques must be a mapping.")
    if not isinstance(phase_signals, dict):
        raise AttackPhaseRegistryError("phase_signals must be a mapping.")

    _validate_phase_definitions(phases)
    _validate_phase_signals(phase_signals, phases)
    _validate_technique_mappings(techniques, phases)
    return data


def _validate_phase_definitions(phases: dict[str, Any]) -> None:
    orders: set[int] = set()
    for key, value in phases.items():
        if not isinstance(key, str) or not PHASE_KEY.fullmatch(key):
            raise AttackPhaseRegistryError(f"Invalid phase key: {key!r}")
        if not isinstance(value, dict):
            raise AttackPhaseRegistryError(f"phases.{key} must be a mapping.")
        tactic_id = str(value.get("id") or "")
        label = str(value.get("label") or "").strip()
        order = value.get("order")
        if not TACTIC_ID.fullmatch(tactic_id):
            raise AttackPhaseRegistryError(f"phases.{key}.id is invalid.")
        if not label:
            raise AttackPhaseRegistryError(f"phases.{key}.label is required.")
        if not isinstance(order, int) or isinstance(order, bool) or order in orders:
            raise AttackPhaseRegistryError(
                f"phases.{key}.order must be a unique integer."
            )
        orders.add(order)


def _validate_phase_signals(
    phase_signals: dict[str, Any], phases: dict[str, Any]
) -> None:
    unknown_signal_phases = set(phase_signals) - set(phases)
    if unknown_signal_phases:
        raise AttackPhaseRegistryError(
            f"phase_signals contains unknown phases: {sorted(unknown_signal_phases)}"
        )
    for key, values in phase_signals.items():
        if (
            not isinstance(values, list)
            or not values
            or any(
                not isinstance(value, str) or not PHASE_KEY.fullmatch(value)
                for value in values
            )
        ):
            raise AttackPhaseRegistryError(
                f"phase_signals.{key} must be a non-empty list of normalized signals."
            )
        if len(values) != len(set(values)):
            raise AttackPhaseRegistryError(
                f"phase_signals.{key} contains duplicate signals."
            )


def _validate_technique_mappings(
    techniques: dict[str, Any], phases: dict[str, Any]
) -> None:
    for technique, mapped_phases in techniques.items():
        if not isinstance(technique, str) or not ATTACK_ID.fullmatch(technique):
            raise AttackPhaseRegistryError(
                f"Invalid ATT&CK technique ID: {technique!r}"
            )
        if not isinstance(mapped_phases, list) or not mapped_phases:
            raise AttackPhaseRegistryError(
                f"techniques.{technique} must contain at least one phase."
            )
        if len(mapped_phases) != len(set(mapped_phases)):
            raise AttackPhaseRegistryError(
                f"techniques.{technique} contains duplicate phases."
            )
        unknown = [phase for phase in mapped_phases if phase not in phases]
        if unknown:
            raise AttackPhaseRegistryError(
                f"techniques.{technique} references unknown phases: {unknown}"
            )


def attack_phases() -> tuple[AttackPhase, ...]:
    registry = load_attack_phase_registry()
    values = [
        AttackPhase(
            key=key,
            tactic_id=str(value["id"]),
            label=str(value["label"]),
            order=int(value["order"]),
        )
        for key, value in registry["phases"].items()
    ]
    return tuple(sorted(values, key=lambda phase: phase.order))


def attack_phase_metadata() -> dict[str, str]:
    metadata = load_attack_phase_registry()["metadata"]
    return {
        "attack_version": str(metadata.get("attack_version") or "unknown"),
        "attack_release_date": str(metadata.get("attack_release_date") or ""),
        "source": str(metadata.get("source") or ""),
    }


def enrich_attack_phases(events: list[TimelineEvent]) -> list[TimelineEvent]:
    for event in events:
        confirmed, candidates = classify_attack_phases(
            event.mitre,
            event.mitre_candidates,
            evidence_role=event.evidence_role,
            signals=[
                event.event_category,
                event.event_action,
                *event.tags,
                *event.detection_names,
                *event.ttp_flags,
            ],
        )
        event.attack_phases = confirmed
        event.attack_phase_candidates = candidates
    return events


def classify_attack_phases(
    confirmed_techniques: list[str],
    candidate_techniques: list[str],
    *,
    evidence_role: str,
    signals: list[str],
) -> tuple[list[str], list[str]]:
    registry = load_attack_phase_registry()
    mappings: dict[str, list[str]] = registry["techniques"]
    normalized_signals = {str(signal).strip().lower() for signal in signals if signal}
    hinted_phases = {
        phase
        for phase, phase_signals in registry["phase_signals"].items()
        if normalized_signals & set(phase_signals)
    }
    confirmed: set[str] = set()
    candidates: set[str] = set()
    for technique in confirmed_techniques:
        options = set(mappings.get(technique, []))
        contextual = options & hinted_phases
        if evidence_role == "behavior" and contextual:
            confirmed.update(contextual)
        elif evidence_role == "behavior" and len(options) == 1:
            confirmed.update(options)
        else:
            candidates.update(options)
    candidates.update(
        phase
        for technique in candidate_techniques
        for phase in mappings.get(technique, [])
    )
    candidates.difference_update(confirmed)
    return order_attack_phases(confirmed), order_attack_phases(candidates)


def phases_for_techniques(techniques: list[str]) -> list[str]:
    mappings: dict[str, list[str]] = load_attack_phase_registry()["techniques"]
    phases = {
        phase for technique in techniques for phase in mappings.get(technique, [])
    }
    return order_attack_phases(phases)


def order_attack_phases(phases: set[str] | list[str]) -> list[str]:
    order = {phase.key: phase.order for phase in attack_phases()}
    return sorted({phase for phase in phases if phase in order}, key=order.__getitem__)
