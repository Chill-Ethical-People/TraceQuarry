from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from uac_parser.resources import resource_file

SEVERITIES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCES = {"low", "medium", "high"}
ACTOR_CONFIDENCE_CAPS = {"low", "medium"}
ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_]*$")
RULE_SECTIONS = (
    "tool_tags",
    "ttp_tags",
    "actor_similarity_profiles",
    "malware_payload_tags",
)


class RegistryError(ValueError):
    pass


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses silently overwritten mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def registry_path() -> Path:
    return resource_file("rules", "tagging_registry.yml")


def load_registry_file(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            # UniqueKeySafeLoader inherits SafeLoader and only rejects duplicates.
            data = yaml.load(handle, Loader=UniqueKeySafeLoader)  # nosec B506
    except (OSError, yaml.YAMLError) as exc:
        raise RegistryError(f"Unable to load tagging registry {path}: {exc}") from exc
    return validate_registry(data)


@lru_cache(maxsize=1)
def load_registry() -> dict[str, Any]:
    path = registry_path()
    if not path.exists():
        raise RegistryError(f"Tagging registry not found: {path}")
    return load_registry_file(path)


def validate_registry(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise RegistryError("Tagging registry must contain a YAML mapping.")
    metadata = _mapping(data, "metadata", "registry")
    if not str(metadata.get("schema_version", "")).strip():
        raise RegistryError("metadata.schema_version is required.")

    sources = _mapping(data, "source_references", "registry")
    for source_id, source in sources.items():
        _validate_rule_id(source_id, "source_references")
        source_rule = _rule_mapping(source, f"source_references.{source_id}")
        _required_text(source_rule, "title", f"source_references.{source_id}")
        url = _required_text(source_rule, "url", f"source_references.{source_id}")
        if not url.startswith("https://"):
            raise RegistryError(f"source_references.{source_id}.url must use https://")

    for section in RULE_SECTIONS:
        rules = _mapping(data, section, "registry")
        for rule_id, raw_rule in rules.items():
            _validate_rule_id(rule_id, section)
            rule = _rule_mapping(raw_rule, f"{section}.{rule_id}")
            _validate_common_rule(section, rule_id, rule, sources)

    if "esxi_behavior_profiles" in data:
        _validate_esxi_behavior_profiles(data, sources)

    return data


def _validate_esxi_behavior_profiles(
    data: dict[str, Any], sources: dict[str, Any]
) -> None:
    for profile_id, raw in _mapping(data, "esxi_behavior_profiles", "registry").items():
        _validate_rule_id(profile_id, "esxi_behavior_profiles")
        path = f"esxi_behavior_profiles.{profile_id}"
        profile = _rule_mapping(raw, path)
        for field in ("display_name", "analyst_warning"):
            _required_text(profile, field, path)
        for field, minimum in (
            ("window_hours", 1),
            ("minimum_event_count", 3),
            ("minimum_supporting_stages", 2),
        ):
            _validate_minimum_integer(
                profile, field, path, default=None, minimum=minimum
            )
        if profile["window_hours"] > 168:
            raise RegistryError(f"{path}.window_hours cannot exceed 168.")
        if not _validate_string_list(profile, "anchor_detections", path):
            raise RegistryError(f"{path} requires anchor_detections.")
        stages = _mapping(profile, "supporting_stages", path)
        if len(stages) < profile["minimum_supporting_stages"]:
            raise RegistryError(f"{path} has insufficient supporting stages.")
        for stage in stages:
            if not _validate_string_list(stages, stage, path):
                raise RegistryError(f"{path}.{stage} must not be empty.")
        refs = _validate_string_list(profile, "source_refs", path)
        if not refs or set(refs) - set(sources):
            raise RegistryError(f"{path} requires valid source_refs.")


def _validate_common_rule(
    section: str,
    rule_id: str,
    rule: dict[str, Any],
    sources: dict[str, Any],
) -> None:
    path = f"{section}.{rule_id}"
    expected_namespace = {
        "tool_tags": "tool",
        "ttp_tags": "ttp",
        "actor_similarity_profiles": "actor_similarity",
        "malware_payload_tags": "malware_payload",
    }[section]
    if _required_text(rule, "namespace", path) != expected_namespace:
        raise RegistryError(f"{path}.namespace must be {expected_namespace!r}.")
    _validate_string_list(rule, "mitre", path, attack_ids=True)
    _validate_string_list(rule, "mitre_candidates", path, attack_ids=True)
    _validate_string_list(rule, "mitre_focus", path, attack_ids=True)
    source_refs = _validate_string_list(rule, "source_refs", path)
    source_refs += _validate_string_list(rule, "actor_refs", path)
    missing_sources = sorted(set(source_refs) - set(sources))
    if missing_sources:
        raise RegistryError(f"{path} references unknown sources: {missing_sources}")

    validators = {
        "tool_tags": _validate_tool_rule,
        "ttp_tags": _validate_ttp_rule,
        "actor_similarity_profiles": _validate_actor_similarity_rule,
        "malware_payload_tags": _validate_malware_payload_rule,
    }
    validators[section](rule, path)


def _validate_literal_rule(rule: dict[str, Any], path: str) -> None:
    _required_text(rule, "category", path)
    _validate_confidence(rule, "confidence_when_matched", path)
    if not _validate_string_list(rule, "match_literals", path):
        raise RegistryError(f"{path}.match_literals must not be empty.")


def _validate_tool_rule(rule: dict[str, Any], path: str) -> None:
    _validate_literal_rule(rule, path)
    _validate_string_list(rule, "required_detection_names", path)


def _validate_ttp_rule(rule: dict[str, Any], path: str) -> None:
    _required_text(rule, "evidence", path)
    _validate_severity(rule, "severity", path)
    _validate_confidence(rule, "confidence_when_matched", path)
    for field in ("match_detection_names", "match_event_actions", "match_tags"):
        _validate_string_list(rule, field, path)


def _validate_actor_similarity_rule(rule: dict[str, Any], path: str) -> None:
    _required_text(rule, "display_name", path)
    _required_text(rule, "analyst_warning", path)
    cap = _required_text(rule, "confidence_cap", path)
    if cap not in ACTOR_CONFIDENCE_CAPS:
        raise RegistryError(
            f"{path}.confidence_cap must be low or medium; actor profiles "
            "cannot produce high-confidence attribution."
        )
    _validate_minimum_integer(
        rule, "required_evidence_count", path, default=None, minimum=2
    )
    _validate_minimum_integer(rule, "minimum_event_count", path, default=2, minimum=1)
    if not _validate_string_list(rule, "strong_indicators", path):
        raise RegistryError(f"{path}.strong_indicators must not be empty.")
    _validate_string_list(rule, "supporting_indicators", path)
    _validate_string_list(rule, "required_any_indicators", path)
    _validate_minimum_integer(
        rule, "minimum_strong_indicators", path, default=2, minimum=1
    )
    _validate_minimum_integer(
        rule, "minimum_supporting_indicators", path, default=1, minimum=0
    )


def _validate_minimum_integer(
    rule: dict[str, Any],
    key: str,
    path: str,
    *,
    default: int | None,
    minimum: int,
) -> None:
    value = rule.get(key) if default is None else rule.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RegistryError(f"{path}.{key} must be >= {minimum}.")


def _validate_malware_payload_rule(rule: dict[str, Any], path: str) -> None:
    _validate_literal_rule(rule, path)
    if "esxi_match" not in rule:
        return
    match = _mapping(rule, "esxi_match", path)
    allowed = {
        "executables",
        "artifact_names",
        "artifact_suffixes",
        "required_arguments",
        "require_vmfs_target",
    }
    if set(match) - allowed:
        raise RegistryError(f"{path}.esxi_match contains unsupported fields.")
    selectors = []
    for field in (
        "executables",
        "artifact_names",
        "artifact_suffixes",
        "required_arguments",
    ):
        selectors += _validate_string_list(match, field, path + ".esxi_match")
    if not selectors:
        raise RegistryError(f"{path}.esxi_match must contain explicit selectors.")
    if not isinstance(match.get("require_vmfs_target", False), bool):
        raise RegistryError(f"{path}.esxi_match.require_vmfs_target must be boolean.")
    if not rule.get("source_refs"):
        raise RegistryError(f"{path}.esxi_match requires source_refs.")


def _mapping(data: dict[str, Any], key: str, path: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise RegistryError(f"{path}.{key} must be a mapping.")
    return value


def _rule_mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{path} must be a mapping.")
    return value


def _validate_rule_id(value: Any, section: str) -> None:
    if not isinstance(value, str) or not RULE_ID.fullmatch(value):
        raise RegistryError(
            f"{section} rule ID {value!r} must use lowercase letters, digits, "
            "and underscores."
        )


def _required_text(rule: dict[str, Any], key: str, path: str) -> str:
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{path}.{key} must be a non-empty string.")
    return value.strip()


def _validate_string_list(
    rule: dict[str, Any], key: str, path: str, *, attack_ids: bool = False
) -> list[str]:
    if key not in rule:
        return []
    value = rule[key]
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise RegistryError(f"{path}.{key} must be a list of non-empty strings.")
    values = [item.strip() for item in value]
    if len(values) != len(set(values)):
        raise RegistryError(f"{path}.{key} contains duplicate values.")
    if attack_ids:
        invalid = [item for item in values if not ATTACK_ID.fullmatch(item)]
        if invalid:
            raise RegistryError(f"{path}.{key} contains invalid ATT&CK IDs: {invalid}")
    return values


def _validate_confidence(rule: dict[str, Any], key: str, path: str) -> None:
    value = _required_text(rule, key, path)
    if value not in CONFIDENCES:
        raise RegistryError(f"{path}.{key} must be one of {sorted(CONFIDENCES)}.")


def _validate_severity(rule: dict[str, Any], key: str, path: str) -> None:
    value = _required_text(rule, key, path)
    if value not in SEVERITIES:
        raise RegistryError(f"{path}.{key} must be one of {sorted(SEVERITIES)}.")


def tool_rules() -> dict[str, dict[str, Any]]:
    return load_registry()["tool_tags"]


def ttp_rules() -> dict[str, dict[str, Any]]:
    return load_registry()["ttp_tags"]


def actor_similarity_rules() -> dict[str, dict[str, Any]]:
    return load_registry()["actor_similarity_profiles"]


def malware_payload_rules() -> dict[str, dict[str, Any]]:
    return load_registry()["malware_payload_tags"]
