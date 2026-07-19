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


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses silently overwritten mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: MappingNode, deep: bool = False
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


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def registry_path() -> Path:
    return resource_file("rules", "tagging_registry.yml")


def load_registry_file(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            # _UniqueKeyLoader inherits from SafeLoader and only rejects duplicates.
            data = yaml.load(handle, Loader=_UniqueKeyLoader)  # nosec B506
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

    return data


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
    _validate_string_list(rule, "mitre_focus", path, attack_ids=True)
    source_refs = _validate_string_list(rule, "source_refs", path)
    source_refs += _validate_string_list(rule, "actor_refs", path)
    missing_sources = sorted(set(source_refs) - set(sources))
    if missing_sources:
        raise RegistryError(f"{path} references unknown sources: {missing_sources}")

    if section == "tool_tags":
        _required_text(rule, "category", path)
        _validate_confidence(rule, "confidence_when_matched", path)
        if not _validate_string_list(rule, "match_literals", path):
            raise RegistryError(f"{path}.match_literals must not be empty.")
    elif section == "ttp_tags":
        _required_text(rule, "evidence", path)
        _validate_severity(rule, "severity", path)
        _validate_confidence(rule, "confidence_when_matched", path)
        for field in (
            "match_detection_names",
            "match_event_actions",
            "match_tags",
        ):
            _validate_string_list(rule, field, path)
    elif section == "actor_similarity_profiles":
        _required_text(rule, "display_name", path)
        _required_text(rule, "analyst_warning", path)
        cap = _required_text(rule, "confidence_cap", path)
        if cap not in ACTOR_CONFIDENCE_CAPS:
            raise RegistryError(
                f"{path}.confidence_cap must be low or medium; actor profiles "
                "cannot produce high-confidence attribution."
            )
        count = rule.get("required_evidence_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 2:
            raise RegistryError(f"{path}.required_evidence_count must be >= 2.")
        event_count = rule.get("minimum_event_count", 2)
        if (
            not isinstance(event_count, int)
            or isinstance(event_count, bool)
            or event_count < 1
        ):
            raise RegistryError(f"{path}.minimum_event_count must be >= 1.")
        if not _validate_string_list(rule, "strong_indicators", path):
            raise RegistryError(f"{path}.strong_indicators must not be empty.")
        _validate_string_list(rule, "supporting_indicators", path)
        _validate_string_list(rule, "required_any_indicators", path)
        for field, default, minimum in (
            ("minimum_strong_indicators", 2, 1),
            ("minimum_supporting_indicators", 1, 0),
        ):
            value = rule.get(field, default)
            if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
                raise RegistryError(f"{path}.{field} must be >= {minimum}.")
    elif section == "malware_payload_tags":
        _required_text(rule, "category", path)
        _validate_confidence(rule, "confidence_when_matched", path)
        if not _validate_string_list(rule, "match_literals", path):
            raise RegistryError(f"{path}.match_literals must not be empty.")


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
