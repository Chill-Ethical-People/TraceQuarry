from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from uac_parser.resources import resource_file


class RegistryError(ValueError):
    pass


def registry_path() -> Path:
    return resource_file("rules", "tagging_registry.yml")


@lru_cache(maxsize=1)
def load_registry() -> dict[str, Any]:
    path = registry_path()
    if not path.exists():
        raise RegistryError(f"Tagging registry not found: {path}")
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise RegistryError("Tagging registry must contain a YAML mapping.")
    metadata = data.get("metadata")
    tools = data.get("tool_tags")
    if not isinstance(metadata, dict) or not metadata.get("schema_version"):
        raise RegistryError("Tagging registry metadata.schema_version is required.")
    if not isinstance(tools, dict):
        raise RegistryError("Tagging registry tool_tags must be a mapping.")
    for tool_id, rule in tools.items():
        if not isinstance(rule, dict) or not isinstance(
            rule.get("match_literals"), list
        ):
            raise RegistryError(f"Tool rule {tool_id!r} requires match_literals.")
    return data


def tool_rules() -> dict[str, dict[str, Any]]:
    return load_registry()["tool_tags"]
