from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TimelineEvent:
    schema_version: str = "1.2"
    event_id: str = ""
    timestamp: str = ""
    timestamp_raw: str = ""
    time_start: str = ""
    time_end: str = ""
    timezone: str = "UTC"
    timezone_confidence: str = "unknown"
    timestamp_type: str = "event_time"
    timestamp_precision: str = "unknown"
    timestamp_confidence: str = "medium"
    evidence_role: str = "behavior"
    host: str = ""
    collection_id: str = ""
    collection_name: str = ""
    collection_input: str = ""
    collection_host: str = ""
    source_path: str = ""
    source_sha256: str = ""
    source_type: str = ""
    parser: str = ""
    parser_version: str = ""
    event_category: str = ""
    event_action: str = ""
    user: str | None = None
    uid: str | None = None
    gid: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    port: str | None = None
    process: str | None = None
    pid: str | None = None
    command: str | None = None
    file_path: str | None = None
    mitre: list[str] = field(default_factory=list)
    mitre_candidates: list[str] = field(default_factory=list)
    attack_phases: list[str] = field(default_factory=list)
    attack_phase_candidates: list[str] = field(default_factory=list)
    detection_names: list[str] = field(default_factory=list)
    ttp_flags: list[str] = field(default_factory=list)
    severity: str = "informational"
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)
    summary: str = ""
    raw: str = ""
    related_event_ids: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = self.__dict__.copy()
        for name in (
            "mitre",
            "mitre_candidates",
            "attack_phases",
            "attack_phase_candidates",
            "detection_names",
            "ttp_flags",
            "tags",
            "related_event_ids",
        ):
            payload[name] = list(payload[name])
        payload["extra"] = deepcopy(self.extra)
        return payload
