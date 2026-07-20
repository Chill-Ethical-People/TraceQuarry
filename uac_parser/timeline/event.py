from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class TimelineEvent:
    schema_version: str = "1.1"
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
        return asdict(self)
