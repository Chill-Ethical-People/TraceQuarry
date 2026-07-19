from __future__ import annotations

import csv
import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from uac_parser.output.permissions import secure_file
from uac_parser.timeline.event import TimelineEvent


@dataclass(frozen=True)
class Ioc:
    value: str
    kind: str = "literal"
    label: str = ""


def parse_ioc_text(text: str | None) -> list[Ioc]:
    if not text:
        return []
    output: list[Ioc] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line:
            parts = [part.strip() for part in line.split(",")]
            value = parts[0]
            kind = parts[1] if len(parts) > 1 and parts[1] else _guess_kind(value)
            label = parts[2] if len(parts) > 2 else ""
        else:
            value = line
            kind = _guess_kind(value)
            label = ""
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        output.append(Ioc(value=value, kind=kind, label=label))
    return output


def load_iocs(path: str | Path | None) -> list[Ioc]:
    if not path:
        return []
    return parse_ioc_text(
        Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    )


def match_iocs(
    events: Iterable[TimelineEvent], iocs: list[Ioc]
) -> list[dict[str, object]]:
    if not iocs:
        return []
    hits: list[dict[str, object]] = []
    for event in events:
        searchable = _event_search_text(event)
        for ioc in iocs:
            if _ioc_matches(ioc, event, searchable):
                hits.append(
                    {
                        "ioc": ioc.value,
                        "ioc_kind": ioc.kind,
                        "ioc_label": ioc.label,
                        "event_id": event.event_id,
                        "timestamp": event.timestamp,
                        "source_path": event.source_path,
                        "source_type": event.source_type,
                        "event_action": event.event_action,
                        "user": event.user,
                        "src_ip": event.src_ip,
                        "dst_ip": event.dst_ip,
                        "file_path": event.file_path,
                        "command": event.command,
                        "summary": event.summary,
                        "raw": event.raw,
                    }
                )
    return hits


def write_ioc_hits(out_dir: Path, hits: list[dict[str, object]]) -> None:
    json_path = out_dir / "ioc_hits.json"
    json_path.write_text(
        json.dumps(hits, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    secure_file(json_path)
    fields = [
        "ioc",
        "ioc_kind",
        "ioc_label",
        "event_id",
        "timestamp",
        "source_path",
        "source_type",
        "event_action",
        "user",
        "src_ip",
        "dst_ip",
        "file_path",
        "command",
        "summary",
    ]
    csv_path = out_dir / "ioc_hits.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for hit in hits:
            writer.writerow({field: hit.get(field) for field in fields})
    secure_file(csv_path)


def ioc_finding(hits: list[dict[str, object]]) -> dict[str, object] | None:
    if not hits:
        return None
    event_ids = []
    for hit in hits:
        event_id = hit.get("event_id")
        if event_id and event_id not in event_ids:
            event_ids.append(str(event_id))
        if len(event_ids) >= 10:
            break
    unique_iocs = sorted({str(hit["ioc"]) for hit in hits})
    return {
        "title": "Known IoC Match",
        "severity": "high",
        "confidence": "high",
        "event_ids": event_ids,
        "summary": f"Observed {len(hits)} event(s) matching {len(unique_iocs)} supplied IoC(s).",
        "tags": ["known_ioc_match"],
        "iocs": unique_iocs[:50],
    }


def _guess_kind(value: str) -> str:
    lower = value.lower()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", lower):
        return "hash"
    if "/" in value or "\\" in value:
        return "path"
    if re.fullmatch(r"[a-z0-9_.-]+(\.[a-z0-9_.-]+)+", lower):
        return "domain"
    return "literal"


def _ioc_matches(ioc: Ioc, event: TimelineEvent, searchable: str) -> bool:
    value = ioc.value.strip()
    if not value:
        return False
    if ioc.kind == "ip":
        return value in {event.src_ip, event.dst_ip} or _wordish_search(
            value, searchable
        )
    if ioc.kind == "domain":
        return value.lower() in searchable.lower()
    if ioc.kind == "path":
        return value.lower() in searchable.lower()
    if ioc.kind == "hash":
        return value.lower() in searchable.lower()
    return _wordish_search(value, searchable)


def _wordish_search(needle: str, haystack: str) -> bool:
    escaped = re.escape(needle)
    return (
        re.search(
            rf"(?<![A-Za-z0-9_.:-]){escaped}(?![A-Za-z0-9_.:-])",
            haystack,
            re.IGNORECASE,
        )
        is not None
    )


def _event_search_text(event: TimelineEvent) -> str:
    fields = [
        event.user,
        event.src_ip,
        event.dst_ip,
        event.process,
        event.command,
        event.file_path,
        event.summary,
        event.raw,
        event.source_path,
    ]
    return "\n".join(field for field in fields if field)
