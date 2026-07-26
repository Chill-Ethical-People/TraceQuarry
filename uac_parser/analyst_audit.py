from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def append_annotation_audit(
    path: Path,
    *,
    event_id: str,
    before: dict[str, Any],
    after: dict[str, Any],
    actor: str = "local_analyst",
) -> dict[str, Any]:
    records = read_and_verify(path)
    previous_hash = str(records[-1]["record_hash"]) if records else GENESIS_HASH
    record: dict[str, Any] = {
        "schema_version": "1.0",
        "sequence": len(records) + 1,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "action": "annotation_removed" if not after else "annotation_saved",
        "actor": actor,
        "event_id": event_id,
        "before": before,
        "after": after,
        "previous_hash": previous_hash,
    }
    record["record_hash"] = _record_hash(record)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for existing in records:
            handle.write(_canonical_json(existing) + "\n")
        handle.write(_canonical_json(record) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)
    path.chmod(0o600)
    return record


def read_and_verify(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Analyst audit record {line_number} is not valid JSON."
                ) from exc
            if not isinstance(record, dict):
                raise ValueError(
                    f"Analyst audit record {line_number} must be a JSON object."
                )
            if int(record.get("sequence") or 0) != len(records) + 1:
                raise ValueError(
                    f"Analyst audit sequence is invalid at record {line_number}."
                )
            if record.get("previous_hash") != previous_hash:
                raise ValueError(
                    f"Analyst audit chain is broken at record {line_number}."
                )
            expected_hash = _record_hash(record)
            if record.get("record_hash") != expected_hash:
                raise ValueError(
                    f"Analyst audit record {line_number} failed integrity verification."
                )
            previous_hash = expected_hash
            records.append(record)
    return records


def audit_status(path: Path) -> dict[str, Any]:
    try:
        records = read_and_verify(path)
    except ValueError as exc:
        return {"valid": False, "records": 0, "error": str(exc)}
    return {
        "valid": True,
        "records": len(records),
        "head_hash": records[-1]["record_hash"] if records else GENESIS_HASH,
    }


def _record_hash(record: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    return hashlib.sha256(_canonical_json(unsigned).encode("utf-8")).hexdigest()


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
