from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from contextlib import suppress
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from uac_parser.timeline.event import TimelineEvent
from uac_parser.timeline.timestamp import parse_any, to_utc_iso

MAX_DATABASE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TABLES = 256
MAX_COLUMNS = 128
MAX_ROWS_PER_TABLE = 100_000
MAX_ROWS_PER_DATABASE = 250_000
MAX_FIELD_CHARS = 4096
TIMESTAMP_NAMES = {
    "timestamp",
    "time_stamp",
    "datetime",
    "date_time",
    "event_time",
    "eventtime",
    "log_time",
    "logtime",
    "created_at",
    "updated_at",
    "modified_at",
    "occurred_at",
    "utcsec",
    "r_utcsec",
    "epoch",
    "time",
    "date",
    "created",
    "updated",
    "modified",
}
MESSAGE_NAMES = (
    "msg",
    "message",
    "description",
    "detail",
    "event",
    "action",
    "operation",
    "command",
)


def parse(
    path: Path,
    relative: str,
    host: str = "",
    year: int | None = None,
    timezone_name: str = "UTC",
) -> list[TimelineEvent]:
    if path.stat().st_size > MAX_DATABASE_BYTES:
        raise ValueError("SQLite database exceeds the 4 GiB parser safety limit.")
    database = sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1",
        uri=True,
        timeout=1,
    )
    try:
        database.execute("PRAGMA query_only=ON")
        with suppress(sqlite3.DatabaseError):
            database.execute("PRAGMA trusted_schema=OFF")
        tables = [
            str(row[0])
            for row in database.execute(
                "SELECT name FROM sqlite_schema "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name "
                "LIMIT ?",
                (MAX_TABLES + 1,),
            )
        ]
        truncated_tables = len(tables) > MAX_TABLES
        tables = tables[:MAX_TABLES]
        lookups = _load_synology_lookups(database, tables)
        events: list[TimelineEvent] = []
        remaining = MAX_ROWS_PER_DATABASE
        for table in tables:
            if remaining <= 0:
                break
            table_events, examined, omitted, truncated = _parse_table(
                database,
                table,
                relative,
                host,
                year,
                timezone_name,
                lookups,
                min(MAX_ROWS_PER_TABLE, remaining),
            )
            remaining -= examined
            events.extend(table_events)
            events.append(
                _inventory_event(
                    relative,
                    table,
                    host,
                    examined,
                    len(table_events),
                    omitted,
                    truncated,
                    _is_synology_database(path),
                )
            )
        if truncated_tables or remaining <= 0:
            events.append(
                TimelineEvent(
                    host=host,
                    source_path=relative,
                    source_type="sqlite_log",
                    parser="sqlite_log",
                    event_category="evidence",
                    event_action="sqlite_extraction_truncated",
                    evidence_role="state",
                    severity="medium",
                    confidence="high",
                    tags=["sqlite", "coverage_limit"],
                    summary=(
                        "SQLite extraction reached a defensive table or row limit; "
                        "review the database directly for records beyond the parsed scope."
                    ),
                    extra={
                        "table_limit": MAX_TABLES,
                        "database_row_limit": MAX_ROWS_PER_DATABASE,
                    },
                )
            )
        return events
    finally:
        database.close()


def _parse_table(
    database: sqlite3.Connection,
    table: str,
    relative: str,
    host_override: str,
    year: int | None,
    timezone_name: str,
    lookups: dict[str, dict[Any, str]],
    row_limit: int,
) -> tuple[list[TimelineEvent], int, int, bool]:
    columns = [
        str(row[1])
        for row in database.execute("SELECT * FROM pragma_table_info(?)", (table,))
    ][:MAX_COLUMNS]
    timestamp_columns = [name for name in columns if _is_timestamp_column(name)]
    if "ldate" in columns and "ltime" in columns:
        timestamp_columns.insert(0, "ldate+ltime")
    if not columns or not timestamp_columns:
        return [], 0, 0, False
    quoted_columns = ", ".join(_quote_identifier(name) for name in columns)
    query = f"SELECT {quoted_columns} FROM {_quote_identifier(table)} LIMIT ?"
    cursor = database.execute(query, (row_limit + 1,))
    events: list[TimelineEvent] = []
    examined = 0
    omitted = 0
    truncated = False
    for values in cursor:
        if examined >= row_limit:
            truncated = True
            break
        examined += 1
        record = dict(zip(columns, values, strict=True))
        timestamp, timestamp_raw, timestamp_column, confidence = _record_timestamp(
            record, timestamp_columns, year, timezone_name
        )
        if not timestamp:
            omitted += 1
            continue
        normalized = {key: _safe_value(value) for key, value in record.items()}
        resolved_host = host_override or _resolved_value(
            record.get("host"), lookups.get("hosts", {})
        )
        process = _resolved_value(record.get("prog"), lookups.get("progs", {}))
        tag = _resolved_value(record.get("tag"), lookups.get("tags", {}))
        message = _message(record)
        src_ip = _ip_value(record.get("ip"))
        summary = message or "SQLite log record"
        if process and not summary.lower().startswith(process.lower()):
            summary = f"{process}: {summary}"
        tags = ["sqlite", "database_log"]
        if _is_synology_name(relative):
            tags.append("synology_nas")
        if tag:
            tags.append(f"synology_tag:{_tag_value(tag)}")
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                timestamp_raw=timestamp_raw,
                timezone="UTC" if _looks_numeric(timestamp_raw) else timezone_name,
                timezone_confidence=(
                    "high" if _looks_numeric(timestamp_raw) else "medium"
                ),
                timestamp_type="log_time",
                timestamp_precision="second",
                timestamp_confidence=confidence,
                host=resolved_host,
                source_path=f"{relative}#table={table}",
                source_type="sqlite_log",
                parser="sqlite_log",
                event_category="system_activity",
                event_action="sqlite_log_record",
                process=process or None,
                src_ip=src_ip,
                severity="informational",
                confidence="medium",
                tags=tags,
                summary=summary[:1000],
                raw=json.dumps(normalized, ensure_ascii=False, sort_keys=True),
                extra={
                    "database_file": relative,
                    "table": table,
                    "row_index": examined,
                    "timestamp_column": timestamp_column,
                    "record": normalized,
                },
            )
        )
    return events, examined, omitted, truncated


def _inventory_event(
    relative: str,
    table: str,
    host: str,
    examined: int,
    emitted: int,
    omitted: int,
    truncated: bool,
    synology: bool,
) -> TimelineEvent:
    tags = ["sqlite", "table_inventory"]
    if synology:
        tags.append("synology_nas")
    return TimelineEvent(
        host=host,
        source_path=f"{relative}#table={table}",
        source_type="sqlite_log",
        parser="sqlite_log",
        event_category="evidence",
        event_action="sqlite_table_inventory",
        evidence_role="state",
        severity="informational",
        confidence="high",
        tags=tags,
        summary=(
            f"SQLite table {table}: examined {examined} row(s), emitted {emitted} "
            f"timestamped event(s), and omitted {omitted} row(s) without a usable time."
        ),
        extra={
            "database_file": relative,
            "table": table,
            "rows_examined": examined,
            "timestamped_rows_emitted": emitted,
            "rows_without_usable_time": omitted,
            "truncated": truncated,
        },
    )


def _record_timestamp(
    record: dict[str, Any],
    candidates: list[str],
    year: int | None,
    timezone_name: str,
) -> tuple[str, str, str, str]:
    for column in candidates:
        if column == "ldate+ltime":
            raw = f"{record.get('ldate') or ''} {record.get('ltime') or ''}".strip()
        else:
            raw = str(record.get(column) or "").strip()
        if not raw:
            continue
        parsed = _parse_timestamp_value(raw, year, timezone_name)
        if parsed:
            return parsed, raw, column, "high" if _looks_numeric(raw) else "medium"
    return "", "", "", "not_applicable"


def _parse_timestamp_value(
    value: str, year: int | None, timezone_name: str
) -> str | None:
    if _looks_numeric(value):
        number = float(value)
        magnitude = abs(number)
        if magnitude >= 1e17:
            number /= 1e9
        elif magnitude >= 1e14:
            number /= 1e6
        elif magnitude >= 1e11:
            number /= 1e3
        if 315_532_800 <= number <= 4_102_444_800:
            try:
                return to_utc_iso(datetime.fromtimestamp(number, tz=UTC))
            except (OverflowError, OSError, ValueError):
                return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is not None:
        if parsed.tzinfo is None:
            try:
                zone: tzinfo = ZoneInfo(timezone_name)
            except ZoneInfoNotFoundError:
                zone = UTC
            parsed = parsed.replace(tzinfo=zone)
        return to_utc_iso(parsed)
    return parse_any(text, year=year, timezone_name=timezone_name)


def _load_synology_lookups(
    database: sqlite3.Connection, tables: list[str]
) -> dict[str, dict[Any, str]]:
    specs = {
        "hosts": (("host_id", "id"), ("host_name", "name")),
        "progs": (("prog_id", "id"), ("prog_name", "name")),
        "tags": (("tag_id", "id"), ("tag_name", "name")),
        "facs": (("fac_id", "id"), ("fac_name", "name")),
    }
    output: dict[str, dict[Any, str]] = {}
    for table, (id_names, value_names) in specs.items():
        if table not in tables:
            continue
        columns = {
            str(row[1])
            for row in database.execute("SELECT * FROM pragma_table_info(?)", (table,))
        }
        id_column = next((name for name in id_names if name in columns), "")
        value_column = next((name for name in value_names if name in columns), "")
        if not id_column or not value_column:
            continue
        query = (
            f"SELECT {_quote_identifier(id_column)}, {_quote_identifier(value_column)} "
            f"FROM {_quote_identifier(table)} LIMIT 100000"
        )
        output[table] = {
            row[0]: str(row[1])
            for row in database.execute(query)
            if row[0] is not None and row[1] is not None
        }
    return output


def _is_timestamp_column(name: str) -> bool:
    lowered = name.lower()
    return lowered in TIMESTAMP_NAMES or bool(
        re.search(r"(?:^|_)(?:timestamp|datetime|epoch|utcsec|time)(?:$|_)", lowered)
    )


def _message(record: dict[str, Any]) -> str:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in MESSAGE_NAMES:
        value = lowered.get(name)
        if value not in (None, ""):
            return str(_safe_value(value))
    return ""


def _resolved_value(value: Any, lookup: dict[Any, str]) -> str:
    if value in lookup:
        return lookup[value]
    return "" if value is None else str(value)


def _ip_value(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, int) or str(value).isdigit():
            return str(ipaddress.IPv4Address(int(value)))
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return str(value)[:64]


def _safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"blob_bytes": len(value), "hex_prefix": value[:128].hex()}
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return str(value)[:MAX_FIELD_CHARS]


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _is_synology_database(path: Path) -> bool:
    return _is_synology_name(path.name)


def _is_synology_name(value: str) -> bool:
    return Path(value).name.upper().startswith(".SYNO") or Path(
        value
    ).name.upper().startswith("SYNO")


def _tag_value(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "_", value.strip().lower())[:40] or "unknown"
