from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any

from uac_parser.job_models import (
    JobState,
    JobVersionConflict,
    validate_transition,
)

JOB_ID_PATTERN = re.compile(r"^[a-f0-9]{12}$")
SCHEMA_VERSION = 2


class CaseRepositoryError(RuntimeError):
    pass


class CaseRepository:
    """Thread-safe live job cache backed by a durable local SQLite index."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._database_path: Path | None = None
        self._retention_seconds = 90 * 24 * 60 * 60
        self._cache: dict[str, dict[str, Any]] = {}
        self._last_write: dict[str, float] = {}

    @property
    def database_path(self) -> Path:
        with self._lock:
            if self._database_path is None:
                raise CaseRepositoryError("Case repository is not configured.")
            return self._database_path

    def configure(self, work_dir: Path, *, retention_days: int) -> None:
        resolved = work_dir.resolve()
        database_path = resolved / "state" / "cases.sqlite3"
        retention_seconds = retention_days * 24 * 60 * 60
        with self._lock:
            if (
                self._database_path == database_path
                and self._retention_seconds == retention_seconds
            ):
                return
            if self._database_path is not None:
                self._flush_locked()
            state_dir = database_path.parent
            state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            state_dir.chmod(0o700)
            self._database_path = database_path
            self._retention_seconds = retention_seconds
            self._cache.clear()
            self._last_write.clear()
            self._initialize_locked()
            self._load_cache_locked()

    def reset(self, *, flush: bool = False) -> None:
        with self._lock:
            if flush and self._database_path is not None:
                self._flush_locked()
            self._database_path = None
            self._cache.clear()
            self._last_write.clear()

    def register(
        self,
        document: dict[str, Any],
        *,
        force: bool = True,
        allow_recovery: bool = False,
    ) -> None:
        job_id = _document_job_id(document)
        self.persist(
            job_id,
            document,
            force=force,
            allow_recovery=allow_recovery,
        )

    def update(
        self,
        job_id: str,
        updates: dict[str, Any],
        *,
        force: bool = False,
        minimum_interval: float = 1.0,
        expected_revision: int | None = None,
        allow_recovery: bool = False,
    ) -> dict[str, Any]:
        _validate_job_id(job_id)
        with self._lock:
            document = deepcopy(self._cache.get(job_id, {"id": job_id}))
            document.update(deepcopy(updates))
            document = self._prepare_document_locked(
                job_id,
                document,
                expected_revision=expected_revision,
                allow_recovery=allow_recovery,
            )
            self._cache[job_id] = document
            self._persist_locked(
                job_id,
                document,
                force=force,
                minimum_interval=minimum_interval,
            )
            return deepcopy(document)

    def persist(
        self,
        job_id: str,
        document: dict[str, Any],
        *,
        force: bool = False,
        minimum_interval: float = 1.0,
        expected_revision: int | None = None,
        allow_recovery: bool = False,
    ) -> None:
        _validate_job_id(job_id)
        if str(document.get("id") or "") != job_id:
            raise ValueError("Case document ID does not match its repository key.")
        with self._lock:
            stored = self._prepare_document_locked(
                job_id,
                document,
                expected_revision=expected_revision,
                allow_recovery=allow_recovery,
            )
            self._cache[job_id] = stored
            self._persist_locked(
                job_id,
                stored,
                force=force,
                minimum_interval=minimum_interval,
            )

    def get(self, job_id: str) -> dict[str, Any] | None:
        _validate_job_id(job_id)
        with self._lock:
            document = self._cache.get(job_id)
            return deepcopy(document) if document is not None else None

    def contains(self, job_id: str) -> bool:
        _validate_job_id(job_id)
        with self._lock:
            return job_id in self._cache

    def list_jobs(self, *, limit: int | None = 200) -> list[dict[str, Any]]:
        with self._lock:
            documents = sorted(
                self._cache.values(),
                key=lambda item: _numeric_time(item.get("created_at")),
                reverse=True,
            )
            selected = documents if limit is None else documents[: max(0, limit)]
            return deepcopy(selected)

    def list_completed_cases(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            documents = [
                document
                for document in self._cache.values()
                if document.get("status") == "complete"
                and document.get("job_type") != "inspection"
            ]
            documents.sort(
                key=lambda item: _numeric_time(item.get("completed_at")),
                reverse=True,
            )
            return deepcopy(documents[: max(0, limit)])

    def status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._lock:
            for document in self._cache.values():
                status = str(document.get("status") or "unknown")
                counts[status] = counts.get(status, 0) + 1
        return counts

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            database_path = self.database_path
            return {
                "backend": "sqlite",
                "schema_version": SCHEMA_VERSION,
                "records": len(self._cache),
                "database_bytes": (
                    database_path.stat().st_size if database_path.exists() else 0
                ),
            }

    def delete(self, job_id: str) -> bool:
        _validate_job_id(job_id)
        with self._lock:
            existed = self._cache.pop(job_id, None) is not None
            self._last_write.pop(job_id, None)
            with self._connection_locked() as connection:
                cursor = connection.execute(
                    "DELETE FROM case_records WHERE job_id = ?", (job_id,)
                )
            self._secure_database_files_locked()
            return existed or cursor.rowcount > 0

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def prune(self) -> int:
        cutoff = time.time() - self._retention_seconds
        with self._lock:
            with self._connection_locked() as connection:
                rows = connection.execute(
                    """
                    SELECT job_id FROM case_records
                    WHERE updated_at < ?
                      AND NOT (status = 'complete' AND job_type != 'inspection')
                    """,
                    (cutoff,),
                ).fetchall()
                identifiers = [str(row[0]) for row in rows]
                connection.executemany(
                    "DELETE FROM case_records WHERE job_id = ?",
                    ((job_id,) for job_id in identifiers),
                )
            for job_id in identifiers:
                self._cache.pop(job_id, None)
                self._last_write.pop(job_id, None)
            self._secure_database_files_locked()
            return len(identifiers)

    def import_legacy_json(self, state_dir: Path) -> int:
        imported = 0
        if not state_dir.is_dir():
            return imported
        for path in sorted(state_dir.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict):
                continue
            job_id = str(value.get("id") or "")
            if not JOB_ID_PATTERN.fullmatch(job_id) or self.contains(job_id):
                continue
            try:
                self.persist(job_id, value, force=True)
            except ValueError:
                continue
            imported += 1
        return imported

    def _initialize_locked(self) -> None:
        with self._connection_locked() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise CaseRepositoryError(
                    "Case repository was created by a newer TraceQuarry version."
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_records (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    job_type TEXT NOT NULL,
                    case_name TEXT NOT NULL,
                    is_case INTEGER NOT NULL,
                    created_at REAL,
                    completed_at REAL,
                    updated_at REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    output_path TEXT NOT NULL,
                    document_json TEXT NOT NULL
                )
                """
            )
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(case_records)")
            }
            if "revision" not in columns:
                connection.execute(
                    "ALTER TABLE case_records ADD COLUMN revision INTEGER NOT NULL DEFAULT 1"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_status_completed "
                "ON case_records(status, completed_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_created "
                "ON case_records(created_at DESC)"
            )
            if version < SCHEMA_VERSION:
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            result = connection.execute("PRAGMA quick_check").fetchone()
            if not result or result[0] != "ok":
                raise CaseRepositoryError("Case repository integrity check failed.")
        self._secure_database_files_locked()

    def _load_cache_locked(self) -> None:
        with self._connection_locked() as connection:
            rows = connection.execute(
                "SELECT job_id, revision, document_json FROM case_records"
            ).fetchall()
        for job_id, revision, encoded in rows:
            try:
                document = json.loads(str(encoded))
            except json.JSONDecodeError:
                continue
            if isinstance(document, dict) and document.get("id") == job_id:
                document["revision"] = int(revision or 1)
                try:
                    JobState.from_document(document)
                except ValueError:
                    continue
                self._cache[str(job_id)] = document

    def _prepare_document_locked(
        self,
        job_id: str,
        document: dict[str, Any],
        *,
        expected_revision: int | None,
        allow_recovery: bool,
    ) -> dict[str, Any]:
        previous_document = self._cache.get(job_id)
        previous = (
            JobState.from_document(previous_document)
            if previous_document is not None
            else None
        )
        current_revision = previous.revision if previous is not None else 0
        if expected_revision is not None and expected_revision != current_revision:
            raise JobVersionConflict(
                f"Job {job_id} revision changed from {expected_revision} "
                f"to {current_revision}."
            )
        stored = deepcopy(document)
        stored["revision"] = current_revision + 1
        current = JobState.from_document(stored)
        validate_transition(previous, current, allow_recovery=allow_recovery)
        return stored

    def _persist_locked(
        self,
        job_id: str,
        document: dict[str, Any],
        *,
        force: bool,
        minimum_interval: float,
    ) -> None:
        now = time.time()
        if not force and now - self._last_write.get(job_id, 0.0) < minimum_interval:
            return
        self._write_locked(job_id, document, now)

    def _write_locked(
        self, job_id: str, document: dict[str, Any], updated_at: float
    ) -> None:
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True)
        with self._connection_locked() as connection:
            connection.execute(
                """
                INSERT INTO case_records (
                    job_id, status, job_type, case_name, is_case, created_at,
                    completed_at, updated_at, revision, output_path, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status = excluded.status,
                    job_type = excluded.job_type,
                    case_name = excluded.case_name,
                    is_case = excluded.is_case,
                    created_at = excluded.created_at,
                    completed_at = excluded.completed_at,
                    updated_at = excluded.updated_at,
                    revision = excluded.revision,
                    output_path = excluded.output_path,
                    document_json = excluded.document_json
                """,
                (
                    job_id,
                    str(document.get("status") or "unknown"),
                    str(document.get("job_type") or "analysis"),
                    str(document.get("case_name") or "TraceQuarry Case"),
                    int(bool(document.get("is_case"))),
                    _optional_numeric_time(document.get("created_at")),
                    _optional_numeric_time(document.get("completed_at")),
                    updated_at,
                    int(document.get("revision") or 1),
                    str(document.get("output") or ""),
                    encoded,
                ),
            )
        self._last_write[job_id] = updated_at
        self._secure_database_files_locked()

    def _flush_locked(self) -> None:
        now = time.time()
        for job_id, document in self._cache.items():
            self._write_locked(job_id, document, now)

    @contextmanager
    def _connection_locked(self) -> Iterator[sqlite3.Connection]:
        if self._database_path is None:
            raise CaseRepositoryError("Case repository is not configured.")
        connection = sqlite3.connect(self._database_path, timeout=30)
        try:
            connection.execute("PRAGMA busy_timeout = 30000")
            with connection:
                yield connection
        except sqlite3.Error as exc:
            raise CaseRepositoryError(
                f"Case repository operation failed: {exc}"
            ) from exc
        finally:
            connection.close()

    def _secure_database_files_locked(self) -> None:
        if self._database_path is None:
            return
        for path in (
            self._database_path,
            self._database_path.with_name(f"{self._database_path.name}-wal"),
            self._database_path.with_name(f"{self._database_path.name}-shm"),
        ):
            if path.exists():
                path.chmod(0o600)


def _document_job_id(document: dict[str, Any]) -> str:
    job_id = str(document.get("id") or "")
    _validate_job_id(job_id)
    return job_id


def _validate_job_id(job_id: str) -> None:
    if not JOB_ID_PATTERN.fullmatch(job_id):
        raise ValueError("Invalid case identifier.")


def _numeric_time(value: Any) -> float:
    numeric = _optional_numeric_time(value)
    return numeric if numeric is not None else 0.0


def _optional_numeric_time(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None
