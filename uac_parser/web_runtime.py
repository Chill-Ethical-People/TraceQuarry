from __future__ import annotations

import json
import secrets
import shutil
import threading
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from uac_parser.case_repository import CaseRepository


@dataclass(frozen=True, slots=True)
class WebSettings:
    work_dir: Path
    input_roots: tuple[Path, ...]
    max_request_bytes: int = 8 * 1024 * 1024 * 1024
    max_work_bytes: int = 40 * 1024 * 1024 * 1024
    minimum_free_bytes: int = 512 * 1024 * 1024
    request_timeout: float = 1800
    case_workers: int = 2
    debug: bool = False
    maintenance_interval: float = 300
    state_retention_days: int = 90
    log_format: str = "text"
    started_at: float = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "work_dir", self.work_dir.resolve())
        object.__setattr__(
            self,
            "input_roots",
            tuple(path.resolve() for path in self.input_roots),
        )
        if not self.input_roots:
            raise ValueError("At least one server-side input root is required.")
        if self.max_request_bytes <= 0 or self.max_work_bytes <= 0:
            raise ValueError("Runtime capacity limits must be positive.")
        if self.request_timeout < 5:
            raise ValueError("Request timeout must be at least five seconds.")
        if self.case_workers < 1:
            raise ValueError("At least one case worker is required.")
        if self.maintenance_interval < 10:
            raise ValueError("Maintenance interval must be at least ten seconds.")
        if self.state_retention_days < 1:
            raise ValueError("Case-state retention must be at least one day.")
        if self.log_format not in {"text", "json"}:
            raise ValueError("Runtime log format must be text or json.")
        if self.started_at <= 0:
            object.__setattr__(self, "started_at", time.time())


class ApplicationContext:
    """Own all mutable services used by one TraceQuarry web application."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._settings: WebSettings | None = None
        self.csrf_token = secrets.token_urlsafe(32)
        self.uploads_lock = threading.Lock()
        self.capacity = WorkCapacityManager()
        self.cases = CaseRepository()
        self.maintenance_stop = threading.Event()
        self.maintenance_thread: threading.Thread | None = None
        self._job_slots: threading.BoundedSemaphore | None = None

    @property
    def settings(self) -> WebSettings:
        with self._lock:
            if self._settings is None:
                raise RuntimeError("TraceQuarry application context is not configured.")
            return self._settings

    def configure(
        self,
        settings: WebSettings,
        *,
        max_concurrent_jobs: int | None = None,
    ) -> None:
        if max_concurrent_jobs is not None and max_concurrent_jobs < 1:
            raise ValueError("At least one concurrent job slot is required.")
        with self._lock:
            self._settings = settings
            self.capacity.configure(
                settings.work_dir,
                max_work_bytes=settings.max_work_bytes,
                minimum_free_bytes=settings.minimum_free_bytes,
                session_ttl_seconds=7 * 24 * 60 * 60,
            )
            self.cases.configure(
                settings.work_dir,
                retention_days=settings.state_retention_days,
            )
            if max_concurrent_jobs is not None:
                self._job_slots = threading.BoundedSemaphore(max_concurrent_jobs)

    def replace_settings(self, **updates: Any) -> WebSettings:
        with self._lock:
            settings = replace(self.settings, **updates)
        self.configure(settings)
        return settings

    def acquire_job_slot(self) -> bool:
        with self._lock:
            slots = self._job_slots
        return slots is not None and slots.acquire(blocking=False)

    def release_job_slot(self) -> None:
        with self._lock:
            slots = self._job_slots
        if slots is not None:
            slots.release()

    def set_job_limit(self, maximum: int | None) -> None:
        if maximum is not None and maximum < 1:
            raise ValueError("At least one concurrent job slot is required.")
        with self._lock:
            self._job_slots = (
                threading.BoundedSemaphore(maximum) if maximum is not None else None
            )

    def reset(self, *, flush: bool = False) -> None:
        with self._lock:
            self.maintenance_stop.set()
            self.maintenance_thread = None
            self._job_slots = None
            self.capacity.reset()
            self.cases.reset(flush=flush)
            self._settings = None


@dataclass(frozen=True)
class CapacitySnapshot:
    work_bytes: int
    reserved_bytes: int
    committed_bytes: int
    max_work_bytes: int
    disk_free_bytes: int
    minimum_free_bytes: int
    active_reservations: int
    measured_at: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


class WorkCapacityManager:
    """Serialize upload reservations and cache expensive work-tree measurements."""

    def __init__(self, *, cache_seconds: float = 15.0) -> None:
        self._lock = threading.RLock()
        self._cache_seconds = cache_seconds
        self._work_dir: Path | None = None
        self._max_work_bytes = 0
        self._minimum_free_bytes = 0
        self._session_ttl_seconds = 0
        self._work_bytes: int | None = None
        self._measured_at = 0.0
        self._reservations: dict[str, int] = {}

    def configure(
        self,
        work_dir: Path,
        *,
        max_work_bytes: int,
        minimum_free_bytes: int,
        session_ttl_seconds: int,
    ) -> None:
        resolved = work_dir.resolve()
        with self._lock:
            changed = (
                self._work_dir != resolved
                or self._max_work_bytes != max_work_bytes
                or self._minimum_free_bytes != minimum_free_bytes
                or self._session_ttl_seconds != session_ttl_seconds
            )
            self._work_dir = resolved
            self._max_work_bytes = max_work_bytes
            self._minimum_free_bytes = minimum_free_bytes
            self._session_ttl_seconds = session_ttl_seconds
            if changed:
                self._work_bytes = None
                self._measured_at = 0.0
                self._reservations = self._recover_reservations_locked()

    def reset(self) -> None:
        with self._lock:
            self._work_dir = None
            self._max_work_bytes = 0
            self._minimum_free_bytes = 0
            self._session_ttl_seconds = 0
            self._work_bytes = None
            self._measured_at = 0.0
            self._reservations.clear()

    def reserve(self, reservation_id: str, incoming_bytes: int) -> CapacitySnapshot:
        if incoming_bytes < 0:
            raise ValueError("Incoming evidence size cannot be negative.")
        with self._lock:
            if reservation_id in self._reservations:
                raise ValueError("Upload reservation already exists.")
            snapshot = self._snapshot_locked(force=False)
            projected = snapshot.work_bytes + snapshot.reserved_bytes + incoming_bytes
            if projected > snapshot.max_work_bytes:
                raise ValueError("TraceQuarry work-directory quota would be exceeded.")
            required_free = (
                snapshot.reserved_bytes + incoming_bytes + snapshot.minimum_free_bytes
            )
            if snapshot.disk_free_bytes < required_free:
                raise ValueError(
                    "Insufficient free disk space for this request, active upload "
                    "reservations, and the evidence safety reserve."
                )
            self._reservations[reservation_id] = incoming_bytes
            return self._snapshot_locked(force=False)

    def check(self, incoming_bytes: int) -> CapacitySnapshot:
        if incoming_bytes < 0:
            raise ValueError("Incoming evidence size cannot be negative.")
        with self._lock:
            snapshot = self._snapshot_locked(force=False)
            projected = snapshot.work_bytes + snapshot.reserved_bytes + incoming_bytes
            if projected > snapshot.max_work_bytes:
                raise ValueError("TraceQuarry work-directory quota would be exceeded.")
            required_free = (
                snapshot.reserved_bytes + incoming_bytes + snapshot.minimum_free_bytes
            )
            if snapshot.disk_free_bytes < required_free:
                raise ValueError(
                    "Insufficient free disk space for this request, active upload "
                    "reservations, and the evidence safety reserve."
                )
            return snapshot

    def consume(self, reservation_id: str, written_bytes: int) -> None:
        if written_bytes < 0:
            raise ValueError("Written evidence size cannot be negative.")
        with self._lock:
            remaining = self._reservations.get(reservation_id)
            if remaining is None:
                return
            remaining = max(0, remaining - written_bytes)
            if remaining:
                self._reservations[reservation_id] = remaining
            else:
                self._reservations.pop(reservation_id, None)
            # The write happened outside this lock. Force the next capacity decision
            # to measure actual bytes instead of trying to infer concurrent changes.
            self._work_bytes = None
            self._measured_at = 0.0

    def release(self, reservation_id: str) -> None:
        with self._lock:
            self._reservations.pop(reservation_id, None)
            self._work_bytes = None
            self._measured_at = 0.0

    def invalidate(self) -> None:
        with self._lock:
            self._work_bytes = None
            self._measured_at = 0.0

    def snapshot(self, *, force: bool = False) -> CapacitySnapshot:
        with self._lock:
            return self._snapshot_locked(force=force)

    def _snapshot_locked(self, *, force: bool) -> CapacitySnapshot:
        work_dir = self._require_work_dir_locked()
        now = time.time()
        if (
            force
            or self._work_bytes is None
            or now - self._measured_at >= self._cache_seconds
        ):
            self._work_bytes = _directory_size(work_dir)
            self._measured_at = now
        reserved = sum(self._reservations.values())
        return CapacitySnapshot(
            work_bytes=self._work_bytes,
            reserved_bytes=reserved,
            committed_bytes=self._work_bytes + reserved,
            max_work_bytes=self._max_work_bytes,
            disk_free_bytes=shutil.disk_usage(work_dir).free,
            minimum_free_bytes=self._minimum_free_bytes,
            active_reservations=len(self._reservations),
            measured_at=self._measured_at,
        )

    def _require_work_dir_locked(self) -> Path:
        if self._work_dir is None:
            raise RuntimeError("TraceQuarry work capacity is not configured.")
        return self._work_dir

    def _recover_reservations_locked(self) -> dict[str, int]:
        work_dir = self._require_work_dir_locked()
        uploads_root = work_dir / "uploads"
        if not uploads_root.is_dir():
            return {}
        now = time.time()
        reservations: dict[str, int] = {}
        for manifest in uploads_root.glob("staged-*/upload_session.json"):
            document = _read_document(manifest)
            upload_id = str(document.get("id") or "")
            if not upload_id or float(document.get("expires_at") or 0) <= now:
                continue
            remaining = sum(
                max(
                    0,
                    int(item.get("size") or 0) - int(item.get("uploaded_bytes") or 0),
                )
                for item in list(document.get("files") or [])
                if isinstance(item, dict) and item.get("status") != "staged"
            )
            if remaining:
                reservations[upload_id] = remaining
        return reservations


def _directory_size(path: Path) -> int:
    total = 0
    for candidate in path.rglob("*"):
        try:
            if candidate.is_file() and not candidate.is_symlink():
                total += candidate.stat().st_size
        except OSError:
            continue
    return total


def _read_document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
