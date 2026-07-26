from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class JobType(StrEnum):
    ANALYSIS = "analysis"
    INSPECTION = "inspection"


class JobStateError(ValueError):
    """Raised when persisted job state violates the lifecycle contract."""


class JobVersionConflict(JobStateError):
    """Raised when a caller attempts to update a stale job revision."""


_ALLOWED_TRANSITIONS = {
    JobStatus.QUEUED: {
        JobStatus.RUNNING,
        JobStatus.FAILED,
        JobStatus.INTERRUPTED,
    },
    JobStatus.RUNNING: {
        JobStatus.COMPLETE,
        JobStatus.FAILED,
        JobStatus.INTERRUPTED,
    },
    JobStatus.COMPLETE: set(),
    JobStatus.FAILED: set(),
    JobStatus.INTERRUPTED: set(),
}


@dataclass(frozen=True, slots=True)
class JobState:
    """Typed lifecycle projection of an extensible persisted job document."""

    job_id: str
    status: JobStatus
    job_type: JobType
    stage: str
    progress: int
    revision: int

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> JobState:
        job_id = str(document.get("id") or "")
        if not job_id:
            raise JobStateError("Job state requires an identifier.")
        try:
            status = JobStatus(str(document.get("status") or ""))
        except ValueError as exc:
            raise JobStateError("Job state contains an unsupported status.") from exc
        try:
            job_type = JobType(str(document.get("job_type") or JobType.ANALYSIS))
        except ValueError as exc:
            raise JobStateError("Job state contains an unsupported job type.") from exc
        try:
            progress = int(document.get("progress") or 0)
            revision = int(document.get("revision") or 0)
        except (TypeError, ValueError) as exc:
            raise JobStateError("Job progress and revision must be integers.") from exc
        if not 0 <= progress <= 100:
            raise JobStateError("Job progress must be between 0 and 100.")
        if revision < 0:
            raise JobStateError("Job revision cannot be negative.")
        return cls(
            job_id=job_id,
            status=status,
            job_type=job_type,
            stage=str(document.get("stage") or status.value),
            progress=progress,
            revision=revision,
        )


def validate_transition(
    previous: JobState | None,
    current: JobState,
    *,
    allow_recovery: bool = False,
) -> None:
    if previous is None or previous.status == current.status:
        return
    allowed = _ALLOWED_TRANSITIONS[previous.status]
    if current.status in allowed:
        return
    if (
        allow_recovery
        and previous.status is JobStatus.INTERRUPTED
        and current.status is JobStatus.COMPLETE
    ):
        return
    raise JobStateError(
        f"Invalid job transition: {previous.status.value} -> {current.status.value}."
    )
