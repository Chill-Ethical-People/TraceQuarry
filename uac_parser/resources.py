from __future__ import annotations

import sysconfig
from pathlib import Path


def resource_directories(kind: str) -> tuple[Path, ...]:
    if kind not in {"assets", "rules"}:
        raise ValueError(f"Unsupported TraceQuarry resource kind: {kind}")
    return (
        Path(__file__).resolve().parents[1] / kind,
        Path(sysconfig.get_path("data")) / "share" / "tracequarry" / kind,
    )


def resource_directory(kind: str) -> Path:
    candidates = resource_directories(kind)
    return next((path for path in candidates if path.is_dir()), candidates[0])


def resource_file(kind: str, name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"Unsafe TraceQuarry resource name: {name}")
    candidates = tuple(root / relative for root in resource_directories(kind))
    return next((path for path in candidates if path.is_file()), candidates[0])
